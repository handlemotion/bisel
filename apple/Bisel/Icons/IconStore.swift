import AppKit
import CryptoKit
import ImageIO
import Observation
import UniformTypeIdentifiers

/// Site icons for result rows, fetched DIRECTLY from the site on this device. No third-party icon service ever
/// sees a domain (SPEC.md §8 "Site icons"). Icons live only in this cache (Application Support/bisel/icons),
/// never in the vault, never synced, never sent to the server.
///
/// Policy: HTTPS only; ephemeral session (no cookies, no cache, no credentials); no Referer; generic User-Agent;
/// ≤3 redirects and only within the same registrable domain; HTML head capped at 64 KB, images at 256 KB; the
/// payload must decode as an image through ImageIO and is re-encoded as a 96 px PNG; at most 3 fetches at once;
/// a failed domain is not retried for 7 days; positive results are cached on disk keyed by SHA-256 of the
/// registrable domain, with an NSCache on top.
@MainActor
@Observable
final class IconStore {
    static let shared = IconStore()

    static let enabledKey = "icons.enabled"
    static let negativeTTL: TimeInterval = 7 * 24 * 3600

    var enabled: Bool {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); generation += 1 }
    }
    /// Bumped by "Clear icon cache" and by toggling, so visible rows re-resolve.
    private(set) var generation = 0
    /// Bumped whenever an icon finishes loading so every visible view of that domain (row and detail) refreshes.
    private(set) var loadedCount = 0

    @ObservationIgnored private let memory = NSCache<NSString, NSImage>()
    @ObservationIgnored private var inflight: [String: Task<NSImage?, Never>] = [:]
    @ObservationIgnored private let gate = FetchGate(limit: 3)

    static var directory: URL {
        URL.applicationSupportDirectory.appending(path: "bisel/icons", directoryHint: .isDirectory)
    }

    private init() {
        UserDefaults.standard.register(defaults: [Self.enabledKey: true])
        enabled = UserDefaults.standard.bool(forKey: Self.enabledKey)
        memory.countLimit = 400
    }

    nonisolated static func key(for domain: String) -> String {
        SHA256.hash(data: Data(DomainName.registrable(domain).utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Instant lookup (memory, then disk). Never touches the network.
    func cached(_ domain: String) -> NSImage? {
        guard enabled, !domain.isEmpty else { return nil }
        let k = Self.key(for: domain)
        if let img = memory.object(forKey: k as NSString) { return img }
        let file = Self.directory.appending(path: "\(k).png")
        if let data = try? Data(contentsOf: file), let img = NSImage(data: data) {
            memory.setObject(img, forKey: k as NSString)
            return img
        }
        return nil
    }

    /// Cached image, else a (deduplicated, gated, negatively-cached) fetch. Returns nil when disabled or not available.
    func load(_ domain: String) async -> NSImage? {
        guard enabled, !domain.isEmpty else { return nil }
        if let img = cached(domain) { return img }
        let k = Self.key(for: domain)
        let neg = Self.directory.appending(path: "\(k).neg")
        if let attrs = try? FileManager.default.attributesOfItem(atPath: neg.path),
           let mtime = attrs[.modificationDate] as? Date, Date().timeIntervalSince(mtime) < Self.negativeTTL {
            return nil
        }
        if let t = inflight[k] { return await t.value }
        let gate = self.gate
        let t = Task<NSImage?, Never> { [weak self] in
            await gate.acquire()
            defer { Task { await gate.release() } }
            if Task.isCancelled { return nil }
            let png = await IconFetcher.fetchIcon(host: domain)
            guard let self else { return nil }
            return self.finish(domain: domain, key: k, png: png, cancelled: Task.isCancelled)
        }
        inflight[k] = t
        let result = await t.value
        inflight[k] = nil
        return result
    }

    private func finish(domain: String, key k: String, png: Data?, cancelled: Bool) -> NSImage? {
        guard enabled else { return nil }
        try? FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true)
        if let png, let img = NSImage(data: png) {
            try? png.write(to: Self.directory.appending(path: "\(k).png"))
            try? FileManager.default.removeItem(at: Self.directory.appending(path: "\(k).neg"))
            memory.setObject(img, forKey: k as NSString)
            loadedCount += 1
            return img
        }
        if !cancelled {
            // Negative cache: remember the failure for 7 days (file mtime is the timestamp; no domain inside).
            try? Data().write(to: Self.directory.appending(path: "\(k).neg"))
        }
        return nil
    }

    func clearCache() {
        memory.removeAllObjects()
        try? FileManager.default.removeItem(at: Self.directory)
        generation += 1
    }

    var cacheSizeDescription: String {
        let files = (try? FileManager.default.contentsOfDirectory(at: Self.directory, includingPropertiesForKeys: [.fileSizeKey])) ?? []
        let n = files.filter { $0.pathExtension == "png" }.count
        return "\(n) icons cached"
    }
}

/// Counting semaphore for async code.
private actor FetchGate {
    private var available: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []
    init(limit: Int) { available = limit }
    func acquire() async {
        if available > 0 { available -= 1; return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        if waiters.isEmpty { available += 1 } else { waiters.removeFirst().resume() }
    }
}

/// Network side. Pure functions, no shared mutable state besides the redirect-count table.
enum IconFetcher {
    static let htmlCap = 64 * 1024
    static let imageCap = 256 * 1024
    static let maxRedirects = 3
    static let outputPixels = 96

    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = 5
        c.timeoutIntervalForResource = 10
        c.httpMaximumConnectionsPerHost = 2
        c.urlCredentialStorage = nil
        c.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        ]
        return URLSession(configuration: c, delegate: RedirectPolicy.shared, delegateQueue: nil)
    }()

    /// Returns a 96 px PNG for `host`'s icon, or nil.
    @concurrent
    static func fetchIcon(host: String) async -> Data? {
        let registrable = DomainName.registrable(host)
        guard let origin = URL(string: "https://\(host)/") else { return nil }
        var candidates: [URL] = []
        if let (html, finalURL) = await get(origin, accept: "text/html,*/*;q=0.5", cap: htmlCap, range: true),
           let text = String(data: html, encoding: .utf8) ?? String(data: html, encoding: .isoLatin1) {
            candidates = iconLinks(in: text, base: finalURL).filter { DomainName.registrable($0.host() ?? "") == registrable }
        }
        // /favicon.ico ranks after sized <link rel=icon> candidates but before apple-touch-icon.
        if let fav = URL(string: "https://\(host)/favicon.ico") {
            let firstTouch = candidates.firstIndex { $0.absoluteString.lowercased().contains("apple-touch") } ?? candidates.count
            candidates.insert(fav, at: firstTouch)
        }
        for url in candidates.prefix(4) {
            if Task.isCancelled { return nil }
            if let (data, _) = await get(url, accept: "image/*,*/*;q=0.1", cap: imageCap, range: false),
               let png = normalize(data) { return png }
        }
        return nil
    }

    /// Reads at most `cap` bytes. Returns the data and the final URL after (policy-checked) redirects.
    private static func get(_ url: URL, accept: String, cap: Int, range: Bool) async -> (Data, URL)? {
        guard url.scheme == "https" else { return nil }
        var req = URLRequest(url: url)
        req.httpShouldHandleCookies = false
        req.setValue(accept, forHTTPHeaderField: "Accept")
        req.setValue(nil, forHTTPHeaderField: "Referer")
        if range { req.setValue("bytes=0-\(cap - 1)", forHTTPHeaderField: "Range") }
        #if DEBUG
        Log.icons.debug("ICONFETCH \(url.host() ?? "?", privacy: .public)\(url.path(), privacy: .public)")
        #endif
        do {
            let (bytes, resp) = try await session.bytes(for: req)
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { return nil }
            if resp.expectedContentLength > Int64(cap), !range { return nil }
            var data = Data()
            for try await b in bytes {
                data.append(b)
                if data.count >= cap { if range { break } else { return nil } }
            }
            return (data, resp.url ?? url)
        } catch { return nil }
    }

    /// `<link rel="icon|shortcut icon|apple-touch-icon" href sizes>` candidates, best first (skips SVG: ImageIO).
    private static func iconLinks(in html: String, base: URL) -> [URL] {
        let head = html.prefix(htmlCap)
        guard let linkRE = try? Regex(#"<link\b[^>]*>"#).ignoresCase() else { return [] }
        struct Cand { var url: URL; var score: Int }
        var out: [Cand] = []
        for m in head.matches(of: linkRE) {
            let tag = String(head[m.range])
            guard let rel = attribute("rel", in: tag)?.lowercased(), rel.contains("icon"),
                  let href = attribute("href", in: tag), !href.lowercased().hasSuffix(".svg"),
                  attribute("type", in: tag)?.lowercased().contains("svg") != true,
                  let url = URL(string: href, relativeTo: base)?.absoluteURL, url.scheme == "https" else { continue }
            // Prefer a plain icon near 96 px; apple-touch-icon last (it usually has an opaque white matte).
            var score = rel.contains("apple-touch") ? 5 : 40
            if let sizes = attribute("sizes", in: tag), let px = Int(sizes.lowercased().split(separator: "x").first ?? "") {
                score += 100 - min(abs(px - 96), 100) / 2
            }
            out.append(Cand(url: url, score: score))
        }
        return out.sorted { $0.score > $1.score }.map(\.url)
    }

    private static func attribute(_ name: String, in tag: String) -> String? {
        guard let re = try? Regex("\\b\(name)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')").ignoresCase(),
              let m = tag.firstMatch(of: re) else { return nil }
        let v = (m.output[1].substring ?? m.output[2].substring).map(String.init)
        return (v?.isEmpty ?? true) ? nil : v
    }

    /// Must decode as an image (ImageIO); picks the frame nearest the output size and re-encodes a 96 px PNG.
    private static func normalize(_ data: Data) -> Data? {
        guard data.count >= 32, let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        let count = CGImageSourceGetCount(src)
        guard count > 0 else { return nil }
        var best = 0, bestDelta = Int.max
        for i in 0..<count {
            guard let props = CGImageSourceCopyPropertiesAtIndex(src, i, nil) as? [CFString: Any],
                  let w = props[kCGImagePropertyPixelWidth] as? Int else { continue }
            let d = abs(w - outputPixels)
            if d < bestDelta { best = i; bestDelta = d }
        }
        let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                     kCGImageSourceCreateThumbnailWithTransform: true,
                                     kCGImageSourceThumbnailMaxPixelSize: outputPixels]
        guard let decoded = CGImageSourceCreateThumbnailAtIndex(src, best, opts as CFDictionary), decoded.width >= 8 else { return nil }
        let thumb = trimmedSquare(decoded) ?? decoded
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, thumb, nil)
        return CGImageDestinationFinalize(dest) ? out as Data : nil
    }
}

/// Removes a uniform margin (transparent, or one solid color such as the white matte of an app icon), then crops to a
/// centered square so the icon can fill the 24 pt tile. Returns nil when there is nothing to trim.
private func trimmedSquare(_ image: CGImage) -> CGImage? {
    let w = image.width, h = image.height
    guard w >= 16, h >= 16 else { return nil }
    var px = [UInt8](repeating: 0, count: w * h * 4)
    guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
    func p(_ x: Int, _ y: Int) -> (r: Int, g: Int, b: Int, a: Int) {
        let i = (y * w + x) * 4
        let a = Int(px[i + 3])
        if a == 0 { return (0, 0, 0, 0) }
        // un-premultiply
        return (min(255, Int(px[i]) * 255 / a), min(255, Int(px[i + 1]) * 255 / a), min(255, Int(px[i + 2]) * 255 / a), a)
    }
    // Reference "border": transparent if the 4 corners are transparent; else the corners' common color.
    let corners = [p(1, 1), p(w - 2, 1), p(1, h - 2), p(w - 2, h - 2)]
    let transparent = corners.allSatisfy { $0.a < 16 }
    let ref = corners[0]
    func close(_ c: (r: Int, g: Int, b: Int, a: Int), _ d: (r: Int, g: Int, b: Int, a: Int), tol: Int) -> Bool {
        abs(c.r - d.r) <= tol && abs(c.g - d.g) <= tol && abs(c.b - d.b) <= tol && abs(c.a - d.a) <= tol
    }
    let solid = !transparent && corners.allSatisfy { $0.a > 200 && close($0, ref, tol: 20) }
    guard transparent || solid else { return nil }
    func isBorder(_ x: Int, _ y: Int) -> Bool {
        let c = p(x, y)
        return transparent ? c.a < 16 : close(c, ref, tol: 22)
    }
    var minX = w, minY = h, maxX = -1, maxY = -1
    for y in 0..<h { for x in 0..<w where !isBorder(x, y) {
        minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y)
    } }
    guard maxX >= minX, maxY >= minY else { return nil }
    var bw = maxX - minX + 1, bh = maxY - minY + 1
    guard bw >= 8, bh >= 8 else { return nil }
    guard bw < w || bh < h else { return nil }
    // Opaque icons: also shave 1 px so anti-aliased edge pixels of the matte do not remain.
    if solid { minX += 1; minY += 1; bw -= 2; bh -= 2 }
    let side = max(bw, bh)
    let cx = minX + bw / 2, cy = minY + bh / 2
    let x0 = min(max(cx - side / 2, 0), max(w - side, 0)), y0 = min(max(cy - side / 2, 0), max(h - side, 0))
    let s = min(side, min(w, h))
    return image.cropping(to: CGRect(x: x0, y: y0, width: s, height: s))
}

/// Redirects: at most 3, HTTPS only, and only within the original registrable domain.
private final class RedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = RedirectPolicy()
    private let lock = NSLock()
    private var counts: [Int: Int] = [:]

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        let n = lock.withLock { counts[task.taskIdentifier, default: 0] + 1 }
        lock.withLock { counts[task.taskIdentifier] = n }
        guard n <= IconFetcher.maxRedirects, let new = request.url, new.scheme == "https",
              let from = task.originalRequest?.url?.host(), let to = new.host(),
              DomainName.registrable(from) == DomainName.registrable(to) else {
            completionHandler(nil)  // deliver the redirect response itself; it is not 2xx, so the fetch fails
            return
        }
        var r = request
        r.setValue(nil, forHTTPHeaderField: "Referer")
        completionHandler(r)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.withLock { _ = counts.removeValue(forKey: task.taskIdentifier) }
    }
}
