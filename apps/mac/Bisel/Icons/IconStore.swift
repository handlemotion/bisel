import AppKit
import CryptoKit
import ImageIO
import Observation
import Security
import UniformTypeIdentifiers

/// Site icons for result rows, fetched DIRECTLY from the site on this device. No third-party icon service ever
/// sees a domain (SPEC.md §8 "Site icons"). Icons live only in this cache (Application Support/bisel/icons),
/// never in the vault, never synced, never sent to the server.
///
/// OFF by default (opt-in, security review M13): every enabled lookup tells the network (DNS, SNI, source IP) which sites are in
/// the vault. Hosts must pass `IconHostPolicy` (no IP literals / local names / non-443 ports; all resolved addresses public).
/// The decoder only sees images of an allow-listed type with sane pixel dimensions (M11). Cache file names are an HMAC under a
/// per-install key held in the Keychain (L8); without a Keychain (unsigned builds) icons are kept in memory only.
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
    nonisolated static let negativeTTL: TimeInterval = 7 * 24 * 3600
    private static let layoutVersionKey = "icons.layoutVersion"
    private static let layoutVersion = 3

    var enabled: Bool {
        didSet { UserDefaults.standard.set(enabled, forKey: Self.enabledKey); generation += 1 }
    }
    /// Bumped by "Clear icon cache" and by toggling, so visible rows re-resolve.
    private(set) var generation = 0

    @ObservationIgnored private let memory = NSCache<NSString, NSImage>()
    @ObservationIgnored private var inflight: [String: Task<NSImage?, Never>] = [:]
    @ObservationIgnored private let gate = FetchGate(limit: 3)

    nonisolated static var directory: URL {
        #if DEBUG
        // A throwaway store (BISEL_DATA_DIR) must not read or fill the real icon cache.
        if let dir = ProcessInfo.processInfo.environment["BISEL_DATA_DIR"], !dir.isEmpty {
            return URL(fileURLWithPath: dir, isDirectory: true).appending(path: "icons", directoryHint: .isDirectory)
        }
        #endif
        return URL.applicationSupportDirectory.appending(path: "bisel/icons", directoryHint: .isDirectory)
    }

    private init() {
        UserDefaults.standard.register(defaults: [Self.enabledKey: false])
        // Icons used to be on by default. That was never a choice, so everyone starts from "off" once (review M13).
        if !UserDefaults.standard.bool(forKey: "icons.optInMigrated") {
            UserDefaults.standard.set(false, forKey: Self.enabledKey)
            UserDefaults.standard.set(true, forKey: "icons.optInMigrated")
        }
        enabled = UserDefaults.standard.bool(forKey: Self.enabledKey)
        memory.countLimit = 400
        // Icons are stored as they are drawn: when `fittedToTile` changes, the cached ones have to be fetched again.
        if UserDefaults.standard.integer(forKey: Self.layoutVersionKey) < Self.layoutVersion {
            try? FileManager.default.removeItem(at: Self.directory)
            UserDefaults.standard.set(Self.layoutVersion, forKey: Self.layoutVersionKey)
        }
    }

    /// File/cache key: HMAC-SHA256 of the registrable domain under the per-install key, so a copy of the cache directory (backup,
    /// disk image) cannot be tested for "does this vault contain mybank.com".
    nonisolated static func key(for domain: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(DomainName.registrable(domain).utf8), using: IconKey.shared.key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    /// Persist to disk only when the key itself survives restarts.
    nonisolated static var canPersist: Bool { IconKey.shared.persistent }

    /// Instant lookup, memory only: rows ask for this while they scroll, so it never touches the disk, the Keychain or the network.
    /// By domain, not by the file key: the key costs an HMAC. It lives only in this process, next to the rows that hold the domain.
    func cached(_ domain: String) -> NSImage? {
        guard enabled, !domain.isEmpty else { return nil }
        return memory.object(forKey: domain as NSString)
    }

    /// What the disk holds for `domain`, away from the main thread: the file key, an icon decoded here (`NSImage(data:)` would
    /// decode it on the main thread, in the frame that draws it), or a recent failure.
    @concurrent
    private static func lookOnDisk(_ domain: String) async -> (key: String, image: NSImage?, failedRecently: Bool) {
        let k = key(for: domain)
        guard canPersist else { return (k, nil, false) }
        if let data = try? Data(contentsOf: directory.appending(path: "\(k).png")), let image = decoded(data) { return (k, image, false) }
        let neg = directory.appending(path: "\(k).neg")
        let mtime = (try? FileManager.default.attributesOfItem(atPath: neg.path))?[.modificationDate] as? Date
        return (k, nil, mtime.map { Date().timeIntervalSince($0) < negativeTTL } ?? false)
    }

    /// An icon this cache wrote (`IconFetcher.normalize`), with its pixels decoded now rather than at first draw.
    nonisolated private static func decoded(_ png: Data) -> NSImage? {
        guard let source = CGImageSourceCreateWithData(png as CFData, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, [kCGImageSourceShouldCacheImmediately: true] as CFDictionary) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: image.width, height: image.height))
    }

    /// Cached image, else a (deduplicated, gated, negatively-cached) fetch. Returns nil when disabled or not available.
    func load(_ domain: String) async -> NSImage? {
        guard enabled, !domain.isEmpty else { return nil }
        if let img = cached(domain) { return img }
        let disk = await Self.lookOnDisk(domain)
        guard enabled else { return nil }
        if let image = disk.image {
            memory.setObject(image, forKey: domain as NSString)
            return image
        }
        if disk.failedRecently { return nil }
        let k = disk.key
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
        let persist = Self.canPersist
        if persist { try? FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true) }
        if let png, let img = Self.decoded(png) {
            if persist {
                try? png.write(to: Self.directory.appending(path: "\(k).png"))
                try? FileManager.default.removeItem(at: Self.directory.appending(path: "\(k).neg"))
            }
            memory.setObject(img, forKey: domain as NSString)
            return img
        }
        if !cancelled && persist {
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
    /// Largest image we agree to decode, per side and in total (M11). Real favicons are ≤ 512 px.
    static let maxSide = 1024
    static let maxPixels = 1_000_000
    static let maxFrames = 16

    /// remote address actually connected to, by task id (filled by the session delegate's metrics callback)
    static let remote = RemoteAddresses()

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
        guard allowed(host: host, port: nil) else {
            Log.icons.notice("icon fetch refused by host policy")
            return nil
        }
        let registrable = DomainName.registrable(host)
        var oc = URLComponents(); oc.scheme = "https"; oc.host = host; oc.path = "/"
        guard let origin = oc.url else { return nil }
        var candidates: [URL] = []
        if let (html, finalURL) = await get(origin, accept: "text/html,*/*;q=0.5", cap: htmlCap, range: true),
           let text = String(data: html, encoding: .utf8) ?? String(data: html, encoding: .isoLatin1) {
            candidates = iconLinks(in: text, base: finalURL).filter {
                DomainName.registrable($0.host() ?? "") == registrable && allowed(host: $0.host() ?? "", port: $0.port)
            }
        }
        // /favicon.ico ranks after sized <link rel=icon> candidates but before apple-touch-icon.
        var fc = URLComponents(); fc.scheme = "https"; fc.host = host; fc.path = "/favicon.ico"
        if let fav = fc.url {
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
    nonisolated static func allowed(host: String, port: Int?) -> Bool {
        IconHostPolicy.acceptable(host: host, port: port) && IconHostPolicy.resolvesToPublicAddressesOnly(host)
    }

    private static func get(_ url: URL, accept: String, cap: Int, range: Bool) async -> (Data, URL)? {
        guard url.scheme == "https", allowed(host: url.host() ?? "", port: url.port) else { return nil }
        var req = URLRequest(url: url)
        req.httpShouldHandleCookies = false
        req.setValue(accept, forHTTPHeaderField: "Accept")
        req.setValue(nil, forHTTPHeaderField: "Referer")
        if range { req.setValue("bytes=0-\(cap - 1)", forHTTPHeaderField: "Range") }
        #if DEBUG
        Log.icons.debug("ICONFETCH \(url.host() ?? "?")\(url.path())")
        #endif
        do {
            let (bytes, resp) = try await session.bytes(for: req)
            defer { remote.forget(bytes.task.taskIdentifier) }
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { return nil }
            if resp.expectedContentLength > Int64(cap), !range { return nil }
            var data = Data()
            for try await b in bytes {
                data.append(b)
                if data.count >= cap { if range { break } else { return nil } }
            }
            // The address we really connected to must be public too (DNS can change between the check and the connect).
            if let addr = remote.address(for: bytes.task.taskIdentifier), !IconHostPolicy.isPublic(addressString: addr) { return nil }
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
    static func normalize(_ data: Data) -> Data? {
        guard data.count >= 32, let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        // Allow-listed container types only: ImageIO's rarer decoders (WebP, TIFF, JPEG 2000, RAW…) are recurring CVE surface.
        guard let type = CGImageSourceGetType(src).flatMap({ UTType($0 as String) }),
              [UTType.png, .jpeg, .gif, .ico].contains(where: { type.conforms(to: $0) }) else { return nil }
        let count = CGImageSourceGetCount(src)
        guard count > 0, count <= maxFrames else { return nil }
        var best = 0, bestDelta = Int.max
        for i in 0..<count {
            // Dimensions come from the headers: reject before any pixel is decoded (a 194 KB PNG can declare 40000 × 40000).
            guard let props = CGImageSourceCopyPropertiesAtIndex(src, i, nil) as? [CFString: Any],
                  let w = props[kCGImagePropertyPixelWidth] as? Int, let h = props[kCGImagePropertyPixelHeight] as? Int,
                  w > 0, h > 0, w <= maxSide, h <= maxSide, w * h <= maxPixels else { return nil }
            let d = abs(w - outputPixels)
            if d < bestDelta { best = i; bestDelta = d }
        }
        let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                     kCGImageSourceCreateThumbnailWithTransform: true,
                                     kCGImageSourceThumbnailMaxPixelSize: outputPixels]
        guard let decoded = CGImageSourceCreateThumbnailAtIndex(src, best, opts as CFDictionary), decoded.width >= 8 else { return nil }
        let thumb = fittedToTile(decoded) ?? decoded
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, thumb, nil)
        return CGImageDestinationFinalize(dest) ? out as Data : nil
    }
}

/// Redraws an icon on a square canvas so every site reads the same size in the tile, whatever margin its file came with.
/// A logo on nothing, on a solid color, or on a rounded tile of one color is centered with `logoInset` around it, and that
/// color runs out to the canvas edges, so the file's own corners never show inside ours. A rounded tile that is not one color
/// fills the canvas, a little over so its clear corners fall outside ours. Returns nil for anything else (a photo, a gradient,
/// art that runs off the edge), which stays as it is.
private let logoInset = 0.2

private func fittedToTile(_ image: CGImage) -> CGImage? {
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
    // Same corners are not a solid background unless the whole edge agrees: a gradient or a logo touching the edge would
    // show a seam against a flat fill.
    if solid {
        let ring = (1..<(w - 1)).allSatisfy { isBorder($0, 1) && isBorder($0, h - 2) }
            && (1..<(h - 1)).allSatisfy { isBorder(1, $0) && isBorder(w - 2, $0) }
        guard ring else { return nil }
    }
    var minX = w, minY = h, maxX = -1, maxY = -1, filled = 0
    for y in 0..<h { for x in 0..<w where !isBorder(x, y) {
        minX = min(minX, x); maxX = max(maxX, x); minY = min(minY, y); maxY = max(maxY, y)
        filled += 1
    } }
    guard maxX >= minX, maxY >= minY else { return nil }
    var bw = maxX - minX + 1, bh = maxY - minY + 1
    guard bw >= 8, bh >= 8 else { return nil }
    var fill = solid ? ref : nil
    var isTile = transparent && Double(filled) / Double(bw * bh) > 0.85 && abs(bw - bh) <= max(bw, bh) / 8
    if isTile {
        // The middle of each side, just inside it: past the rounded corners, and clear of a logo unless it touches the edge.
        let across = (minX + bw / 4)...(maxX - bw / 4), down = (minY + bh / 4)...(maxY - bh / 4)
        let edge = across.flatMap { [p($0, minY + 2), p($0, maxY - 2)] } + down.flatMap { [p(minX + 2, $0), p(maxX - 2, $0)] }
        if let first = edge.first, edge.allSatisfy({ $0.a > 200 && close($0, first, tol: 22) }) {
            // One color: the tile is really a background, so what counts is the logo on it. Soft pixels are the tile's own edge.
            var lx = w, ly = h, hx = -1, hy = -1
            for y in minY...maxY { for x in minX...maxX {
                let c = p(x, y)
                guard c.a > 240, !close(c, first, tol: 22) else { continue }
                lx = min(lx, x); hx = max(hx, x); ly = min(ly, y); hy = max(hy, y)
            } }
            if hx - lx >= 7, hy - ly >= 7 {
                minX = lx; minY = ly; bw = hx - lx + 1; bh = hy - ly + 1
                fill = first
                isTile = false
            }
        }
    }
    guard let content = image.cropping(to: CGRect(x: minX, y: minY, width: bw, height: bh)) else { return nil }

    let side = IconFetcher.outputPixels
    guard let canvas = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
                                 space: CGColorSpaceCreateDeviceRGB(),
                                 bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
    canvas.interpolationQuality = .high
    if let fill {
        canvas.setFillColor(red: Double(fill.r) / 255, green: Double(fill.g) / 255, blue: Double(fill.b) / 255, alpha: 1)
        canvas.fill(CGRect(x: 0, y: 0, width: side, height: side))
    }
    let box = Double(side) * (isTile ? 1.08 : 1 - 2 * logoInset)
    let scale = box / Double(isTile ? min(bw, bh) : max(bw, bh))
    let dw = Double(bw) * scale, dh = Double(bh) * scale
    canvas.draw(content, in: CGRect(x: (Double(side) - dw) / 2, y: (Double(side) - dh) / 2, width: dw, height: dh))
    return canvas.makeImage()
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
              DomainName.registrable(from) == DomainName.registrable(to),
              IconFetcher.allowed(host: to, port: new.port) else {
            completionHandler(nil)  // deliver the redirect response itself; it is not 2xx, so the fetch fails
            return
        }
        var r = request
        r.setValue(nil, forHTTPHeaderField: "Referer")
        completionHandler(r)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        if let addr = metrics.transactionMetrics.last?.remoteAddress { IconFetcher.remote.set(addr, for: task.taskIdentifier) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.withLock { _ = counts.removeValue(forKey: task.taskIdentifier) }
    }
}

/// Remote address of each finished task, for the "connected to a public address" check.
final class RemoteAddresses: @unchecked Sendable {
    private let lock = NSLock()
    private var table: [Int: String] = [:]
    func set(_ a: String, for id: Int) { lock.withLock { table[id] = a } }
    func address(for id: Int) -> String? { lock.withLock { table[id] } }
    func forget(_ id: Int) { lock.withLock { _ = table.removeValue(forKey: id) } }
}

/// Per-install random key for the icon cache names. Lives in the Keychain (data-protection keychain; needs a signed build).
/// If that is unavailable the key is memory-only and nothing is written to disk.
final class IconKey: @unchecked Sendable {
    static let shared = IconKey()
    let key: SymmetricKey
    let persistent: Bool

    private init() {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "app.bisel.mac.icon-cache",
                                    kSecAttrAccount as String: "hmac-key", kSecUseDataProtectionKeychain as String: true]
        var found: CFTypeRef?
        if SecItemCopyMatching(query.merging([kSecReturnData as String: true]) { $1 } as CFDictionary, &found) == errSecSuccess,
           let d = found as? Data, d.count == 32 {
            key = SymmetricKey(data: d); persistent = true; return
        }
        let fresh = SymmetricKey(size: .bits256)
        let data = fresh.withUnsafeBytes { Data($0) }
        let add = query.merging([kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]) { $1 }
        let status = SecItemAdd(add as CFDictionary, nil)
        key = fresh; persistent = status == errSecSuccess
        if !persistent { Log.icons.notice("icon cache key not stored (keychain status \(status)): icons stay in memory this run") }
    }
}
