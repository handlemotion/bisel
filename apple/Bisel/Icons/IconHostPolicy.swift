import Foundation
import Darwin

/// Which hosts the icon fetcher may contact (security review M12). Item URLs are data from imports and sync, so they must not
/// be able to make this Mac probe its own machine or LAN: no IP literals, no single-label / local names, only port 443,
/// and every address the name resolves to (and the address actually connected to) must be public.
enum IconHostPolicy {
    private static let blockedSuffixes: Set<String> = [
        "local", "localhost", "internal", "lan", "home", "corp", "intranet", "localdomain", "invalid", "test", "example", "onion", "arpa",
    ]

    /// Syntax checks only (no DNS).
    static func acceptable(host rawHost: String, port: Int?) -> Bool {
        if let port, port != 443 { return false }
        let host = rawHost.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !host.isEmpty, host.count <= 253, !host.contains(":"), !host.contains("["), !host.contains("%") else { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 }) else { return false }
        guard let tld = labels.last, !blockedSuffixes.contains(String(tld)) else { return false }
        // IP literals in any spelling ("127.1", "0x7f.0.0.1", "2130706433"): the TLD of a real name is never all digits / hex.
        if tld.allSatisfy({ $0.isNumber }) || tld.hasPrefix("0x") { return false }
        var buf = [UInt8](repeating: 0, count: 16)
        if inet_pton(AF_INET, host, &buf) == 1 || inet_pton(AF_INET6, host, &buf) == 1 { return false }
        return !DomainName.isPublicSuffix(host)
    }

    /// Resolves `host` and requires every address to be public. Blocking (getaddrinfo): call off the main actor.
    static func resolvesToPublicAddressesOnly(_ host: String) -> Bool {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0,
                             ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &res) == 0, let first = res else { return false }
        defer { freeaddrinfo(res) }
        var p: UnsafeMutablePointer<addrinfo>? = first
        var any = false
        while let ai = p?.pointee {
            any = true
            guard let sa = ai.ai_addr else { return false }
            if ai.ai_family == AF_INET {
                let bytes = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin_addr) { Array($0) } }
                if !isPublic(v4: bytes) { return false }
            } else if ai.ai_family == AF_INET6 {
                let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { withUnsafeBytes(of: $0.pointee.sin6_addr) { Array($0) } }
                if !isPublic(v6: bytes) { return false }
            } else { return false }
            p = ai.ai_next
        }
        return any
    }

    /// For the address the connection actually used (URLSessionTaskMetrics.remoteAddress); guards against DNS answers that changed
    /// between the check and the connect.
    static func isPublic(addressString s: String) -> Bool {
        var b4 = [UInt8](repeating: 0, count: 4), b6 = [UInt8](repeating: 0, count: 16)
        if inet_pton(AF_INET, s, &b4) == 1 { return isPublic(v4: b4) }
        if inet_pton(AF_INET6, s, &b6) == 1 { return isPublic(v6: b6) }
        return false
    }

    static func isPublic(v4 b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        let (a, c) = (b[0], b[1])
        switch a {
        case 0, 10, 127: return false
        case 100 where (64...127).contains(c): return false                     // CGNAT
        case 169 where c == 254: return false                                   // link-local
        case 172 where (16...31).contains(c): return false
        case 192 where c == 168: return false
        case 192 where c == 0 && b[2] == 0: return false                        // IETF protocol assignments
        case 192 where c == 0 && b[2] == 2: return false                        // TEST-NET-1
        case 198 where c == 18 || c == 19: return false                         // benchmarking
        case 198 where c == 51 && b[2] == 100: return false
        case 203 where c == 0 && b[2] == 113: return false
        case 224...255: return false                                            // multicast, reserved, broadcast
        default: return true
        }
    }

    static func isPublic(v6 b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        if b.allSatisfy({ $0 == 0 }) { return false }                           // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }     // ::1
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff { return isPublic(v4: Array(b[12..<16])) }   // ::ffff:a.b.c.d
        if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return false }              // fe80::/10 link-local
        if (b[0] & 0xfe) == 0xfc { return false }                              // fc00::/7 ULA
        if b[0] == 0xff { return false }                                       // multicast
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false }   // documentation
        if b[0] == 0x01 && b[1] == 0x00 && b[2..<8].allSatisfy({ $0 == 0 }) { return false } // 100::/64 discard
        if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b { return isPublic(v4: Array(b[12..<16])) } // NAT64
        return true
    }
}
