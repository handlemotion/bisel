#if os(macOS)
import Darwin
import Foundation
import Security

/// Who is on the other end of the socket, from the kernel's audit token rather than anything the peer says. The tool only runs what
/// it told the app it would run, so this check is what makes the approval prompt truthful. It is not the access control: any program
/// of this user can run the real tool, and Touch ID is what stops it.
public enum AgentPeer {
    private static let team = "ZVGTVNUPVA"
    public static let toolRequirement = requirement(identifier: "app.bisel.cli")
    public static let appRequirement = requirement(identifier: "app.bisel.mac")

    private static func requirement(identifier: String) -> String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
    }

    public static func satisfies(_ requirement: String, fd: Int32) -> Bool {
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0 else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return false }
        var parsed: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &parsed) == errSecSuccess, let parsed else { return false }
        return SecCodeCheckValidity(code, [], parsed) == errSecSuccess
    }
}
#endif
