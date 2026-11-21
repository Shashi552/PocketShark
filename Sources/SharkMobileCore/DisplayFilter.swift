import Foundation

public struct DisplayFilter {
    public static func evaluate(filter: String, packet: PacketRecord, depth: Int = 0) -> Bool {
        guard depth < 8 else { return true }
        let trimmed = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return true }

        // Handle OR expressions
        if trimmed.contains("||") {
            let parts = trimmed.components(separatedBy: "||").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if parts.isEmpty { return true }
            return parts.contains { evaluate(filter: $0, packet: packet, depth: depth + 1) }
        }

        // Handle AND expressions
        if trimmed.contains("&&") {
            let parts = trimmed.components(separatedBy: "&&").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if parts.isEmpty { return true }
            return parts.allSatisfy { evaluate(filter: $0, packet: packet, depth: depth + 1) }
        }

        let expr = trimmed.lowercased()

        // Protocol matching
        if expr == "tcp" { return packet.protocolType == .tcp || packet.layers.contains { $0.name.contains("TCP") } }
        if expr == "udp" { return packet.protocolType == .udp || packet.layers.contains { $0.name.contains("UDP") } }
        if expr == "dns" { return packet.protocolType == .dns || packet.protocolType == .mdns || packet.layers.contains { $0.name.contains("DNS") } }
        if expr == "mdns" { return packet.protocolType == .mdns || packet.layers.contains { $0.name.contains("mDNS") || $0.name.contains("Bonjour") } }
        if expr == "tls" || expr == "ssl" { return packet.protocolType == .tls || packet.layers.contains { $0.name.contains("TLS") } }
        if expr == "http" { return packet.protocolType == .http || packet.layers.contains { $0.name.contains("HTTP") } }
        if expr == "websocket" || expr == "ws" { return packet.protocolType == .websocket || packet.layers.contains { $0.name.contains("WebSocket") } }
        if expr == "icmp" { return packet.protocolType == .icmp || packet.layers.contains { $0.name.contains("ICMP") } }
        if expr == "arp" { return packet.protocolType == .arp || packet.layers.contains { $0.name.contains("ARP") } }
        if expr == "ble" { return packet.protocolType == .ble || packet.layers.contains { $0.name.contains("Bluetooth") } }
        if expr == "quic" { return packet.protocolType == .quic || packet.layers.contains { $0.name.contains("QUIC") } }
        if expr == "dhcp" || expr == "bootp" { return packet.protocolType == .dhcp || packet.layers.contains { $0.name.contains("DHCP") || $0.name.contains("BOOTP") } }
        if expr == "ssdp" { return packet.protocolType == .ssdp || packet.layers.contains { $0.name.contains("SSDP") } }

        // Expert Info Severity Filters (1-tap via Expert Pills)
        if expr == "error" || expr == "errors" { return packet.expertInfo?.severity == .error }
        if expr == "warn" || expr == "warning" || expr == "warnings" { return packet.expertInfo?.severity == .warning }
        if expr == "note" || expr == "notes" { return packet.expertInfo?.severity == .note }
        if expr == "chat" || expr == "chats" { return packet.expertInfo?.severity == .chat }

        // IP Address matching with exact match (avoiding 192.168.1.1 matching 192.168.1.100)
        if expr.hasPrefix("ip.addr ==") || expr.hasPrefix("ip.addr==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return isExactMatch(address: target, candidate: packet.source) || isExactMatch(address: target, candidate: packet.destination)
        }
        if expr.hasPrefix("ip.addr !=") || expr.hasPrefix("ip.addr!=") {
            let target = expr.components(separatedBy: "!=").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return !isExactMatch(address: target, candidate: packet.source) && !isExactMatch(address: target, candidate: packet.destination)
        }
        if expr.hasPrefix("ip.src ==") || expr.hasPrefix("ip.src==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return isExactMatch(address: target, candidate: packet.source)
        }
        if expr.hasPrefix("ip.src !=") || expr.hasPrefix("ip.src!=") {
            let target = expr.components(separatedBy: "!=").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return !isExactMatch(address: target, candidate: packet.source)
        }
        if expr.hasPrefix("ip.dst ==") || expr.hasPrefix("ip.dst==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return isExactMatch(address: target, candidate: packet.destination)
        }
        if expr.hasPrefix("ip.dst !=") || expr.hasPrefix("ip.dst!=") {
            let target = expr.components(separatedBy: "!=").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return !isExactMatch(address: target, candidate: packet.destination)
        }

        // IPv6 matching
        if expr.hasPrefix("ipv6.addr ==") || expr.hasPrefix("ipv6.addr==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.source.lowercased() == target || packet.destination.lowercased() == target
        }
        if expr.hasPrefix("ipv6.src ==") || expr.hasPrefix("ipv6.src==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.source.lowercased() == target
        }
        if expr.hasPrefix("ipv6.dst ==") || expr.hasPrefix("ipv6.dst==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.destination.lowercased() == target
        }

        // Port matching
        if expr.hasPrefix("tcp.port ==") || expr.hasPrefix("tcp.port==") || expr.hasPrefix("udp.port ==") || expr.hasPrefix("udp.port==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return matchesPort(target: target, packet: packet)
        }
        if expr.hasPrefix("tcp.port !=") || expr.hasPrefix("tcp.port!=") || expr.hasPrefix("udp.port !=") || expr.hasPrefix("udp.port!=") {
            let target = expr.components(separatedBy: "!=").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !target.isEmpty else { return true }
            return !matchesPort(target: target, packet: packet)
        }

        // General substring search with lossy UTF8 decoding
        if expr.contains("contains") {
            let target = expr.components(separatedBy: "contains").last?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\"", with: "") ?? ""
            guard !target.isEmpty else { return true }
            let ascii = String(decoding: packet.rawData, as: UTF8.self)
            return ascii.lowercased().contains(target) || packet.info.lowercased().contains(target)
        }

        // Fallback: search anywhere in info, source, or destination
        return packet.info.lowercased().contains(expr) || packet.source.lowercased().contains(expr) || packet.destination.lowercased().contains(expr)
    }

    private static func isExactMatch(address: String, candidate: String) -> Bool {
        let cleanCandidate = candidate.components(separatedBy: ":").first ?? candidate
        return cleanCandidate.trimmingCharacters(in: .whitespacesAndNewlines) == address
    }

    private static func matchesPort(target: String, packet: PacketRecord) -> Bool {
        return packet.layers.contains { l in
            l.fields.contains { f in f.value == target && f.name.contains("Port") }
        } || packet.info.contains(" \(target) ") || packet.info.hasPrefix("\(target) →") || packet.info.contains("→ \(target) ")
    }
}
