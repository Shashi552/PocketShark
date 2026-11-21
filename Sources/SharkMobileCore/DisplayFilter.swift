import Foundation

public struct DisplayFilter {
    public static func evaluate(filter: String, packet: PacketRecord) -> Bool {
        let trimmed = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return true }

        // Handle OR expressions
        if trimmed.contains("||") {
            let parts = trimmed.components(separatedBy: "||")
            return parts.contains { evaluate(filter: $0, packet: packet) }
        }

        // Handle AND expressions
        if trimmed.contains("&&") {
            let parts = trimmed.components(separatedBy: "&&")
            return parts.allSatisfy { evaluate(filter: $0, packet: packet) }
        }

        let expr = trimmed.lowercased()

        // Protocol matching
        if expr == "tcp" { return packet.protocolType == .tcp || packet.layers.contains { $0.name.contains("TCP") } }
        if expr == "udp" { return packet.protocolType == .udp || packet.layers.contains { $0.name.contains("UDP") } }
        if expr == "dns" { return packet.protocolType == .dns || packet.layers.contains { $0.name.contains("DNS") } }
        if expr == "tls" || expr == "ssl" { return packet.protocolType == .tls || packet.layers.contains { $0.name.contains("TLS") } }
        if expr == "http" { return packet.protocolType == .http || packet.layers.contains { $0.name.contains("HTTP") } }
        if expr == "icmp" { return packet.protocolType == .icmp || packet.layers.contains { $0.name.contains("ICMP") } }
        if expr == "arp" { return packet.protocolType == .arp || packet.layers.contains { $0.name.contains("ARP") } }

        // IP Address matching
        if expr.hasPrefix("ip.addr ==") || expr.hasPrefix("ip.addr==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.source.contains(target) || packet.destination.contains(target)
        }
        if expr.hasPrefix("ip.src ==") || expr.hasPrefix("ip.src==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.source.contains(target)
        }
        if expr.hasPrefix("ip.dst ==") || expr.hasPrefix("ip.dst==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.destination.contains(target)
        }

        // Port matching
        if expr.hasPrefix("tcp.port ==") || expr.hasPrefix("tcp.port==") || expr.hasPrefix("udp.port ==") || expr.hasPrefix("udp.port==") {
            let target = expr.components(separatedBy: "==").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return packet.info.contains(target) || packet.layers.contains { l in
                l.fields.contains { f in f.value == target && (f.name.contains("Port")) }
            }
        }

        // General substring search
        if expr.contains("contains") {
            let target = expr.components(separatedBy: "contains").last?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\"", with: "") ?? ""
            if let ascii = String(data: packet.rawData, encoding: .utf8) {
                return ascii.lowercased().contains(target)
            }
            return packet.info.lowercased().contains(target)
        }

        // Fallback: search anywhere in info, source, or destination
        return packet.info.lowercased().contains(expr) || packet.source.lowercased().contains(expr) || packet.destination.lowercased().contains(expr)
    }
}
