import Foundation

public enum ThreatSeverity: String, Codable, CaseIterable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"

    public var colorHex: String {
        switch self {
        case .critical: return "#FF1744"
        case .high: return "#FF5252"
        case .medium: return "#FF9100"
        case .low: return "#00E676"
        }
    }

    public var badgeIcon: String {
        switch self {
        case .critical: return "flame.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "shield.lefthalf.filled"
        case .low: return "info.circle.fill"
        }
    }
}

public enum ThreatType: String, Codable, CaseIterable {
    case arpSpoofing = "ARP Poisoning / MITM"
    case rogueDHCP = "Rogue DHCP Server"
    case dnsSpoofing = "DNS Cache Poisoning"
    case portScan = "Port Scan / Sweep"
    case credentialLeak = "Credential Exposure"
    case synFlood = "TCP SYN Flood"
    case sslStrip = "Plaintext HTTP Downgrade"
}

public struct ThreatEvent: Identifiable, Hashable, Codable {
    public let id: UUID
    public let timestamp: Double
    public let type: ThreatType
    public let severity: ThreatSeverity
    public let title: String
    public let description: String
    public let attackerIP: String
    public let victimIP: String
    public let evidencePacketId: Int
    public let mitreTactic: String
    public let remediationAdvice: String

    public init(
        id: UUID = UUID(),
        timestamp: Double,
        type: ThreatType,
        severity: ThreatSeverity,
        title: String,
        description: String,
        attackerIP: String,
        victimIP: String,
        evidencePacketId: Int,
        mitreTactic: String,
        remediationAdvice: String
    ) {
        self.id = id
        self.timestamp = (timestamp.isFinite && timestamp >= 0) ? timestamp : Date().timeIntervalSince1970
        self.type = type
        self.severity = severity
        self.title = title
        self.description = description
        self.attackerIP = attackerIP
        self.victimIP = victimIP
        self.evidencePacketId = evidencePacketId
        self.mitreTactic = mitreTactic
        self.remediationAdvice = remediationAdvice
    }

    // Resilience & Backwards-Compatibility Accessors
    public var details: String { description }
    public var source: String { attackerIP }
    public var packetId: Int { evidencePacketId }
}

@MainActor
public final class ThreatDetector: ObservableObject {
    @Published public var threats: [ThreatEvent] = []
    @Published public var criticalCount: Int = 0
    @Published public var highCount: Int = 0
    @Published public var mediumCount: Int = 0
    @Published public var lowCount: Int = 0

    private let maxThreatsCount: Int = 500
    private let maxTrackedIPs: Int = 200
    private let maxArpEntries: Int = 500

    // State Tracking
    private var arpTable: [String: (mac: String, timestamp: Double)] = [:]
    private var knownDHCPServers: Set<String> = []
    private var dnsTransactions: [Int: (domain: String, timestamp: Double, answers: [String])] = [:]
    private var portScanTracker: [String: [(port: Int, timestamp: Double)]] = [:]

    public init() {}

    public func clear() {
        threats.removeAll()
        criticalCount = 0
        highCount = 0
        mediumCount = 0
        lowCount = 0
        arpTable.removeAll()
        knownDHCPServers.removeAll()
        dnsTransactions.removeAll()
        portScanTracker.removeAll()
    }

    @discardableResult
    public func analyze(packet: PacketRecord) -> [ThreatEvent] {
        var newThreats: [ThreatEvent] = []

        // 1. ARP Poisoning / Spoofing Analysis
        if packet.protocolType == .arp {
            if let arpThreat = checkARP(packet: packet) {
                newThreats.append(arpThreat)
            }
        }

        // 2. Rogue DHCP Server Detection
        if packet.protocolType == .dhcp {
            if let dhcpThreat = checkDHCP(packet: packet) {
                newThreats.append(dhcpThreat)
            }
        }

        // 3. DNS Spoofing / Insecure Resolution
        if packet.protocolType == .dns {
            if let dnsThreat = checkDNS(packet: packet) {
                newThreats.append(dnsThreat)
            }
        }

        // 4. Port Scan / Reconnaissance Detection (TCP SYN / UDP)
        if packet.protocolType == .tcp || packet.protocolType == .udp {
            if let scanThreat = checkPortScan(packet: packet) {
                newThreats.append(scanThreat)
            }
        }

        // 5. Security Hunter Finding Integration
        let hunterFindings = SecurityHunter.inspect(packet: packet)
        for h in hunterFindings {
            let threat = ThreatEvent(
                timestamp: h.timestamp,
                type: .credentialLeak,
                severity: h.severity == .critical ? .critical : .high,
                title: h.title,
                description: "\(h.description) Preview: \(h.secretPreview)",
                attackerIP: h.destinationIP,
                victimIP: h.sourceIP,
                evidencePacketId: h.packetId,
                mitreTactic: "TA0006: Credential Access (T1557)",
                remediationAdvice: "Enforce TLS 1.3 / HTTPS immediately. Revoke and rotate exposed credentials."
            )
            newThreats.append(threat)
        }

        // Register new threats into published model
        for t in newThreats {
            threats.insert(t, at: 0)
            switch t.severity {
            case .critical: criticalCount += 1
            case .high: highCount += 1
            case .medium: mediumCount += 1
            case .low: lowCount += 1
            }
        }
        if threats.count > maxThreatsCount {
            threats.removeLast(threats.count - maxThreatsCount)
        }

        return newThreats
    }

    private func checkARP(packet: PacketRecord) -> ThreatEvent? {
        guard let arpLayer = packet.layers.first(where: { $0.name.contains("Address Resolution Protocol") }) else { return nil }
        var senderMAC = ""
        var senderIP = ""
        var isReply = false

        for f in arpLayer.fields {
            if f.name == "Sender MAC Address" { senderMAC = f.value.lowercased() }
            if f.name == "Sender IP Address" { senderIP = f.value }
            if f.name == "Opcode" && f.value.contains("reply") { isReply = true }
        }

        guard !senderIP.isEmpty && !senderMAC.isEmpty && senderIP != "0.0.0.0" else { return nil }

        if arpTable.count >= maxArpEntries && arpTable[senderIP] == nil {
            arpTable.removeAll()
        }

        if isReply, let existing = arpTable[senderIP] {
            if existing.mac != senderMAC {
                // Conflict detected! Same IP mapped to different MAC
                let threat = ThreatEvent(
                    timestamp: packet.timestamp,
                    type: .arpSpoofing,
                    severity: .critical,
                    title: "Active ARP Poisoning / MITM Attack",
                    description: "Host '\(senderIP)' was previously bound to MAC '\(existing.mac)', but MAC '\(senderMAC)' is now claiming this IP address. Potential rogue gateway spoofing.",
                    attackerIP: senderMAC,
                    victimIP: senderIP,
                    evidencePacketId: packet.id,
                    mitreTactic: "TA0009: Collection (T1557.002 ARP Poisoning)",
                    remediationAdvice: "Enable Dynamic ARP Inspection (DAI) on the switch and inspect local gateway ARP cache."
                )
                arpTable[senderIP] = (mac: senderMAC, timestamp: packet.timestamp)
                return threat
            }
        } else {
            arpTable[senderIP] = (mac: senderMAC, timestamp: packet.timestamp)
        }

        return nil
    }

    private func checkDHCP(packet: PacketRecord) -> ThreatEvent? {
        // Look for DHCP Offer / ACK from a server (port 67 -> 68)
        let isServerToClient = packet.info.contains("67") && packet.info.contains("68")
        guard isServerToClient || packet.info.contains("Offer") || packet.info.contains("ACK") else { return nil }

        if knownDHCPServers.count > 50 {
            knownDHCPServers.removeAll()
        }

        let serverIP = packet.source
        if knownDHCPServers.isEmpty {
            knownDHCPServers.insert(serverIP)
            return nil
        }

        if !knownDHCPServers.contains(serverIP) {
            // A second unexpected DHCP server has appeared on the broadcast segment
            knownDHCPServers.insert(serverIP)
            return ThreatEvent(
                timestamp: packet.timestamp,
                type: .rogueDHCP,
                severity: .high,
                title: "Rogue DHCP Server Detected",
                description: "Unauthorized host '\(serverIP)' answered DHCP lease requests. Known server: \(knownDHCPServers.filter { $0 != serverIP }.joined(separator: ", ")).",
                attackerIP: serverIP,
                victimIP: "255.255.255.255 (Broadcast)",
                evidencePacketId: packet.id,
                mitreTactic: "TA0001: Initial Access (T1200)",
                remediationAdvice: "Enable DHCP Snooping on upstream managed switches and isolate port for \(serverIP)."
            )
        }

        return nil
    }

    private func checkDNS(packet: PacketRecord) -> ThreatEvent? {
        // Parse DNS responses
        guard packet.info.contains("response"),
              let dnsLayer = packet.layers.first(where: { $0.name.contains("Domain Name System") }) else { return nil }

        var txIdStr = ""
        var domain = ""
        for f in dnsLayer.fields {
            if f.name == "Transaction ID" { txIdStr = f.value }
            if f.name == "Queried Domain" { domain = f.value }
        }

        // Suspicious answers pointing public domain to loopback or RFC1918
        if (domain.contains("apple.com") || domain.contains("google.com") || domain.contains("microsoft.com") || domain.contains("bank")) &&
            (packet.info.contains("127.0.0.1") || packet.info.contains("0.0.0.0")) {
            return ThreatEvent(
                timestamp: packet.timestamp,
                type: .dnsSpoofing,
                severity: .critical,
                title: "Malicious DNS Redirection / Sinkhole",
                description: "Critical domain '\(domain)' (TxID: \(txIdStr)) was resolved to loopback/blackhole IP address in response from '\(packet.source)'.",
                attackerIP: packet.source,
                victimIP: packet.destination,
                evidencePacketId: packet.id,
                mitreTactic: "TA0009: Collection (T1557.001 DNS Spoofing)",
                remediationAdvice: "Switch to DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) with DNSSEC validation."
            )
        }

        return nil
    }

    private func checkPortScan(packet: PacketRecord) -> ThreatEvent? {
        // Track TCP SYN or UDP probes
        guard let tcpLayer = packet.layers.first(where: { $0.name.contains("Transmission Control Protocol") }) else {
            return nil
        }

        var isSYN = false
        var isACK = false
        var dstPort = 0
        for f in tcpLayer.fields {
            if f.name == "Flags" {
                if f.value.contains("SYN") { isSYN = true }
                if f.value.contains("ACK") { isACK = true }
            }
            if f.name == "Destination Port" {
                dstPort = Int(f.value) ?? 0
            }
        }

        // Only count initiating SYN packets (SYN without ACK)
        guard isSYN && !isACK && dstPort > 0 else { return nil }

        let src = packet.source
        let now = packet.timestamp.isFinite ? packet.timestamp : Date().timeIntervalSince1970

        if portScanTracker.count >= maxTrackedIPs && portScanTracker[src] == nil {
            // Prune expired IPs outside 15 second window
            portScanTracker = portScanTracker.filter { _, history in
                guard let latest = history.last else { return false }
                return (now - latest.timestamp) <= 15.0
            }
            if portScanTracker.count >= maxTrackedIPs {
                portScanTracker.removeAll()
            }
        }

        var history = portScanTracker[src] ?? []
        // Clean out older entries outside 15 second window
        history.removeAll { now - $0.timestamp > 15.0 }
        history.append((port: dstPort, timestamp: now))
        portScanTracker[src] = history

        let uniquePorts = Set(history.map { $0.port })
        if uniquePorts.count >= 6 {
            // Trigger scan detection and reset history so we don't spam
            portScanTracker[src] = []
            return ThreatEvent(
                timestamp: packet.timestamp,
                type: .portScan,
                severity: .high,
                title: "TCP SYN Port Scan / Host Sweep",
                description: "Host '\(src)' probed \(uniquePorts.count) distinct destination ports in under 15 seconds. High probability of Nmap or automated scanner sweep.",
                attackerIP: src,
                victimIP: packet.destination,
                evidencePacketId: packet.id,
                mitreTactic: "TA0007: Discovery (T1046 Network Service Scanning)",
                remediationAdvice: "Block offending IP at the boundary firewall and verify if exposed services require public binding."
            )
        }

        return nil
    }
}
