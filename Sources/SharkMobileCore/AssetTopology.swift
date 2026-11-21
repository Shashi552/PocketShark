import Foundation

public struct DiscoveredHost: Identifiable, Hashable, Codable {
    public var id: String { ip.isEmpty ? mac : ip }
    public let ip: String
    public var mac: String
    public var hostname: String?
    public var vendor: String
    public var osGuess: String
    public var activeRoles: [String]
    public var openPorts: [Int]
    public var packetCount: Int
    public var bytesTransferred: Int
    public var firstSeen: Double
    public var lastSeen: Double
    public var countryFlag: String?
    public var countryName: String?
    public var asnInfo: String?

    public init(
        ip: String,
        mac: String,
        hostname: String? = nil,
        vendor: String = "Unknown Vendor",
        osGuess: String = "Generic Network Device",
        activeRoles: [String] = [],
        openPorts: [Int] = [],
        packetCount: Int = 1,
        bytesTransferred: Int = 0,
        firstSeen: Double = Date().timeIntervalSince1970,
        lastSeen: Double = Date().timeIntervalSince1970,
        countryFlag: String? = nil,
        countryName: String? = nil,
        asnInfo: String? = nil
    ) {
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.vendor = vendor
        self.osGuess = osGuess
        self.activeRoles = activeRoles
        self.openPorts = openPorts
        self.packetCount = packetCount
        self.bytesTransferred = max(0, bytesTransferred)
        let now = Date().timeIntervalSince1970
        self.firstSeen = (firstSeen.isFinite && firstSeen >= 0) ? firstSeen : now
        self.lastSeen = (lastSeen.isFinite && lastSeen >= 0) ? lastSeen : now
        self.countryFlag = countryFlag
        self.countryName = countryName
        self.asnInfo = asnInfo
    }
}

@MainActor
public final class AssetTopology: ObservableObject {
    @Published public var assets: [DiscoveredHost] = []
    public var hosts: [DiscoveredHost] { return assets }
    @Published public var totalDiscoveredHosts: Int = 0
    @Published public var gatewayHost: DiscoveredHost?

    private let maxHosts: Int = 500
    private var hostMap: [String: DiscoveredHost] = [:]

    public init() {}

    public func clear() {
        hostMap.removeAll()
        assets.removeAll()
        totalDiscoveredHosts = 0
        gatewayHost = nil
    }

    public func process(packet: PacketRecord) {
        let srcIP = packet.source
        let dstIP = packet.destination

        // Extract MACs if available from layers
        var srcMAC = ""
        var dstMAC = ""
        var hostnameCandidate: String? = nil

        for layer in packet.layers {
            if layer.name == "Ethernet II" {
                for f in layer.fields {
                    if f.name == "Source MAC" { srcMAC = f.value }
                    if f.name == "Destination MAC" { dstMAC = f.value }
                }
            } else if layer.name.contains("Address Resolution Protocol") {
                for f in layer.fields {
                    if f.name == "Sender MAC Address" { srcMAC = f.value }
                    if f.name == "Target MAC Address" { dstMAC = f.value }
                }
            } else if layer.name.contains("Domain Name System") {
                for f in layer.fields {
                    if f.name == "Queried Domain" && !f.value.isEmpty {
                        if f.value.hasSuffix(".local") {
                            hostnameCandidate = f.value
                        }
                    }
                }
            } else if layer.name.contains("Transport Layer Security") {
                for f in layer.fields {
                    if f.name == "Server Name Indication" {
                        hostnameCandidate = f.value
                    }
                }
            }
        }

        // Process Source Host
        if isUsableIP(srcIP) {
            updateHost(
                ip: srcIP,
                mac: srcMAC,
                bytes: packet.length,
                timestamp: packet.timestamp,
                hostname: hostnameCandidate,
                packet: packet,
                isSource: true
            )
        }

        // Process Destination Host
        if isUsableIP(dstIP) {
            updateHost(
                ip: dstIP,
                mac: dstMAC,
                bytes: packet.length,
                timestamp: packet.timestamp,
                hostname: hostnameCandidate,
                packet: packet,
                isSource: false
            )
        }

        // Keep published array in sync sorted by packet count
        self.assets = Array(hostMap.values).sorted { $0.packetCount > $1.packetCount }
        self.totalDiscoveredHosts = hostMap.count
    }

    private func isUsableIP(_ ip: String) -> Bool {
        return !ip.isEmpty && ip != "Unknown" && ip != "0.0.0.0" && ip != "255.255.255.255" && !ip.contains("BLE")
    }

    private func updateHost(
        ip: String,
        mac: String,
        bytes: Int,
        timestamp: Double,
        hostname: String?,
        packet: PacketRecord,
        isSource: Bool
    ) {
        let safeTimestamp = (timestamp.isFinite && timestamp >= 0) ? timestamp : Date().timeIntervalSince1970
        let safeBytes = max(0, bytes)

        if hostMap[ip] == nil && hostMap.count >= maxHosts {
            if let lowestKey = hostMap.min(by: { $0.value.packetCount < $1.value.packetCount })?.key {
                hostMap.removeValue(forKey: lowestKey)
            }
        }

        var host = hostMap[ip] ?? DiscoveredHost(
            ip: ip,
            mac: mac,
            firstSeen: safeTimestamp,
            lastSeen: safeTimestamp
        )

        host.lastSeen = safeTimestamp
        host.packetCount += 1
        host.bytesTransferred += safeBytes

        if host.mac.isEmpty && !mac.isEmpty {
            host.mac = mac
        }

        // MAC OUI lookup
        if host.vendor == "Unknown Vendor" && !host.mac.isEmpty {
            host.vendor = lookupOUIVendor(mac: host.mac)
        }

        // Hostname assignment
        if let h = hostname, host.hostname == nil {
            host.hostname = h
        }

        // Passive OS Fingerprinting (IPv4 TTL + TCP Window)
        if host.osGuess == "Generic Network Device" {
            host.osGuess = fingerprintOS(packet: packet)
        }

        // Role & Port Discovery
        var roles = Set(host.activeRoles)
        var ports = Set(host.openPorts)

        if ip.hasSuffix(".1") || ip.hasSuffix(".254") {
            roles.insert("Gateway / Router")
            if gatewayHost == nil {
                gatewayHost = host
            }
        }

        if packet.protocolType == .dns { roles.insert("DNS Resolver") }
        if packet.protocolType == .dhcp { roles.insert("DHCP Service") }
        if packet.protocolType == .tls || packet.protocolType == .http {
            if !isSource { roles.insert("Web Server") }
        }

        // Extract Ports from packet info
        if packet.info.contains("53") { ports.insert(53) }
        if packet.info.contains("80") { ports.insert(80) }
        if packet.info.contains("443") { ports.insert(443) }
        if packet.info.contains("22") { ports.insert(22) }
        if packet.info.contains("1900") { ports.insert(1900) }
        if packet.info.contains("5353") { ports.insert(5353) }

        host.activeRoles = Array(roles)
        host.openPorts = Array(ports).sorted()

        // GeoIP Enrichment
        if host.countryName == nil {
            let geo = OfflineGeoIP.lookup(ipString: ip)
            host.countryFlag = geo.flagEmoji
            host.countryName = geo.countryName
            host.asnInfo = geo.asn
        }

        hostMap[ip] = host
    }

    private func fingerprintOS(packet: PacketRecord) -> String {
        // Read TTL from IPv4 layer if available
        guard let ipLayer = packet.layers.first(where: { $0.name.contains("Internet Protocol Version 4") }) else {
            return "Generic Network Device"
        }

        var ttl = 0
        for f in ipLayer.fields {
            if f.name == "Time to Live" {
                ttl = Int(f.value) ?? 0
            }
        }

        if ttl > 0 {
            if ttl <= 64 {
                return "Apple macOS / iOS / Linux / Android (TTL ~64)"
            } else if ttl <= 128 {
                return "Microsoft Windows 10/11 / Server (TTL ~128)"
            } else {
                return "Cisco IOS / Network Gateway / Solaris (TTL ~255)"
            }
        }

        return "Generic Network Device"
    }

    private func lookupOUIVendor(mac: String) -> String {
        let clean = mac.uppercased().replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "")
        guard clean.count >= 6 else { return "Unknown Vendor" }
        let prefix = String(clean.prefix(6))

        switch prefix {
        case "000393", "000502", "000A27", "0010FA", "0017F2", "001EC2", "3C22FB", "406C8F", "70EE50", "ACDE48", "F01898":
            return "Apple, Inc."
        case "00000C", "000142", "000143", "000163", "000164", "6C03B5", "000C86":
            return "Cisco Systems, Inc."
        case "0002B3", "000347", "000423", "000E0C", "A44CC8":
            return "Intel Corporation"
        case "0000F0", "000278", "0007AB", "5056BF", "94652D":
            return "Samsung Electronics"
        case "240AC4", "30AEA4", "2462AB", "840D8E", "18FE34":
            return "Espressif Systems (IoT / ESP32)"
        case "B827EB", "DCA632", "E45F01", "28CDC1":
            return "Raspberry Pi Foundation"
        case "001A11", "3C5AB4", "546009", "F4F5DB":
            return "Google LLC"
        case "0003FF", "00125A", "00155D", "7C1E52":
            return "Microsoft Corporation"
        case "00065B", "000874", "001143", "14FEB5":
            return "Dell Technologies"
        default:
            return "Standard IEEE Host"
        }
    }
}
