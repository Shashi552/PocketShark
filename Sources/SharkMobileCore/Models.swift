import Foundation

public enum ProtocolType: String, Codable, CaseIterable {
    case ethernet = "ETH"
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"
    case arp = "ARP"
    case icmp = "ICMP"
    case tcp = "TCP"
    case udp = "UDP"
    case dns = "DNS"
    case tls = "TLS"
    case http = "HTTP"
    case unknown = "DATA"

    public var colorHex: String {
        switch self {
        case .http: return "#E4FFC7"     // Wireshark light green
        case .tcp: return "#E7E6FF"      // Wireshark light purple
        case .udp: return "#DAEEFF"      // Wireshark light cyan
        case .dns: return "#BFDCFF"      // Wireshark soft blue
        case .tls: return "#D0C9FF"      // Wireshark dark purple
        case .icmp: return "#E8E8E8"     // Wireshark gray
        case .arp: return "#FAF0D7"      // Wireshark cream
        default: return "#FFFFFF"
        }
    }
}

public struct FieldDetail: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let value: String
    public let byteRange: Range<Int>?

    public init(name: String, value: String, byteRange: Range<Int>? = nil) {
        self.name = name
        self.value = value
        self.byteRange = byteRange
    }
}

public struct DissectedLayer: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let summary: String
    public let fields: [FieldDetail]
    public let byteRange: Range<Int>?

    public init(name: String, summary: String, fields: [FieldDetail], byteRange: Range<Int>? = nil) {
        self.name = name
        self.summary = summary
        self.fields = fields
        self.byteRange = byteRange
    }
}

public struct PacketRecord: Identifiable, Hashable {
    public let id: Int
    public let timestamp: Double
    public let timeString: String
    public let source: String
    public let destination: String
    public let protocolType: ProtocolType
    public let length: Int
    public let info: String
    public let rawData: Data
    public let layers: [DissectedLayer]

    public init(
        id: Int,
        timestamp: Double,
        source: String,
        destination: String,
        protocolType: ProtocolType,
        length: Int,
        info: String,
        rawData: Data,
        layers: [DissectedLayer]
    ) {
        self.id = id
        self.timestamp = timestamp
        let secs = Int(timestamp)
        let micros = Int((timestamp - Double(secs)) * 1_000_000)
        self.timeString = String(format: "%d.%06d", secs, micros)
        self.source = source
        self.destination = destination
        self.protocolType = protocolType
        self.length = length
        self.info = info
        self.rawData = rawData
        self.layers = layers
    }
}
