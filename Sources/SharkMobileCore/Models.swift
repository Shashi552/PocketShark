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
    case mdns = "mDNS"
    case tls = "TLS"
    case http = "HTTP"
    case websocket = "WS"
    case quic = "QUIC"
    case dhcp = "DHCP"
    case ssdp = "SSDP"
    case ssh = "SSH"
    case ble = "BLE"
    case unknown = "DATA"

    public var colorHex: String {
        switch self {
        case .http: return "#E4FFC7"     // Wireshark light green
        case .tcp: return "#E7E6FF"      // Wireshark light purple
        case .udp: return "#DAEEFF"      // Wireshark light cyan
        case .dns: return "#BFDCFF"      // Wireshark soft blue
        case .mdns: return "#BFEFFF"     // Wireshark icy cyan
        case .tls: return "#D0C9FF"      // Wireshark dark purple
        case .icmp: return "#E8E8E8"     // Wireshark gray
        case .arp: return "#FAF0D7"      // Wireshark cream
        case .quic: return "#FCE4D6"     // Wireshark peach
        case .dhcp: return "#E2EFDA"     // Wireshark mint
        case .websocket: return "#FFE4B5" // Wireshark moccasin
        case .ssdp: return "#FFF2CC"     // Wireshark pale yellow
        case .ssh: return "#D9E1F2"      // Wireshark steel blue
        case .ble: return "#DDEBF7"      // Wireshark wireless blue
        default: return "#FFFFFF"
        }
    }
}

public enum ExpertSeverity: String, Codable, CaseIterable {
    case error = "Error"       // Red (Connection RST, malformed, SSL alert)
    case warning = "Warning"   // Yellow (Retransmissions, High RTT, dup ACKs)
    case note = "Note"         // Cyan (Connection handshakes, redirects, new host)
    case chat = "Chat"         // Green (Routine 200 OK, DNS queries)

    public var colorHex: String {
        switch self {
        case .error: return "#FF3B30"
        case .warning: return "#FFCC00"
        case .note: return "#00E5FF"
        case .chat: return "#34C759"
        }
    }

    public var badgeIcon: String {
        switch self {
        case .error: return "exclamationmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .note: return "info.circle.fill"
        case .chat: return "message.circle.fill"
        }
    }
}

public struct ExpertInfo: Identifiable, Hashable, Codable {
    public let id: UUID
    public let severity: ExpertSeverity
    public let message: String
    public let group: String

    public init(id: UUID = UUID(), severity: ExpertSeverity, message: String, group: String) {
        self.id = id
        self.severity = severity
        self.message = message
        self.group = group
    }
}

public struct GPSCoordinate: Identifiable, Hashable, Codable {
    public let id: UUID
    public let latitude: Double
    public let longitude: Double
    public let altitude: Double
    public let horizontalAccuracy: Double
    public let speed: Double
    public let timestamp: Double

    public init(
        id: UUID = UUID(),
        latitude: Double,
        longitude: Double,
        altitude: Double = 0.0,
        horizontalAccuracy: Double = 5.0,
        speed: Double = 0.0,
        timestamp: Double = Date().timeIntervalSince1970
    ) {
        self.id = id
        self.latitude = latitude
        self.longitude = longitude
        self.altitude = altitude
        self.horizontalAccuracy = horizontalAccuracy
        self.speed = speed
        self.timestamp = timestamp
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
        if let r = byteRange, r.lowerBound >= 0 && r.upperBound >= r.lowerBound {
            self.byteRange = r
        } else {
            self.byteRange = nil
        }
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
        if let r = byteRange, r.lowerBound >= 0 && r.upperBound >= r.lowerBound {
            self.byteRange = r
        } else {
            self.byteRange = nil
        }
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
    public let interface: String
    public let expertInfo: ExpertInfo?
    public let geoCoord: GPSCoordinate?
    public let countryFlag: String?
    public let countryName: String?
    public let asnInfo: String?

    public init(
        id: Int,
        timestamp: Double,
        source: String,
        destination: String,
        protocolType: ProtocolType,
        length: Int,
        info: String,
        rawData: Data,
        layers: [DissectedLayer],
        interface: String = "en0 (Wi-Fi)",
        expertInfo: ExpertInfo? = nil,
        geoCoord: GPSCoordinate? = nil,
        countryFlag: String? = nil,
        countryName: String? = nil,
        asnInfo: String? = nil
    ) {
        self.id = max(0, id)
        let safeTimestamp = (timestamp.isFinite && !timestamp.isNaN && timestamp >= 0) ? min(timestamp, Double(UInt32.max)) : 0.0
        self.timestamp = safeTimestamp
        let secs = Int(safeTimestamp)
        let remainder = max(0.0, safeTimestamp - Double(secs))
        let micros = min(999_999, max(0, Int(remainder * 1_000_000)))
        self.timeString = String(format: "%d.%06d", secs, micros)
        self.source = source
        self.destination = destination
        self.protocolType = protocolType
        self.length = length
        self.info = info
        self.rawData = rawData
        self.layers = layers
        self.interface = interface
        self.expertInfo = expertInfo
        self.geoCoord = geoCoord
        self.countryFlag = countryFlag
        self.countryName = countryName
        self.asnInfo = asnInfo
    }
}
