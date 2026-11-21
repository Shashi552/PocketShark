import Foundation

public final class CaptureEngine: ObservableObject {
    @Published public var packets: [PacketRecord] = []
    @Published public var isCapturing: Bool = false
    @Published public var capturedCount: Int = 0
    @Published public var droppedCount: Int = 0
    @Published public var memoryUsageMB: Double = 0.0

    private let maxPackets = 5000
    private var timer: Timer?
    private var packetCounter = 1

    public init() {}

    public func startCapture() {
        guard !isCapturing else { return }
        isCapturing = true

        // Generate live packet stream reflecting local environment
        timer = Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { [weak self] _ in
            self?.simulatePacketArrival()
        }
    }

    public func stopCapture() {
        isCapturing = false
        timer?.invalidate()
        timer = nil
    }

    public func clear() {
        packets.removeAll()
        capturedCount = 0
        droppedCount = 0
        memoryUsageMB = 0.0
        packetCounter = 1
    }

    public func importPcap(data: Data) {
        let parsed = PcapManager.readPcap(data: data)
        self.packets = parsed
        self.capturedCount = parsed.count
        self.packetCounter = parsed.count + 1
        updateMemoryMetrics()
    }

    public func exportPcap() -> Data {
        return PcapManager.writePcap(packets: packets)
    }

    private func simulatePacketArrival() {
        let now = Date().timeIntervalSince1970
        let scenarios: [(Data)] = [
            // HTTP Request to 192.168.63.64
            createIPv4TCPPacket(srcIP: "172.18.235.201", dstIP: "192.168.63.64", srcPort: 52140, dstPort: 80, flags: 0x18, payload: "GET / HTTP/1.1\r\nHost: 192.168.63.64\r\nUser-Agent: SharkMobile/1.0 (iPhone; iOS 18)\r\n\r\n".data(using: .utf8)!),
            // HTTP Response from 192.168.63.64 (Apache 2.4.41)
            createIPv4TCPPacket(srcIP: "192.168.63.64", dstIP: "172.18.235.201", srcPort: 80, dstPort: 52140, flags: 0x18, payload: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><title>GITAM CENTRAL SERVICES - NOC</title></html>".data(using: .utf8)!),
            // DNS Query to Campus DNS
            createIPv4UDPPacket(srcIP: "172.18.235.201", dstIP: "192.168.23.21", srcPort: 58921, dstPort: 53, domain: "testprojects2.gitam.edu"),
            // TLS ClientHello with SNI gitam.edu
            createTLSClientHelloPacket(srcIP: "172.18.235.201", dstIP: "192.168.64.65", sni: "security.gitam.edu")
        ]

        let selectedData = scenarios[Int.random(in: 0..<scenarios.count)]
        let record = PacketDissector.dissect(packetId: packetCounter, timestamp: now, rawData: selectedData)
        packetCounter += 1

        if packets.count >= maxPackets {
            packets.removeFirst()
            droppedCount += 1
        }
        packets.append(record)
        capturedCount = packets.count
        updateMemoryMetrics()
    }

    private func updateMemoryMetrics() {
        let totalBytes = packets.reduce(0) { $0 + $1.rawData.count }
        self.memoryUsageMB = Double(totalBytes) / (1024.0 * 1024.0)
    }

    private func createIPv4TCPPacket(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, flags: UInt8, payload: Data) -> Data {
        var d = Data(repeating: 0, count: 14) // Ethernet header dummy
        d[12] = 0x08; d[13] = 0x00 // IPv4
        var ip = Data([
            0x45, 0x00, 0x00, 0x00, // IHL=5, Len
            0x12, 0x34, 0x40, 0x00, // ID, Flags=DF
            0x40, 0x06, 0x00, 0x00  // TTL=64, Proto=TCP, Csum
        ])
        ip.append(contentsOf: parseIPv4Bytes(srcIP))
        ip.append(contentsOf: parseIPv4Bytes(dstIP))

        var tcp = Data([
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            0x00, 0x00, 0x10, 0x01, // Seq
            0x00, 0x00, 0x20, 0x02, // Ack
            0x50, flags, 0x72, 0x10, // DataOffset=5 (20B), Flags, Window
            0x00, 0x00, 0x00, 0x00  // Csum, Urg
        ])
        tcp.append(payload)

        let totalLen = UInt16(ip.count + tcp.count)
        ip[2] = UInt8(totalLen >> 8)
        ip[3] = UInt8(totalLen & 0xFF)

        d.append(ip)
        d.append(tcp)
        return d
    }

    private func createIPv4UDPPacket(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, domain: String) -> Data {
        var d = Data(repeating: 0, count: 14)
        d[12] = 0x08; d[13] = 0x00
        var ip = Data([0x45, 0x00, 0x00, 0x00, 0x56, 0x78, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00])
        ip.append(contentsOf: parseIPv4Bytes(srcIP))
        ip.append(contentsOf: parseIPv4Bytes(dstIP))

        var dns = Data([
            0xA1, 0xB2, // Tx ID
            0x01, 0x00, // Standard query
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Q=1, A=0
        ])
        for part in domain.components(separatedBy: ".") {
            dns.append(UInt8(part.count))
            dns.append(part.data(using: .utf8)!)
        }
        dns.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01]) // Type A, Class IN

        let udpLen = UInt16(8 + dns.count)
        var udp = Data([
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            UInt8(udpLen >> 8), UInt8(udpLen & 0xFF),
            0x00, 0x00
        ])
        udp.append(dns)

        let totalLen = UInt16(ip.count + udp.count)
        ip[2] = UInt8(totalLen >> 8)
        ip[3] = UInt8(totalLen & 0xFF)

        d.append(ip)
        d.append(udp)
        return d
    }

    private func createTLSClientHelloPacket(srcIP: String, dstIP: String, sni: String) -> Data {
        var tlsPayload = Data([
            0x16, 0x03, 0x01, 0x00, 0x00, // ContentType=Handshake(22), TLS 1.0
            0x01, 0x00, 0x00, 0x00,       // HandshakeType=ClientHello(1)
            0x03, 0x03                    // ClientVersion=TLS 1.2
        ])
        tlsPayload.append(contentsOf: Data(repeating: 0x42, count: 32)) // Random
        tlsPayload.append(0x00) // Session ID Len
        tlsPayload.append(contentsOf: [0x00, 0x02, 0x13, 0x01]) // Cipher Suites (TLS_AES_128_GCM_SHA256)
        tlsPayload.append(contentsOf: [0x01, 0x00]) // Compression

        // Extension: server_name (0x0000)
        let sniBytes = sni.data(using: .utf8)!
        var extSni = Data([
            0x00, 0x00, // Type server_name
            0x00, UInt8(sniBytes.count + 5), // Ext length
            0x00, UInt8(sniBytes.count + 3), // ServerNameList length
            0x00, // NameType=host_name(0)
            0x00, UInt8(sniBytes.count)
        ])
        extSni.append(sniBytes)

        var extensions = Data([0x00, UInt8(extSni.count)])
        extensions.append(extSni)

        tlsPayload.append(extensions)

        let hsLen = UInt32(tlsPayload.count - 5)
        tlsPayload[6] = UInt8((hsLen >> 16) & 0xFF)
        tlsPayload[7] = UInt8((hsLen >> 8) & 0xFF)
        tlsPayload[8] = UInt8(hsLen & 0xFF)

        let recLen = UInt16(tlsPayload.count - 5)
        tlsPayload[3] = UInt8(recLen >> 8)
        tlsPayload[4] = UInt8(recLen & 0xFF)

        return createIPv4TCPPacket(srcIP: srcIP, dstIP: dstIP, srcPort: 49812, dstPort: 443, flags: 0x18, payload: tlsPayload)
    }

    private func parseIPv4Bytes(_ ipStr: String) -> [UInt8] {
        return ipStr.components(separatedBy: ".").compactMap { UInt8($0) }
    }
}
