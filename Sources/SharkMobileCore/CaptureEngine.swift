import Foundation

public final class CaptureEngine: ObservableObject {
    @Published public var packets: [PacketRecord] = []
    @Published public var isCapturing: Bool = false
    @Published public var capturedCount: Int = 0
    @Published public var droppedCount: Int = 0
    @Published public var memoryUsageMB: Double = 0.0
    @Published public var selectedInterface: String = "All Interfaces"
    @Published public var maxMemoryMB: Double = 100.0 // Configurable up to 500MB

    private var timer: Timer?
    private var packetCounter = 1

    public init() {}

    public func startCapture() {
        guard !isCapturing else { return }
        isCapturing = true

        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
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
        let (raw, iface) = generateDiversePacket()

        // Filter by interface if not "All Interfaces"
        if selectedInterface != "All Interfaces" && !iface.contains(selectedInterface.prefix(3)) {
            return
        }

        let record = PacketDissector.dissect(packetId: packetCounter, timestamp: now, rawData: raw, interface: iface)
        packetCounter += 1

        packets.append(record)
        capturedCount += 1
        updateMemoryMetrics()

        // Evict oldest only if exceeding user-configured memory threshold
        while memoryUsageMB > maxMemoryMB && !packets.isEmpty {
            packets.removeFirst()
            droppedCount += 1
            updateMemoryMetrics()
        }
    }

    private func updateMemoryMetrics() {
        let totalBytes = packets.reduce(0) { $0 + $1.rawData.count }
        self.memoryUsageMB = Double(totalBytes) / (1024.0 * 1024.0)
    }

    private func generateDiversePacket() -> (Data, String) {
        let localIP = "192.168.1.\(Int.random(in: 101...150))"
        let r = Int.random(in: 0..<11)
        switch r {
        case 0:
            // HTTP Request to Cloudflare / Enterprise Web Server
            let cloudflareIP = "104.21.48.91"
            let payload = "GET /api/v1/status HTTP/1.1\r\nHost: api.cloudflare.com\r\nUser-Agent: SharkMobile/1.0 (iPhone; iOS 18)\r\nAccept: application/json\r\n\r\n".data(using: .utf8)!
            return (createIPv4TCPPacket(srcIP: localIP, dstIP: cloudflareIP, srcPort: 51200 + Int.random(in: 1...1000), dstPort: 80, flags: 0x18, payload: payload), "en0 (Wi-Fi)")
        case 1:
            // TLS Client Hello with SNI to Cloudflare
            return (createTLSClientHelloPacket(srcIP: localIP, dstIP: "1.1.1.1", sni: "cloudflare.com"), "en0 (Wi-Fi)")
        case 2:
            // TLS Client Hello with SNI to Apple iCloud Gateway
            return (createTLSClientHelloPacket(srcIP: localIP, dstIP: "17.253.144.10", sni: "gateway.icloud.com"), "en0 (Wi-Fi)")
        case 3:
            // DNS Query to Cloudflare / Google DNS
            let domains = ["apple.com", "gateway.icloud.com", "cloudflare.com", "google.com", "github.com", "openai.com", "aws.amazon.com", "api.telegram.org"]
            let d = domains[Int.random(in: 0..<domains.count)]
            let dnsServer = Bool.random() ? "1.1.1.1" : "8.8.8.8"
            return (createIPv4UDPPacket(srcIP: localIP, dstIP: dnsServer, srcPort: 54321 + Int.random(in: 1...100), dstPort: 53, domain: d), "en0 (Wi-Fi)")
        case 4:
            // QUIC / HTTP3 UDP Transport to Google Cloud
            let quicPayload = Data([0xC0, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            return (createIPv4UDPPacketWithPayload(srcIP: localIP, dstIP: "142.250.190.46", srcPort: 58210, dstPort: 443, payload: quicPayload), "en0 (Wi-Fi)")
        case 5:
            // Bluetooth Low Energy (AirPods Proximity Pairing Advertisement)
            return (createBleFrame(mfgData: Data([0x4C, 0x00, 0x07, 0x19, 0x01, 0x02, 0x20])), "ble0 (BLE Radio)")
        case 6:
            // Bluetooth Low Energy (AirTag / FindMy Tracker Beacon)
            return (createBleFrame(mfgData: Data([0x4C, 0x00, 0x12, 0x19, 0x10, 0xAA, 0xBB])), "ble0 (BLE Radio)")
        case 7:
            // ARP Request on LAN Gateway
            return (createARPPacket(senderIP: "192.168.1.1", targetIP: localIP), "en0 (Wi-Fi)")
        case 8:
            // SSDP Multicast (UPnP Device Discovery)
            let ssdpPayload = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n".data(using: .utf8)!
            return (createIPv4UDPPacketWithPayload(srcIP: localIP, dstIP: "239.255.255.250", srcPort: 49200, dstPort: 1900, payload: ssdpPayload), "en0 (Wi-Fi)")
        case 9:
            // Loopback IPC Traffic (Local daemon / agent communications)
            return (createIPv4TCPPacket(srcIP: "127.0.0.1", dstIP: "127.0.0.1", srcPort: 8990, dstPort: 58012, flags: 0x18, payload: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"service\":\"sharkmobile-agent\"}".data(using: .utf8)!), "lo0 (Loopback)")
        default:
            // Cellular PDP traffic to Apple Push Notification Service (APNs) / CloudFront
            let cellularIP = "10.142.\(Int.random(in: 10...90)).\(Int.random(in: 1...254))"
            return (createIPv4TCPPacket(srcIP: cellularIP, dstIP: "17.253.144.10", srcPort: 59124, dstPort: 443, flags: 0x10, payload: Data(repeating: 0x17, count: 64)), "pdp_ip0 (Cellular)")
        }
    }

    private func createBleFrame(mfgData: Data) -> Data {
        var d = Data([0x42, 0x4C, 0x45]) // Magic "BLE"
        d.append(UInt8(bitPattern: Int8(-55))) // RSSI
        d.append(mfgData)
        return d
    }

    private func createARPPacket(senderIP: String, targetIP: String) -> Data {
        var d = Data(repeating: 0, count: 14)
        d[12] = 0x08; d[13] = 0x06 // ARP
        var arp = Data([
            0x00, 0x01, // HW Ethernet
            0x08, 0x00, // Proto IPv4
            0x06, 0x04, // HW Size 6, Proto Size 4
            0x00, 0x01  // Request
        ])
        arp.append(contentsOf: [0x6C, 0x03, 0xB5, 0x64, 0x39, 0x5E]) // Cisco MAC
        arp.append(contentsOf: parseIPv4Bytes(senderIP))
        arp.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // Target MAC
        arp.append(contentsOf: parseIPv4Bytes(targetIP))
        d.append(arp)
        return d
    }

    private func createIPv4TCPPacket(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, flags: UInt8, payload: Data) -> Data {
        var d = Data(repeating: 0, count: 14)
        d[12] = 0x08; d[13] = 0x00
        var ip = Data([0x45, 0x00, 0x00, 0x00, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00])
        ip.append(contentsOf: parseIPv4Bytes(srcIP))
        ip.append(contentsOf: parseIPv4Bytes(dstIP))

        var tcp = Data([
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x20, 0x02,
            0x50, flags, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00
        ])
        tcp.append(payload)

        let totalLen = UInt16(ip.count + tcp.count)
        ip[2] = UInt8(totalLen >> 8); ip[3] = UInt8(totalLen & 0xFF)
        d.append(ip)
        d.append(tcp)
        return d
    }

    private func createIPv4UDPPacket(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, domain: String) -> Data {
        var dns = Data([0xA1, 0xB2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for part in domain.components(separatedBy: ".") {
            dns.append(UInt8(part.count))
            dns.append(part.data(using: .utf8)!)
        }
        dns.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return createIPv4UDPPacketWithPayload(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: dns)
    }

    private func createIPv4UDPPacketWithPayload(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, payload: Data) -> Data {
        var d = Data(repeating: 0, count: 14)
        d[12] = 0x08; d[13] = 0x00
        var ip = Data([0x45, 0x00, 0x00, 0x00, 0x56, 0x78, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00])
        ip.append(contentsOf: parseIPv4Bytes(srcIP))
        ip.append(contentsOf: parseIPv4Bytes(dstIP))

        let udpLen = UInt16(8 + payload.count)
        var udp = Data([
            UInt8(srcPort >> 8), UInt8(srcPort & 0xFF),
            UInt8(dstPort >> 8), UInt8(dstPort & 0xFF),
            UInt8(udpLen >> 8), UInt8(udpLen & 0xFF),
            0x00, 0x00
        ])
        udp.append(payload)

        let totalLen = UInt16(ip.count + udp.count)
        ip[2] = UInt8(totalLen >> 8); ip[3] = UInt8(totalLen & 0xFF)
        d.append(ip)
        d.append(udp)
        return d
    }

    private func createTLSClientHelloPacket(srcIP: String, dstIP: String, sni: String) -> Data {
        var tlsPayload = Data([0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03])
        tlsPayload.append(contentsOf: Data(repeating: 0x42, count: 32))
        tlsPayload.append(0x00)
        tlsPayload.append(contentsOf: [0x00, 0x02, 0x13, 0x01, 0x01, 0x00])

        let sniBytes = sni.data(using: .utf8)!
        var extSni = Data([0x00, 0x00, 0x00, UInt8(sniBytes.count + 5), 0x00, UInt8(sniBytes.count + 3), 0x00, 0x00, UInt8(sniBytes.count)])
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
