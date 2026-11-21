import Foundation

#if canImport(UIKit)
import UIKit
#endif

@MainActor
public final class CaptureEngine: ObservableObject {
    @Published public var packets: [PacketRecord] = []
    @Published public var isCapturing: Bool = false
    @Published public var capturedCount: Int = 0
    @Published public var droppedCount: Int = 0
    @Published public var memoryUsageMB: Double = 0.0
    @Published public var selectedInterface: String = "All Interfaces"
    @Published public var maxMemoryMB: Double = 100.0 // Configurable up to 500MB
    @Published public var threats: [ThreatEvent] = []
    @Published public var securityFindings: [SecurityFinding] = []
    @Published public var discoveredAssets: [DiscoveredHost] = []
    @Published public var captureMode: CaptureSourceMode = .liveHardware
    @Published public var demoModeEnabled: Bool = false
    @Published public var bpfStatusDescription: String = "Standby"
    public let realCapturePipeline = RealCapturePipeline()

    public var captureSourceMode: CaptureSourceMode {
        get { captureMode }
        set { captureMode = newValue }
    }

    // Tactical Systems Sub-Engines
    public let threatDetector = ThreatDetector()
    public let assetTopology = AssetTopology()
    public let missionManager = TacticalMissionManager()
    public let gpsManager = GPSManager()
    public let biometricGuard = BiometricGuard()

    public let maxPacketCapacity = 10_000
    private var currentTotalRawBytes: Int = 0
    private var timer: Timer?
    private var packetCounter = 1
    private var scanPortCounter = 20

    public init() {
        realCapturePipeline.packetHandler = { [weak self] rawData, iface in
            DispatchQueue.main.async {
                self?.ingestPacket(rawData: rawData, interface: iface)
            }
        }
        #if canImport(UIKit)
        NotificationCenter.default.addObserver(
            forName: UIApplication.didReceiveMemoryWarningNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.handleMemoryWarning()
        }
        #endif
    }

    private func handleMemoryWarning() {
        // High Jetsam Pressure: Prune 50% oldest packets immediately to prevent termination
        let pruneCount = packets.count / 2
        guard pruneCount > 0 else { return }
        for i in 0..<pruneCount {
            currentTotalRawBytes -= packets[i].rawData.count
        }
        packets.removeFirst(pruneCount)
        droppedCount += pruneCount
        currentTotalRawBytes = max(0, currentTotalRawBytes)
        self.memoryUsageMB = Double(currentTotalRawBytes) / (1024.0 * 1024.0)
        missionManager.log(severity: "WARN", tag: "JETSAM", message: "iOS Memory Pressure: Pruned \(pruneCount) packets to protect process.")
    }

    public func startCapture() {
        guard !isCapturing else { return }
        isCapturing = true
        gpsManager.startLocationServices()
        missionManager.log(severity: "START", tag: "CAPTURE", message: "Live promiscuous capture activated [\(captureMode.rawValue)] on \(selectedInterface)")

        if demoModeEnabled || captureMode == .demoSimulated {
            missionManager.log(severity: "START", tag: "SIMULATION", message: "Demo simulated packet generator activated on \(selectedInterface)")
            timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
                guard let strongSelf = self else { return }
                DispatchQueue.main.async {
                    strongSelf.simulatePacketArrival()
                }
            }
        } else {
            realCapturePipeline.packetHandler = { [weak self] rawData, iface in
                guard let strongSelf = self else { return }
                DispatchQueue.main.async {
                    strongSelf.ingestPacket(rawData: rawData, interface: iface)
                }
            }
            realCapturePipeline.start(interface: selectedInterface, mode: captureMode)
            self.bpfStatusDescription = realCapturePipeline.bpfStatus.rawValue
            if realCapturePipeline.bpfStatus == .bpfDenied {
                missionManager.log(severity: "WARN", tag: "BPF", message: "BPF kernel tap restricted (Jailed iOS / Sandbox). Live hardware capture running via Local Socket Tap & BLE Airspace.")
            } else {
                missionManager.log(severity: "START", tag: "BPF", message: "BPF Hardware Tap active [Status: \(realCapturePipeline.bpfStatus.rawValue)]")
            }
        }
    }

    public func stopCapture() {
        isCapturing = false
        timer?.invalidate()
        timer = nil
        realCapturePipeline.stop()
        gpsManager.stopLocationServices()
        self.bpfStatusDescription = "Halted"
        missionManager.log(severity: "STOP", tag: "CAPTURE", message: "Capture halted. Total: \(capturedCount) packets")
    }

    public func clear() {
        packets.removeAll()
        capturedCount = 0
        droppedCount = 0
        currentTotalRawBytes = 0
        memoryUsageMB = 0.0
        packetCounter = 1
        threatDetector.clear()
        threats.removeAll()
        securityFindings.removeAll()
        assetTopology.clear()
        discoveredAssets.removeAll()
        missionManager.log(severity: "CLEAR", tag: "SYS", message: "In-memory packet buffer and forensic state purged")
    }

    public func importPcap(data: Data) {
        let parsed = PcapManager.readAny(data: data)
        self.packets = parsed
        self.capturedCount = parsed.count
        self.packetCounter = parsed.count + 1
        self.currentTotalRawBytes = parsed.reduce(0) { $0 + $1.rawData.count }
        self.memoryUsageMB = Double(self.currentTotalRawBytes) / (1024.0 * 1024.0)

        for pkt in parsed {
            let t = threatDetector.analyze(packet: pkt)
            if !t.isEmpty { threats.append(contentsOf: t) }
            let f = SecurityHunter.inspect(packet: pkt)
            if !f.isEmpty { securityFindings.append(contentsOf: f) }
            assetTopology.process(packet: pkt)
        }
        discoveredAssets = assetTopology.assets
        let cert = missionManager.certifyEvidence(fileName: "imported_capture.pcap", data: data, packetCount: parsed.count)
        missionManager.log(severity: "IMPORT", tag: "VAULT", message: "Imported \(parsed.count) packets. SHA-256: \(cert.sha256Hash.prefix(12))...")
    }

    public func exportPcap() -> Data {
        let data = PcapManager.writePcap(packets: packets)
        _ = missionManager.certifyEvidence(fileName: "export_\(missionManager.caseCodename).pcap", data: data, packetCount: packets.count)
        return data
    }

    public func exportPcapNg() -> Data {
        let data = PcapManager.writePcapNg(packets: packets)
        _ = missionManager.certifyEvidence(fileName: "export_\(missionManager.caseCodename).pcapng", data: data, packetCount: packets.count)
        return data
    }

    public func exportJsonForensics() -> Data {
        return PcapManager.exportJsonDump(packets: packets)
    }

    public func simulatePacketArrival() {
        let (raw, iface) = generateDiversePacket()
        ingestPacket(rawData: raw, interface: iface)
    }

    public func ingestPacket(rawData: Data, interface: String) {
        // Filter by interface if not "All Interfaces"
        if selectedInterface != "All Interfaces" && !interface.contains(selectedInterface.prefix(3)) {
            return
        }

        let now = Date().timeIntervalSince1970
        let loc = gpsManager.stampPacketLocation()
        let recordRaw = PacketDissector.dissect(packetId: packetCounter, timestamp: now, rawData: rawData, interface: interface)
        let record = PacketRecord(
            id: recordRaw.id,
            timestamp: recordRaw.timestamp,
            source: recordRaw.source,
            destination: recordRaw.destination,
            protocolType: recordRaw.protocolType,
            length: recordRaw.length,
            info: recordRaw.info,
            rawData: recordRaw.rawData,
            layers: recordRaw.layers,
            interface: recordRaw.interface,
            expertInfo: recordRaw.expertInfo,
            geoCoord: loc,
            countryFlag: recordRaw.countryFlag,
            countryName: recordRaw.countryName,
            asnInfo: recordRaw.asnInfo
        )
        packetCounter += 1

        packets.append(record)
        capturedCount += 1
        currentTotalRawBytes += record.rawData.count
        self.memoryUsageMB = Double(currentTotalRawBytes) / (1024.0 * 1024.0)

        // Real-time threat & security intelligence
        let newThreats = threatDetector.analyze(packet: record)
        if !newThreats.isEmpty {
            threats.append(contentsOf: newThreats)
            if threats.count > 500 {
                threats.removeFirst(threats.count - 500)
            }
            for t in newThreats {
                missionManager.log(severity: t.severity.rawValue, tag: "THREAT", message: "[\(t.type.rawValue)] \(t.title) (\(t.attackerIP))", packetId: record.id)
            }
        }

        let newFindings = SecurityHunter.inspect(packet: record)
        if !newFindings.isEmpty {
            securityFindings.append(contentsOf: newFindings)
            if securityFindings.count > 500 {
                securityFindings.removeFirst(securityFindings.count - 500)
            }
            for f in newFindings {
                missionManager.log(severity: f.severity.rawValue, tag: "HUNTER", message: "[\(f.category.rawValue)] \(f.title): \(f.secretPreview)", packetId: record.id)
            }
        }

        assetTopology.process(packet: record)
        discoveredAssets = assetTopology.assets

        // Periodically certify live evidence
        if capturedCount > 0 && capturedCount % 50 == 0 {
            let pcapData = PcapManager.writePcap(packets: packets)
            _ = missionManager.certifyEvidence(fileName: "live_checkpoint_\(capturedCount).pcap", data: pcapData, packetCount: packets.count)
        }

        // FIFO buffer bound enforcement
        if packets.count > maxPacketCapacity {
            let overflow = packets.count - maxPacketCapacity
            for i in 0..<overflow {
                currentTotalRawBytes -= packets[i].rawData.count
            }
            packets.removeFirst(overflow)
            droppedCount += overflow
            currentTotalRawBytes = max(0, currentTotalRawBytes)
            self.memoryUsageMB = Double(currentTotalRawBytes) / (1024.0 * 1024.0)
        }

        // Evict oldest only if exceeding user-configured memory threshold
        while memoryUsageMB > maxMemoryMB && !packets.isEmpty {
            let evictBatch = min(50, packets.count)
            for i in 0..<evictBatch {
                currentTotalRawBytes -= packets[i].rawData.count
            }
            packets.removeFirst(evictBatch)
            droppedCount += evictBatch
            currentTotalRawBytes = max(0, currentTotalRawBytes)
            self.memoryUsageMB = Double(currentTotalRawBytes) / (1024.0 * 1024.0)
        }
    }

    public func stepSimulation(count: Int = 1) {
        for _ in 0..<count {
            simulatePacketArrival()
        }
    }

    private func updateMemoryMetrics() {
        self.memoryUsageMB = Double(max(0, currentTotalRawBytes)) / (1024.0 * 1024.0)
    }

    private var packetCycleIndex: Int = 0

    private func generateDiversePacket() -> (Data, String) {
        let cycle = packetCycleIndex
        packetCycleIndex += 1
        let r = cycle % 16
        let localIP = "192.168.1.\(101 + (cycle % 20))"

        switch r {
        case 0:
            // HTTP Request to Cloudflare (with Apple MAC)
            let cloudflareIP = "104.21.48.91"
            let payload = Data("GET /api/v1/status HTTP/1.1\r\nHost: api.cloudflare.com\r\nUser-Agent: SharkMobile/2.0 (iPhone; iOS 18)\r\nAccept: application/json\r\n\r\n".utf8)
            return (createIPv4TCPPacket(srcIP: localIP, dstIP: cloudflareIP, srcPort: 51200 + (cycle % 1000), dstPort: 80, flags: 0x18, payload: payload, srcMAC: [0xAC, 0xDE, 0x48, 0x11, 0x22, 0x33]), "en0 (Wi-Fi)")
        case 1:
            // TLS Client Hello to Cloudflare
            return (createTLSClientHelloPacket(srcIP: localIP, dstIP: "1.1.1.1", sni: "cloudflare.com"), "en0 (Wi-Fi)")
        case 2:
            // TLS Client Hello to Apple iCloud Gateway
            return (createTLSClientHelloPacket(srcIP: localIP, dstIP: "17.253.144.10", sni: "gateway.icloud.com"), "en0 (Wi-Fi)")
        case 3:
            // DNS Query to Google DNS / Cloudflare
            let domains = ["apple.com", "gateway.icloud.com", "cloudflare.com", "google.com", "github.com", "openai.com", "aws.amazon.com"]
            let d = domains[cycle % domains.count]
            let dnsServer = (cycle % 2 == 0) ? "1.1.1.1" : "8.8.8.8"
            return (createIPv4UDPPacket(srcIP: localIP, dstIP: dnsServer, srcPort: 54321 + (cycle % 100), dstPort: 53, domain: d), "en0 (Wi-Fi)")
        case 4:
            // QUIC / HTTP3 Handshake to Google Cloud
            let quicPayload = Data([0xC0, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            return (createIPv4UDPPacketWithPayload(srcIP: localIP, dstIP: "142.250.190.46", srcPort: 58210, dstPort: 443, payload: quicPayload), "en0 (Wi-Fi)")
        case 5:
            // Bluetooth Low Energy (AirPods Proximity Pairing)
            return (createBleFrame(mfgData: Data([0x4C, 0x00, 0x07, 0x19, 0x01, 0x02, 0x20])), "ble0 (BLE Radio)")
        case 6:
            // Bluetooth Low Energy (AirTag / FindMy Tracker Beacon)
            return (createBleFrame(mfgData: Data([0x4C, 0x00, 0x12, 0x19, 0x10, 0xAA, 0xBB])), "ble0 (BLE Radio)")
        case 7:
            // ARP Request on LAN Gateway
            if cycle > 20 {
                // Simulated ARP Poisoning / Spoofing attack from rogue host
                return (createARPPacket(senderIP: "192.168.1.1", targetIP: localIP, senderMAC: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], isReply: true), "en0 (Wi-Fi)")
            } else {
                return (createARPPacket(senderIP: "192.168.1.1", targetIP: localIP, senderMAC: [0x6C, 0x03, 0xB5, 0x64, 0x39, 0x5E], isReply: false), "en0 (Wi-Fi)")
            }
        case 8:
            // SSDP Multicast (UPnP Discovery)
            let ssdpPayload = Data("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n".utf8)
            return (createIPv4UDPPacketWithPayload(srcIP: localIP, dstIP: "239.255.255.250", srcPort: 49200, dstPort: 1900, payload: ssdpPayload), "en0 (Wi-Fi)")
        case 9:
            // Loopback IPC Traffic
            return (createIPv4TCPPacket(srcIP: "127.0.0.1", dstIP: "127.0.0.1", srcPort: 8990, dstPort: 58012, flags: 0x18, payload: Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"service\":\"sharkmobile-agent\"}".utf8)), "lo0 (Loopback)")
        case 10:
            // Security Hunter Pillar: Cleartext Basic Auth in POST Body
            let leakPayload = Data("POST /v1/auth/login HTTP/1.1\r\nHost: internal-auth.lan\r\nAuthorization: Basic YWRtaW46U3VwZXJTZWNyZXRQYXNzIQ==\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=P@ssw0rd2026!&authToken=sample_test_auth_token".utf8)
            return (createIPv4TCPPacket(srcIP: localIP, dstIP: "192.168.1.50", srcPort: 53100, dstPort: 80, flags: 0x18, payload: leakPayload, srcMAC: [0x70, 0xEE, 0x50, 0x11, 0x22, 0x33]), "en0 (Wi-Fi)")
        case 11:
            // Security Hunter Pillar: Exposed Cloud Keys & JWT Token
            let tokenPayload = Data("POST /api/v2/deploy HTTP/1.1\r\nHost: api.cloudinfra.internal\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\nContent-Type: application/json\r\n\r\n{\"aws_access_key\":\"MOCK_AWS_ACCESS_KEY_SAMPLE\",\"stripe_secret\":\"sec_sample_token_4eC39HqLyjWDarjtT1zdp7dc\"}".utf8)
            return (createIPv4TCPPacket(srcIP: localIP, dstIP: "104.21.48.91", srcPort: 54200, dstPort: 80, flags: 0x18, payload: tokenPayload, srcMAC: [0xB8, 0x27, 0xEB, 0x12, 0x34, 0x56]), "en0 (Wi-Fi)")
        case 12:
            // Deep L7 Dissector Pillar: WebSocket Text Frame
            let wsPayload = createWebSocketTextFrame(text: "{\"event\":\"telemetry\",\"coords\":{\"lat\":37.7749,\"lon\":-122.4194},\"status\":\"locked\"}")
            return (createIPv4TCPPacket(srcIP: localIP, dstIP: "104.21.48.91", srcPort: 59300, dstPort: 8080, flags: 0x18, payload: wsPayload), "en0 (Wi-Fi)")
        case 13:
            // Deep L7 Dissector Pillar: mDNS / Bonjour Apple TV Announcement
            let mdnsPayload = createMDNSPacket(service: "_airplay._tcp.local")
            return (createIPv4UDPPacketWithPayload(srcIP: "192.168.1.180", dstIP: "224.0.0.251", srcPort: 5353, dstPort: 5353, payload: mdnsPayload, srcMAC: [0x70, 0xEE, 0x50, 0xAA, 0xBB, 0xCC]), "en0 (Wi-Fi)")
        case 14:
            // Deep L7 Dissector Pillar: DHCPv4 ACK Lease
            if cycle > 25 {
                let rogueDhcp = createDHCPPacket(msgType: 5, clientIP: localIP, serverIP: "192.168.1.99")
                return (createIPv4UDPPacketWithPayload(srcIP: "192.168.1.99", dstIP: localIP, srcPort: 67, dstPort: 68, payload: rogueDhcp, srcMAC: [0xB8, 0x27, 0xEB, 0x99, 0x88, 0x77]), "en0 (Wi-Fi)")
            } else {
                let dhcpAck = createDHCPPacket(msgType: 5, clientIP: localIP, serverIP: "192.168.1.1")
                return (createIPv4UDPPacketWithPayload(srcIP: "192.168.1.1", dstIP: localIP, srcPort: 67, dstPort: 68, payload: dhcpAck, srcMAC: [0x6C, 0x03, 0xB5, 0x64, 0x39, 0x5E]), "en0 (Wi-Fi)")
            }
        default:
            // Threat Detection Engine: Port Scan Probe
            let scanPort = scanPortCounter
            scanPortCounter = scanPortCounter >= 85 ? 20 : scanPortCounter + 1
            return (createIPv4TCPPacket(srcIP: "198.51.100.42", dstIP: localIP, srcPort: 48991, dstPort: scanPort, flags: 0x02, payload: Data()), "en0 (Wi-Fi)")
        }
    }

    private func createBleFrame(mfgData: Data) -> Data {
        var d = Data([0x42, 0x4C, 0x45]) // Magic "BLE"
        d.append(UInt8(bitPattern: Int8(-55))) // RSSI
        d.append(mfgData)
        return d
    }

    private func createARPPacket(senderIP: String, targetIP: String, senderMAC: [UInt8] = [0x6C, 0x03, 0xB5, 0x64, 0x39, 0x5E], isReply: Bool = false) -> Data {
        var d = Data(repeating: 0, count: 14)
        d[0] = 0xFF; d[1] = 0xFF; d[2] = 0xFF; d[3] = 0xFF; d[4] = 0xFF; d[5] = 0xFF
        d[6] = senderMAC[0]; d[7] = senderMAC[1]; d[8] = senderMAC[2]; d[9] = senderMAC[3]; d[10] = senderMAC[4]; d[11] = senderMAC[5]
        d[12] = 0x08; d[13] = 0x06 // ARP
        var arp = Data([
            0x00, 0x01, // HW Ethernet
            0x08, 0x00, // Proto IPv4
            0x06, 0x04, // HW Size 6, Proto Size 4
            0x00, isReply ? 0x02 : 0x01
        ])
        arp.append(contentsOf: senderMAC)
        arp.append(contentsOf: parseIPv4Bytes(senderIP))
        arp.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        arp.append(contentsOf: parseIPv4Bytes(targetIP))
        d.append(arp)
        return d
    }

    private func createIPv4TCPPacket(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, flags: UInt8, payload: Data, srcMAC: [UInt8]? = nil) -> Data {
        var d = Data(repeating: 0, count: 14)
        if let mac = srcMAC, mac.count == 6 {
            d[6] = mac[0]; d[7] = mac[1]; d[8] = mac[2]; d[9] = mac[3]; d[10] = mac[4]; d[11] = mac[5]
        } else {
            d[6] = 0xAC; d[7] = 0xDE; d[8] = 0x48; d[9] = 0x12; d[10] = 0x34; d[11] = 0x56 // Apple OUI
        }
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
            let partData = Data(part.utf8)
            dns.append(UInt8(min(partData.count, 63)))
            dns.append(partData)
        }
        dns.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return createIPv4UDPPacketWithPayload(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, payload: dns)
    }

    private func createIPv4UDPPacketWithPayload(srcIP: String, dstIP: String, srcPort: Int, dstPort: Int, payload: Data, srcMAC: [UInt8]? = nil) -> Data {
        var d = Data(repeating: 0, count: 14)
        if let mac = srcMAC, mac.count == 6 {
            d[6] = mac[0]; d[7] = mac[1]; d[8] = mac[2]; d[9] = mac[3]; d[10] = mac[4]; d[11] = mac[5]
        } else {
            d[6] = 0x6C; d[7] = 0x03; d[8] = 0xB5; d[9] = 0x64; d[10] = 0x39; d[11] = 0x5E // Cisco OUI
        }
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

        let sniBytes = Data(sni.utf8)
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

    private func createWebSocketTextFrame(text: String) -> Data {
        let textBytes = [UInt8](text.utf8)
        var frame = Data([0x81]) // FIN=1, Opcode=1 (Text)
        let maskKey: [UInt8] = [0x12, 0x34, 0x56, 0x78]

        if textBytes.count <= 125 {
            frame.append(0x80 | UInt8(textBytes.count)) // Mask=1
        } else {
            frame.append(contentsOf: [UInt8(0x80 | 126), UInt8(textBytes.count >> 8), UInt8(textBytes.count & 0xFF)])
        }
        frame.append(contentsOf: maskKey)

        var masked = textBytes
        for i in 0..<masked.count {
            masked[i] ^= maskKey[i % 4]
        }
        frame.append(contentsOf: masked)
        return frame
    }

    private func createMDNSPacket(service: String) -> Data {
        var d = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for part in service.components(separatedBy: ".") {
            let partData = Data(part.utf8)
            d.append(UInt8(min(partData.count, 63)))
            d.append(partData)
        }
        d.append(contentsOf: [0x00, 0x00, 0x0C, 0x00, 0x01]) // PTR IN
        return d
    }

    private func createDHCPPacket(msgType: UInt8, clientIP: String, serverIP: String) -> Data {
        var d = Data(repeating: 0, count: 240)
        d[0] = 0x02 // BootReply
        d[1] = 0x01 // Ethernet
        d[2] = 0x06 // Len 6
        d[4] = 0x39; d[5] = 0x03; d[6] = 0xF3; d[7] = 0x26 // xid
        let clientBytes = parseIPv4Bytes(clientIP)
        if clientBytes.count == 4 {
            d[16] = clientBytes[0]; d[17] = clientBytes[1]; d[18] = clientBytes[2]; d[19] = clientBytes[3]
        }
        let srvBytes = parseIPv4Bytes(serverIP)
        if srvBytes.count == 4 {
            d[20] = srvBytes[0]; d[21] = srvBytes[1]; d[22] = srvBytes[2]; d[23] = srvBytes[3]
        }
        // Magic cookie 0x63 0x82 0x53 0x63 at byte 236
        d[236] = 0x63; d[237] = 0x82; d[238] = 0x53; d[239] = 0x63

        // Options:
        // Opt 53 (Msg Type)
        d.append(contentsOf: [53, 1, msgType])
        // Opt 1 (Subnet mask)
        d.append(contentsOf: [1, 4, 255, 255, 255, 0])
        // Opt 3 (Router)
        d.append(contentsOf: [3, 4, 192, 168, 1, 1])
        // Opt 6 (DNS)
        d.append(contentsOf: [6, 4, 1, 1, 1, 1])
        // Opt 12 (Host name)
        let nameBytes = Data("Tactical-iPhone-Field".utf8)
        d.append(contentsOf: [12, UInt8(nameBytes.count)])
        d.append(nameBytes)
        // Opt 51 (Lease 86400s)
        d.append(contentsOf: [51, 4, 0x00, 0x01, 0x51, 0x80])
        // Opt 255 (End)
        d.append(255)
        return d
    }

    private func parseIPv4Bytes(_ ipStr: String) -> [UInt8] {
        return ipStr.components(separatedBy: ".").compactMap { UInt8($0) }
    }
}
