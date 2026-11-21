import Foundation
import Darwin
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

// MARK: - Capture Source Mode
public enum CaptureSourceMode: String, CaseIterable, Identifiable {
    case liveHardware = "Live Multi-Source Hardware"
    case bpfRaw = "BPF Raw Kernel (/dev/bpf)"
    case localSocketTap = "Local Socket Tap (mDNS/SSDP)"
    case bleAirspace = "BLE Airspace Radio (ble0)"
    case demoSimulated = "Synthetic Protocol Simulator"

    public var id: String { rawValue }
}

// MARK: - 1. Native Darwin Berkeley Packet Filter (BPF) Engine
public final class BpfPacketCapture {
    public enum BpfStatus: String {
        case idle = "Standby (Idle)"
        case capturing = "Active (Promiscuous Tap)"
        case bpfDenied = "Permission Denied (Jailed iOS / Sandbox)"
        case deviceNotFound = "Device Not Found (/dev/bpf* Unavailable)"
        case interfaceError = "Interface Configuration Failed"
        case error = "BPF Error"
    }

    // IOCTL Darwin Constants
    public static let BIOCSETIF: UInt = 0x8020426c    // _IOW('B', 108, struct ifreq)
    public static let BIOCPROMISC: UInt = 0x20004269  // _IO('B', 105)
    public static let BIOCIMMEDIATE: UInt = 0x80044270// _IOW('B', 112, u_int)
    public static let BIOCGBLEN: UInt = 0x40044266    // _IOR('B', 102, u_int)

    public private(set) var status: BpfStatus = .idle
    public private(set) var isRunning: Bool = false
    public private(set) var boundDevicePath: String? = nil
    public private(set) var boundInterface: String? = nil
    public private(set) var bufferLength: UInt32 = 0

    public var packetHandler: ((Data, String) -> Void)?

    private var bpfFd: Int32 = -1
    private let readQueue = DispatchQueue(label: "com.sharkmobile.bpf.read", qos: .userInitiated)

    public init() {}

    deinit {
        stop()
    }

    @discardableResult
    public func start(interface: String = "en0") -> Bool {
        guard !isRunning else { return true }

        let cleanIface = resolveInterfaceName(interface)
        self.boundInterface = cleanIface

        // Step 1: Probe /dev/bpf0 ... /dev/bpf255
        var openedFd: Int32 = -1
        var selectedPath = ""
        var encounteredPermissionDenied = false

        for i in 0...255 {
            let path = "/dev/bpf\(i)"
            let fd = open(path, O_RDWR)
            if fd >= 0 {
                openedFd = fd
                selectedPath = path
                break
            } else {
                let err = errno
                if err == EACCES || err == EPERM {
                    encounteredPermissionDenied = true
                }
                // Try Read-Only fallback
                let roFd = open(path, O_RDONLY)
                if roFd >= 0 {
                    openedFd = roFd
                    selectedPath = path
                    break
                }
            }
        }

        guard openedFd >= 0 else {
            if encounteredPermissionDenied {
                self.status = .bpfDenied
            } else {
                self.status = .deviceNotFound
            }
            return false
        }

        self.bpfFd = openedFd
        self.boundDevicePath = selectedPath

        // Step 2: Bind to target interface via BIOCSETIF (0x8020426c)
        var ifr = [CChar](repeating: 0, count: 64)
        _ = cleanIface.withCString { strncpy(&ifr, $0, 15) }
        let setifRes = ioctl(bpfFd, BpfPacketCapture.BIOCSETIF, &ifr)
        if setifRes < 0 {
            close(bpfFd)
            self.bpfFd = -1
            self.status = .interfaceError
            return false
        }

        // Step 3: Enable Promiscuous Mode via BIOCPROMISC (0x20004269)
        _ = ioctl(bpfFd, BpfPacketCapture.BIOCPROMISC)

        // Step 4: Enable Immediate Mode via BIOCIMMEDIATE (0x80044270)
        var immediate: UInt32 = 1
        _ = ioctl(bpfFd, BpfPacketCapture.BIOCIMMEDIATE, &immediate)

        // Step 5: Query Buffer Length via BIOCGBLEN (0x40044266)
        var bufLen: UInt32 = 0
        if ioctl(bpfFd, BpfPacketCapture.BIOCGBLEN, &bufLen) < 0 || bufLen == 0 {
            bufLen = 32768
        }
        self.bufferLength = bufLen
        self.status = .capturing
        self.isRunning = true

        // Step 6: Spawn continuous background BPF reader
        readQueue.async { [weak self, bpfFd, bufLen, cleanIface] in
            guard let self = self else { return }
            var localBuffer = [UInt8](repeating: 0, count: Int(bufLen))

            while self.isRunning {
                let bytesRead = read(bpfFd, &localBuffer, Int(bufLen))
                if bytesRead > 0 {
                    self.parseBpfBuffer(bytes: localBuffer, count: bytesRead, interface: cleanIface)
                } else if bytesRead < 0 {
                    let err = errno
                    if err == EINTR || err == EAGAIN {
                        continue
                    }
                    break
                } else {
                    usleep(5_000)
                }
            }
        }

        return true
    }

    public func stop() {
        isRunning = false
        packetHandler = nil
        if bpfFd >= 0 {
            close(bpfFd)
            bpfFd = -1
        }
        boundDevicePath = nil
        boundInterface = nil
        status = .idle
    }

    /// Parses Darwin 64-bit bpf_hdr records:
    /// - bh_tstamp: 8 bytes (timeval32)
    /// - bh_caplen: 4 bytes at offset 8
    /// - bh_datalen: 4 bytes at offset 12
    /// - bh_hdrlen: 2 bytes at offset 16
    /// - Total header length: 18-20 bytes, aligned to BPF_WORDALIGN (4 bytes)
    private func parseBpfBuffer(bytes: [UInt8], count: Int, interface: String) {
        var offset = 0
        while offset + 18 <= count {
            let caplen = Int(bytes[offset + 8]) |
                         (Int(bytes[offset + 9]) << 8) |
                         (Int(bytes[offset + 10]) << 16) |
                         (Int(bytes[offset + 11]) << 24)
            let hdrlen = Int(bytes[offset + 16]) |
                         (Int(bytes[offset + 17]) << 8)

            guard hdrlen > 0, caplen > 0, offset + hdrlen + caplen <= count else {
                break
            }

            let packetBytes = bytes[(offset + hdrlen)..<(offset + hdrlen + caplen)]
            let rawData = Data(packetBytes)

            self.packetHandler?(rawData, "\(interface) (BPF)")

            // BPF_WORDALIGN: round up to next 4-byte boundary
            let aligned = ((hdrlen + caplen + 3) & ~3)
            guard aligned > 0 else { break }
            offset += aligned
        }
    }

    private func resolveInterfaceName(_ raw: String) -> String {
        let lower = raw.lowercased()
        if lower.contains("lo") {
            return "lo0"
        } else if lower.contains("pdp_ip") {
            return "pdp_ip0"
        } else if lower.contains("en1") {
            return "en1"
        } else if lower.contains("utun") {
            return "utun0"
        } else {
            return "en0"
        }
    }
}

// MARK: - 2. Bluetooth Low Energy (BLE) Airspace Hardware Capture
public final class BleAirspaceCapture: NSObject, @unchecked Sendable {
    public var packetHandler: ((Data, String) -> Void)?
    public private(set) var isScanning: Bool = false
    public private(set) var discoveredBleCount: Int = 0

    #if canImport(CoreBluetooth)
    private var centralManager: CBCentralManager?
    private var centralDelegateWrapper: BleDelegateBridge?
    #endif

    public override init() {
        super.init()
    }

    public func start() {
        guard !isScanning else { return }
        isScanning = true

        #if canImport(CoreBluetooth)
        if centralDelegateWrapper == nil {
            let bridge = BleDelegateBridge { [weak self] frame in
                self?.discoveredBleCount += 1
                self?.packetHandler?(frame, "ble0 (BLE Radio)")
            }
            self.centralDelegateWrapper = bridge
            self.centralManager = CBCentralManager(delegate: bridge, queue: DispatchQueue(label: "com.sharkmobile.ble.central", qos: .utility))
        } else {
            centralDelegateWrapper?.isScanning = true
            if centralManager?.state == .poweredOn {
                centralManager?.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
            }
        }
        #endif
    }

    public func stop() {
        isScanning = false
        #if canImport(CoreBluetooth)
        centralDelegateWrapper?.isScanning = false
        centralManager?.stopScan()
        #endif
    }

    public func deliverSyntheticBleFrame(mfgData: Data, rssi: Int = -60) {
        var frame = Data([0x42, 0x4C, 0x45])
        frame.append(UInt8(bitPattern: Int8(clamping: rssi)))
        frame.append(mfgData)
        while frame.count < 8 { frame.append(0) }
        discoveredBleCount += 1
        packetHandler?(frame, "ble0 (BLE Radio)")
    }
}

#if canImport(CoreBluetooth)
private final class BleDelegateBridge: NSObject, CBCentralManagerDelegate {
    var isScanning: Bool = true
    let onPacket: (Data) -> Void

    init(onPacket: @escaping (Data) -> Void) {
        self.onPacket = onPacket
        super.init()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn && isScanning {
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        var frame = Data([0x42, 0x4C, 0x45]) // Magic "BLE"
        let rssiInt = RSSI.intValue
        frame.append(UInt8(bitPattern: Int8(clamping: rssiInt)))

        if let mfg = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data, !mfg.isEmpty {
            frame.append(mfg)
        } else if let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name, let nameBytes = name.data(using: .utf8) {
            frame.append(UInt8(min(nameBytes.count + 1, 255)))
            frame.append(0x09) // Complete Local Name
            frame.append(nameBytes)
        } else if let uuids = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID], let first = uuids.first {
            let uuidData = first.data
            frame.append(UInt8(min(uuidData.count + 1, 255)))
            frame.append(0x03) // Complete 16-bit UUID
            frame.append(uuidData)
        } else {
            frame.append(contentsOf: [0x02, 0x01, 0x06, 0x00])
        }

        while frame.count < 8 { frame.append(0) }
        onPacket(frame)
    }
}
#endif

// MARK: - 3. Local Socket Tap (Real UDP Multicast & Broadcast Capture)
public final class LocalSocketCapture: @unchecked Sendable {
    public var packetHandler: ((Data, String) -> Void)?
    public private(set) var isListening: Bool = false
    public private(set) var capturedSocketPacketCount: Int = 0

    private var mdnsFd: Int32 = -1
    private var ssdpFd: Int32 = -1
    private var mdnsSource: DispatchSourceRead?
    private var ssdpSource: DispatchSourceRead?
    private let queue = DispatchQueue(label: "com.sharkmobile.localsocket.tap", qos: .userInitiated)

    public init() {}

    deinit {
        stop()
    }

    public func start() {
        guard !isListening else { return }
        isListening = true

        setupMdnsTap()
        setupSsdpTap()
        sendMulticastDiscoveryProbes()
    }

    public func stop() {
        isListening = false
        if let s = mdnsSource {
            s.cancel()
            mdnsSource = nil
        }
        if let s = ssdpSource {
            s.cancel()
            ssdpSource = nil
        }
        if mdnsFd >= 0 {
            close(mdnsFd)
            mdnsFd = -1
        }
        if ssdpFd >= 0 {
            close(ssdpFd)
            ssdpFd = -1
        }
    }

    private func setupMdnsTap() {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = in_port_t(5353).bigEndian
        sin.sin_addr.s_addr = in_addr_t(0) // INADDR_ANY

        let bindRes = withUnsafePointer(to: &sin) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if bindRes == 0 {
            var mreq = ip_mreq()
            mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251")
            mreq.imr_interface.s_addr = in_addr_t(0)
            _ = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size))
        }

        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        self.mdnsFd = fd

        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler { [weak self] in
            self?.readFromSocket(fd: fd, defaultDstIP: "224.0.0.251", defaultDstPort: 5353)
        }
        src.resume()
        self.mdnsSource = src
    }

    private func setupSsdpTap() {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = in_port_t(1900).bigEndian
        sin.sin_addr.s_addr = in_addr_t(0)

        let bindRes = withUnsafePointer(to: &sin) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                bind(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if bindRes == 0 {
            var mreq = ip_mreq()
            mreq.imr_multiaddr.s_addr = inet_addr("239.255.255.250")
            mreq.imr_interface.s_addr = in_addr_t(0)
            _ = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size))
        }

        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        self.ssdpFd = fd

        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler { [weak self] in
            self?.readFromSocket(fd: fd, defaultDstIP: "239.255.255.250", defaultDstPort: 1900)
        }
        src.resume()
        self.ssdpSource = src
    }

    private func readFromSocket(fd: Int32, defaultDstIP: String, defaultDstPort: Int) {
        var buffer = [UInt8](repeating: 0, count: 65535)
        while true {
            var srcAddr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &srcAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    recvfrom(fd, &buffer, buffer.count, 0, saPtr, &addrLen)
                }
            }
            guard n > 0 else { break }

            let payload = Data(buffer[0..<n])
            let srcIP = String(cString: inet_ntoa(srcAddr.sin_addr))
            let srcPort = Int(UInt16(bigEndian: srcAddr.sin_port))

            let packetFrame = buildEthernetIPv4UDP(
                srcIP: srcIP, dstIP: defaultDstIP,
                srcPort: srcPort, dstPort: defaultDstPort,
                payload: payload
            )
            capturedSocketPacketCount += 1
            packetHandler?(packetFrame, "en0 (Wi-Fi)")
        }
    }

    public func sendMulticastDiscoveryProbes() {
        queue.async { [weak self] in
            // Active SSDP M-SEARCH Discovery Probe
            let ssdpText = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
            self?.sendUDP(payload: Data(ssdpText.utf8), dstIP: "239.255.255.250", dstPort: 1900)

            // Active mDNS Discovery Query for local services
            let mdnsPayload = self?.createMdnsDiscoveryQuery() ?? Data()
            self?.sendUDP(payload: mdnsPayload, dstIP: "224.0.0.251", dstPort: 5353)
        }
    }

    private func sendUDP(payload: Data, dstIP: String, dstPort: UInt16) {
        let probeSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard probeSocket >= 0 else { return }
        defer { close(probeSocket) }

        var broadcastEnable: Int32 = 1
        setsockopt(probeSocket, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, socklen_t(MemoryLayout<Int32>.size))

        var dstAddr = sockaddr_in()
        dstAddr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dstAddr.sin_family = sa_family_t(AF_INET)
        dstAddr.sin_port = dstPort.bigEndian
        dstAddr.sin_addr.s_addr = inet_addr(dstIP)

        _ = payload.withUnsafeBytes { rawBytes in
            withUnsafePointer(to: &dstAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    sendto(probeSocket, rawBytes.baseAddress, payload.count, 0, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    public func createMdnsDiscoveryQuery() -> Data {
        // Query for _services._dns-sd._udp.local (PTR IN)
        var d = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let parts = ["_services", "_dns-sd", "_udp", "local"]
        for p in parts {
            let partData = Data(p.utf8)
            d.append(UInt8(min(partData.count, 63)))
            d.append(partData)
        }
        d.append(contentsOf: [0x00, 0x00, 0x0C, 0x00, 0x01])
        return d
    }

    public func buildEthernetIPv4UDP(
        srcIP: String, dstIP: String,
        srcPort: Int, dstPort: Int,
        payload: Data
    ) -> Data {
        var d = Data(repeating: 0, count: 14)
        // Multicast destination MAC
        d[0] = 0x01; d[1] = 0x00; d[2] = 0x5E; d[3] = 0x00; d[4] = 0x00; d[5] = 0xFB
        // Source MAC (Apple/Host OUI)
        d[6] = 0xAC; d[7] = 0xDE; d[8] = 0x48; d[9] = 0x55; d[10] = 0x66; d[11] = 0x77
        d[12] = 0x08; d[13] = 0x00 // EtherType IPv4

        var ip = Data([0x45, 0x00, 0x00, 0x00, 0x1A, 0x2B, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00])
        let srcParts = srcIP.components(separatedBy: ".").compactMap { UInt8($0) }
        let dstParts = dstIP.components(separatedBy: ".").compactMap { UInt8($0) }
        if srcParts.count == 4 { ip.append(contentsOf: srcParts) } else { ip.append(contentsOf: [192, 168, 1, 100]) }
        if dstParts.count == 4 { ip.append(contentsOf: dstParts) } else { ip.append(contentsOf: [224, 0, 0, 251]) }

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
}

// MARK: - 4. Apple NetworkExtension PacketTunnelBridge (VPN Tunnel Driver)
public final class PacketTunnelBridge: @unchecked Sendable {
    public static let shared = PacketTunnelBridge()
    public var packetHandler: ((Data, String) -> Void)?
    public private(set) var isActive: Bool = false
    public private(set) var receivedTunnelCount: Int = 0

    private init() {}

    public func start() {
        isActive = true
    }

    public func stop() {
        isActive = false
    }

    /// Entry point for Apple NEPacketTunnelProvider / NEPacketTunnelFlow
    /// Called when NEPacketTunnelFlow.readPackets(completionHandler:) delivers packets
    public func handleIncomingPackets(packets: [Data], protocols: [NSNumber], interface: String = "utun0 (VPN)") {
        guard isActive else { return }
        for pkt in packets {
            receivedTunnelCount += 1
            packetHandler?(pkt, interface)
        }
    }

    /// Single packet entry point for extensions or IPC pipes
    public func ingestTunnelPacket(data: Data, interface: String = "utun0 (VPN)") {
        guard isActive else { return }
        receivedTunnelCount += 1
        packetHandler?(data, interface)
    }
}

// MARK: - 5. Real Capture Pipeline (Hardware Multi-Source Coordinator)
public final class RealCapturePipeline: @unchecked Sendable {
    public let bpfCapture = BpfPacketCapture()
    public let bleCapture = BleAirspaceCapture()
    public let localSocketCapture = LocalSocketCapture()
    public let packetTunnelBridge = PacketTunnelBridge.shared

    public var packetHandler: ((Data, String) -> Void)?
    public private(set) var isCapturing: Bool = false
    public private(set) var activeMode: CaptureSourceMode = .liveHardware

    public var bpfStatus: BpfPacketCapture.BpfStatus {
        bpfCapture.status
    }

    public init() {}

    public func start(interface: String = "All Interfaces", mode: CaptureSourceMode = .liveHardware) {
        guard !isCapturing else { return }
        self.isCapturing = true
        self.activeMode = mode

        // Route all child capture sinks into pipeline handler
        bpfCapture.packetHandler = { [weak self] data, iface in
            self?.packetHandler?(data, iface)
        }
        bleCapture.packetHandler = { [weak self] data, iface in
            self?.packetHandler?(data, iface)
        }
        localSocketCapture.packetHandler = { [weak self] data, iface in
            self?.packetHandler?(data, iface)
        }
        packetTunnelBridge.packetHandler = { [weak self] data, iface in
            self?.packetHandler?(data, iface)
        }

        switch mode {
        case .liveHardware:
            // Multi-source concurrent hardware tap:
            // 1. Attempt BPF raw promiscuous tap
            bpfCapture.start(interface: interface)
            // 2. Start Local Socket mDNS/SSDP listener
            localSocketCapture.start()
            // 3. Start BLE Airspace receiver
            bleCapture.start()
            // 4. Activate PacketTunnelBridge
            packetTunnelBridge.start()

        case .bpfRaw:
            bpfCapture.start(interface: interface)

        case .localSocketTap:
            localSocketCapture.start()

        case .bleAirspace:
            bleCapture.start()

        case .demoSimulated:
            break
        }
    }

    public func stop() {
        isCapturing = false
        bpfCapture.stop()
        bleCapture.stop()
        localSocketCapture.stop()
        packetTunnelBridge.stop()
    }
}
