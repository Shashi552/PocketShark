import SwiftUI

#if canImport(UIKit)
import UIKit
#endif

// MARK: - Root Tab View
public struct SharkMobileMainView: View {
    @StateObject private var engine = CaptureEngine()
    @StateObject private var bleScanner = BleAirspaceScanner()
    @State private var selectedTab = 0

    public init() {}

    public var body: some View {
        TabView(selection: $selectedTab) {
            // Tab 1: Live Wireshark Sniffer
            SnifferDashboardView(engine: engine)
                .tabItem {
                    Label("Capture", systemImage: "waveform.path.ecg")
                }
                .tag(0)

            // Tab 2: Radios & Hardware Interfaces
            InterfacesDashboardView(engine: engine, bleScanner: bleScanner)
                .tabItem {
                    Label("Interfaces", systemImage: "antenna.radiowaves.left.and.right")
                }
                .tag(1)

            // Tab 3: Traffic Analytics & Statistics
            TrafficAnalyticsView(engine: engine)
                .tabItem {
                    Label("Analytics", systemImage: "chart.pie.fill")
                }
                .tag(2)

            // Tab 4: PCAP File Vault
            PcapVaultView(engine: engine)
                .tabItem {
                    Label("PCAP Library", systemImage: "externaldrive.fill")
                }
                .tag(3)

            // Tab 5: Engine Settings & Buffer Tuning
            SettingsDashboardView(engine: engine)
                .tabItem {
                    Label("Settings", systemImage: "gearshape.fill")
                }
                .tag(4)
        }
    }
}

// MARK: - Tab 1: Sniffer Dashboard
public struct SnifferDashboardView: View {
    @ObservedObject var engine: CaptureEngine
    @State private var filterText: String = ""
    @State private var inspectedPacket: PacketRecord? = nil
    @State private var showingFollowStream: Bool = false
    @State private var followTargetPacket: PacketRecord? = nil

    private var filteredPackets: [PacketRecord] {
        if filterText.isEmpty {
            return engine.packets
        }
        return engine.packets.filter { DisplayFilter.evaluate(filter: filterText, packet: $0) }
    }

    public var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Top Control & Interface Strip
                VStack(spacing: 6) {
                    HStack(spacing: 8) {
                        // Start / Stop Capture
                        Button(action: {
                            if engine.isCapturing {
                                engine.stopCapture()
                            } else {
                                engine.startCapture()
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: engine.isCapturing ? "stop.fill" : "play.fill")
                                    .foregroundColor(.white)
                                Text(engine.isCapturing ? "Stop" : "Capture")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.white)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .background(engine.isCapturing ? Color.red : Color.green)
                            .cornerRadius(8)
                        }

                        // Clear Button
                        Button(action: { engine.clear() }) {
                            Image(systemName: "trash")
                                .font(.system(size: 14))
                                .foregroundColor(.secondary)
                                .padding(7)
                                .background(Color.secondary.opacity(0.12))
                                .cornerRadius(8)
                        }

                        // Interface Selector Pill Menu
                        Menu {
                            Button("All Interfaces") { engine.selectedInterface = "All Interfaces" }
                            Button("Wi-Fi (en0)") { engine.selectedInterface = "en0" }
                            Button("Cellular (pdp_ip0)") { engine.selectedInterface = "pdp_ip0" }
                            Button("Loopback (lo0)") { engine.selectedInterface = "lo0" }
                            Button("BLE Airspace (ble0)") { engine.selectedInterface = "ble0" }
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "network")
                                    .font(.system(size: 11))
                                Text(engine.selectedInterface)
                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                Image(systemName: "chevron.down")
                                    .font(.system(size: 9))
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 7)
                            .background(Color.secondary.opacity(0.15))
                            .cornerRadius(8)
                        }

                        Spacer()

                        // Follow Stream Action Button
                        if let last = filteredPackets.last(where: { $0.protocolType == .tcp || $0.protocolType == .http }) {
                            Button(action: {
                                followTargetPacket = last
                                showingFollowStream = true
                            }) {
                                Image(systemName: "bubble.left.and.bubble.right.fill")
                                    .font(.system(size: 13))
                                    .foregroundColor(.accentColor)
                                    .padding(7)
                                    .background(Color.accentColor.opacity(0.12))
                                    .cornerRadius(8)
                            }
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.top, 6)

                    // Wireshark Display Filter Input
                    HStack {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                            .foregroundColor(.secondary)
                        TextField("Filter (e.g. ip.addr == 1.1.1.1, tcp, dns, tls, ble, quic)", text: $filterText)
                            .font(.system(size: 12, design: .monospaced))
                        if !filterText.isEmpty {
                            Button(action: { filterText = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                    .padding(7)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(8)
                    .padding(.horizontal, 10)

                    // Quick Filter Syntax Pills
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            FilterPill(title: "All", filter: "", activeFilter: $filterText)
                            FilterPill(title: "TCP", filter: "tcp", activeFilter: $filterText)
                            FilterPill(title: "HTTP", filter: "http", activeFilter: $filterText)
                            FilterPill(title: "TLS/SSL", filter: "tls", activeFilter: $filterText)
                            FilterPill(title: "DNS", filter: "dns", activeFilter: $filterText)
                            FilterPill(title: "QUIC", filter: "quic", activeFilter: $filterText)
                            FilterPill(title: "BLE", filter: "ble", activeFilter: $filterText)
                            FilterPill(title: "Cloudflare", filter: "ip.addr == 1.1.1.1", activeFilter: $filterText)
                            FilterPill(title: "Gateway", filter: "ip.addr == 192.168.1.1", activeFilter: $filterText)
                        }
                        .padding(.horizontal, 10)
                        .padding(.bottom, 6)
                    }
                }
                .background(Color.secondary.opacity(0.04))

                Divider()

                // Pane 1: Full-Width Packet Table
                List(filteredPackets) { packet in
                    PacketRowView(packet: packet)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            // Tapping opens dismissible full inspector sheet!
                            self.inspectedPacket = packet
                        }
                        .contextMenu {
                            Button("Inspect Packet Details") {
                                self.inspectedPacket = packet
                            }
                            if packet.protocolType == .tcp || packet.protocolType == .http {
                                Button("Follow TCP Stream") {
                                    self.followTargetPacket = packet
                                    self.showingFollowStream = true
                                }
                            }
                        }
                        .listRowInsets(EdgeInsets(top: 2, leading: 6, bottom: 2, trailing: 6))
                        .listRowBackground(Color(hex: packet.protocolType.colorHex).opacity(0.65))
                }
                .listStyle(.plain)

                Divider()

                // Real-Time Bottom Telemetry Bar
                HStack {
                    Text("Packets: \(engine.capturedCount)  |  Shown: \(filteredPackets.count)  |  Dropped: \(engine.droppedCount)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("RAM: \(String(format: "%.2f", engine.memoryUsageMB)) MB / \(Int(engine.maxMemoryMB)) MB")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(engine.memoryUsageMB > (engine.maxMemoryMB * 0.8) ? .red : .secondary)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Color.secondary.opacity(0.08))
            }
            .navigationTitle("SharkMobile")
            .navigationBarTitleDisplayMode(.inline)
            // DISMISSIBLE PACKET INSPECTOR SHEET WITH DONE BUTTON
            .sheet(item: $inspectedPacket) { packet in
                PacketInspectorModalView(packet: packet, allPackets: engine.packets) {
                    self.inspectedPacket = nil // Closes instantly!
                }
            }
            .sheet(isPresented: $showingFollowStream) {
                if let target = followTargetPacket {
                    FollowStreamView(packets: engine.packets, selectedPacket: target)
                }
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

// MARK: - Filter Pill
struct FilterPill: View {
    let title: String
    let filter: String
    @Binding var activeFilter: String

    var isSelected: Bool {
        activeFilter == filter
    }

    var body: some View {
        Button(action: { activeFilter = filter }) {
            Text(title)
                .font(.system(size: 11, weight: isSelected ? .bold : .medium, design: .monospaced))
                .foregroundColor(isSelected ? .white : .primary)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(isSelected ? Color.accentColor : Color.secondary.opacity(0.12))
                .cornerRadius(12)
        }
    }
}

// MARK: - Dismissible Full Packet Inspector Modal
public struct PacketInspectorModalView: View {
    public let packet: PacketRecord
    public let allPackets: [PacketRecord]
    public let onClose: () -> Void

    @State private var selectedTab: Int = 0
    @State private var selectedField: FieldDetail? = nil

    public var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Inspector Tab Selector
                Picker("Inspector Mode", selection: $selectedTab) {
                    Text("Protocol Tree").tag(0)
                    Text("Hex & ASCII").tag(1)
                    Text("Follow Stream").tag(2)
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(8)

                Divider()

                if selectedTab == 0 {
                    // Protocol Breakdown Tree
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(packet.layers) { layer in
                                DisclosureGroup(
                                    isExpanded: .constant(true),
                                    content: {
                                        VStack(alignment: .leading, spacing: 3) {
                                            ForEach(layer.fields) { field in
                                                HStack(alignment: .top) {
                                                    Text(field.name + ":")
                                                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                                        .foregroundColor(.secondary)
                                                    Text(field.value)
                                                        .font(.system(size: 12, design: .monospaced))
                                                        .foregroundColor(.primary)
                                                    Spacer()
                                                }
                                                .padding(3)
                                                .background(selectedField?.id == field.id ? Color.accentColor.opacity(0.2) : Color.clear)
                                                .cornerRadius(4)
                                                .onTapGesture {
                                                    selectedField = field
                                                }
                                            }
                                        }
                                        .padding(.leading, 12)
                                    },
                                    label: {
                                        Text(layer.summary)
                                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                                            .foregroundColor(.primary)
                                    }
                                )
                                Divider()
                            }
                        }
                        .padding(10)
                    }
                } else if selectedTab == 1 {
                    // Interactive Hex Dump with synchronized highlight
                    VStack(alignment: .leading, spacing: 4) {
                        if let field = selectedField {
                            HStack {
                                Text("Selected Field: \(field.name)")
                                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                                    .foregroundColor(.accentColor)
                                Spacer()
                                if let r = field.byteRange {
                                    Text("Bytes [\(r.lowerBound)...\((r.upperBound - 1))]")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(.horizontal, 10)
                            .padding(.top, 4)
                        }
                        HexDumpView(data: packet.rawData, highlightRange: selectedField?.byteRange)
                    }
                } else {
                    // In-Line Stream Reassembler
                    let chunks = StreamReassembler.followStream(packets: allPackets, selectedPacket: packet)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(chunks) { chunk in
                                Text(chunk.text)
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(chunk.isClientToServer ? .red : .blue)
                                    .padding(6)
                                    .background(Color.secondary.opacity(0.06))
                                    .cornerRadius(6)
                            }
                        }
                        .padding()
                    }
                }

                Divider()

                // Bottom Metadata Strip
                HStack {
                    Text("Length: \(packet.length) bytes")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("Interface: \(packet.interface)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Color.secondary.opacity(0.05))
            }
            .navigationTitle("Packet #\(packet.id) [\(packet.protocolType.rawValue)]")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarItems(
                trailing: Button("Done") {
                    onClose() // INSTANTLY CLOSES VIEW!
                }
                .font(.system(size: 14, weight: .bold))
            )
        }
    }
}

// MARK: - Tab 2: Interfaces & Radios Dashboard
public struct InterfacesDashboardView: View {
    @ObservedObject var engine: CaptureEngine
    @ObservedObject var bleScanner: BleAirspaceScanner
    @State private var interfaces: [NetworkInterfaceInfo] = []

    public var body: some View {
        NavigationView {
            List {
                // Section: Hardware Network Interfaces
                Section(header: Text("Network Interfaces (getifaddrs)")) {
                    ForEach(interfaces) { iface in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(iface.name)
                                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                                Spacer()
                                Text(iface.type.rawValue)
                                    .font(.system(size: 11, weight: .semibold))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.accentColor.opacity(0.15))
                                    .cornerRadius(6)
                            }
                            HStack {
                                Text("IP: \(iface.ipAddress)")
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(.secondary)
                                Spacer()
                                Text(iface.isUp ? "UP" : "DOWN")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(iface.isUp ? .green : .red)
                            }
                            Text("Mask: \(iface.netmask)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary.opacity(0.8))
                        }
                        .padding(.vertical, 2)
                    }
                }

                // Section: Live BLE Airspace Radio Scanner
                Section(header: HStack {
                    Text("Bluetooth Low Energy Airspace")
                    Spacer()
                    Button(bleScanner.isScanning ? "Stop Scan" : "Scan Airspace") {
                        if bleScanner.isScanning {
                            bleScanner.stopScan()
                        } else {
                            bleScanner.startScan()
                        }
                    }
                    .font(.system(size: 11, weight: .bold))
                }) {
                    if bleScanner.discoveredDevices.isEmpty {
                        Text("No BLE advertising beacons detected. Tap 'Scan Airspace' to begin.")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(bleScanner.discoveredDevices) { dev in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(dev.name)
                                        .font(.system(size: 13, weight: .bold))
                                    Spacer()
                                    Text("\(dev.rssi) dBm")
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(dev.rssi > -60 ? .green : (dev.rssi > -80 ? .orange : .red))
                                }
                                if let continuity = dev.continuityType {
                                    Text("Apple Continuity: \(continuity)")
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(.purple)
                                }
                                Text("UUID: \(dev.id)")
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(.secondary)
                                if !dev.manufacturerDataHex.isEmpty {
                                    Text("Payload: \(dev.manufacturerDataHex)")
                                        .font(.system(size: 9, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("Radios & Interfaces")
            .onAppear {
                self.interfaces = InterfaceDetector.getActiveInterfaces()
                self.bleScanner.startScan()
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

// MARK: - Tab 3: Analytics & Statistics Dashboard
public struct TrafficAnalyticsView: View {
    @ObservedObject var engine: CaptureEngine

    public var body: some View {
        NavigationView {
            List {
                Section(header: Text("Protocol Hierarchy Breakdown")) {
                    let total = max(1, engine.packets.count)
                    ForEach(ProtocolType.allCases, id: \.self) { proto in
                        let count = engine.packets.filter { $0.protocolType == proto }.count
                        if count > 0 {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(proto.rawValue)
                                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                                    Spacer()
                                    Text("\(count) packets (\(Int(Double(count)/Double(total)*100))%)")
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                                ProgressView(value: Double(count), total: Double(total))
                                    .accentColor(Color(hex: proto.colorHex))
                            }
                            .padding(.vertical, 2)
                        }
                    }
                }

                Section(header: Text("Top Conversations & Endpoints")) {
                    let convos = getTopConversations()
                    if convos.isEmpty {
                        Text("Capture traffic to analyze conversations.")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(convos, id: \.0) { ep, count in
                            HStack {
                                Text(ep)
                                    .font(.system(size: 11, design: .monospaced))
                                Spacer()
                                Text("\(count) pkts")
                                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                                    .foregroundColor(.accentColor)
                            }
                        }
                    }
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("Traffic Analytics")
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }

    private func getTopConversations() -> [(String, Int)] {
        var map: [String: Int] = [:]
        for p in engine.packets {
            let key = "\(p.source) ⟷ \(p.destination)"
            map[key, default: 0] += 1
        }
        return map.sorted { $0.value > $1.value }.prefix(10).map { ($0.key, $0.value) }
    }
}

// MARK: - Tab 4: PCAP Vault View
public struct PcapVaultView: View {
    @ObservedObject var engine: CaptureEngine
    @State private var exportSuccessMessage: String? = nil

    public var body: some View {
        NavigationView {
            List {
                Section(header: Text("Active Capture Buffer")) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Current Buffer")
                                .font(.system(size: 14, weight: .bold))
                            Text("\(engine.capturedCount) Packets | \(String(format: "%.2f", engine.memoryUsageMB)) MB")
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button(action: { exportAndShare() }) {
                            HStack(spacing: 4) {
                                Image(systemName: "square.and.arrow.up")
                                Text("Export .pcap")
                            }
                            .font(.system(size: 12, weight: .bold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Color.accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                        }
                    }
                }

                Section(header: Text("Import from Files / AirDrop")) {
                    Text("You can open standard .pcap and .pcapng files from iCloud Drive, Mac AirDrop, or local iOS Files to dissect any capture packet-by-packet.")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("PCAP Library")
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }

    private func exportAndShare() {
        let data = engine.exportPcap()
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("sharkmobile_\(Int(Date().timeIntervalSince1970)).pcap")
        try? data.write(to: tempURL)

        #if canImport(UIKit)
        let av = UIActivityViewController(activityItems: [tempURL], applicationActivities: nil)
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = windowScene.windows.first?.rootViewController {
            root.present(av, animated: true)
        }
        #endif
    }
}

// MARK: - Tab 5: Settings Dashboard View
public struct SettingsDashboardView: View {
    @ObservedObject var engine: CaptureEngine

    public var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Memory Ring Buffer Limit"), footer: Text("Adjust memory threshold based on device headroom. Default is 100MB on modern iPhones, or 12MB for background NetworkExtension stability.")) {
                    HStack {
                        Text("Max Buffer:")
                            .font(.system(size: 14, design: .monospaced))
                        Spacer()
                        Text("\(Int(engine.maxMemoryMB)) MB")
                            .font(.system(size: 14, weight: .bold, design: .monospaced))
                    }
                    Slider(value: $engine.maxMemoryMB, in: 12...500, step: 10)
                }

                Section(header: Text("Engine Information")) {
                    HStack {
                        Text("Architecture")
                        Spacer()
                        Text("Mach-O 64-bit arm64")
                            .foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Compatibility")
                        Spacer()
                        Text("LiveContainer / TrollStore / Jailed")
                            .foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Private APIs")
                        Spacer()
                        Text("Zero (100% Pure Swift)")
                            .foregroundColor(.green)
                    }
                }
            }
            .navigationTitle("Settings")
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

// MARK: - Packet Row View
public struct PacketRowView: View {
    public let packet: PacketRecord

    public var body: some View {
        HStack(spacing: 6) {
            Text("\(packet.id)")
                .frame(width: 32, alignment: .leading)
            Text(packet.timeString)
                .frame(width: 75, alignment: .leading)
            Text(packet.source)
                .frame(width: 105, alignment: .leading)
            Text(packet.destination)
                .frame(width: 105, alignment: .leading)
            Text(packet.protocolType.rawValue)
                .frame(width: 42, alignment: .center)
                .font(.system(size: 10, weight: .bold))
            Text("\(packet.length)")
                .frame(width: 36, alignment: .trailing)
            Text(packet.info)
                .lineLimit(1)
            Spacer()
        }
        .font(.system(size: 11, design: .monospaced))
        .padding(.vertical, 2)
    }
}

// MARK: - Hex Dump View
public struct HexDumpView: View {
    public let data: Data
    public let highlightRange: Range<Int>?

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(0..<(data.count + 15) / 16, id: \.self) { row in
                    let start = row * 16
                    let end = min(start + 16, data.count)
                    let rowData = data.subdata(in: start..<end)

                    HStack(spacing: 6) {
                        Text(String(format: "%04x", start))
                            .foregroundColor(.secondary)

                        HStack(spacing: 3) {
                            ForEach(0..<16, id: \.self) { col in
                                let idx = start + col
                                if idx < data.count {
                                    let byte = data[idx]
                                    let isHighlighted = highlightRange?.contains(idx) ?? false
                                    Text(String(format: "%02x", byte))
                                        .foregroundColor(isHighlighted ? .accentColor : .primary)
                                        .font(.system(size: 10, weight: isHighlighted ? .bold : .regular, design: .monospaced))
                                } else {
                                    Text("  ")
                                }
                            }
                        }

                        Text(formatAscii(rowData))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    .font(.system(size: 10, design: .monospaced))
                }
            }
            .padding(8)
        }
    }

    private func formatAscii(_ d: Data) -> String {
        return d.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
    }
}

// MARK: - Follow TCP Stream View
public struct FollowStreamView: View {
    public let packets: [PacketRecord]
    public let selectedPacket: PacketRecord
    @Environment(\.presentationMode) var presentationMode

    public var body: some View {
        NavigationView {
            let chunks = StreamReassembler.followStream(packets: packets, selectedPacket: selectedPacket)
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(chunks) { chunk in
                        Text(chunk.text)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(chunk.isClientToServer ? .red : .blue)
                            .padding(6)
                            .background(Color.secondary.opacity(0.06))
                            .cornerRadius(6)
                    }
                }
                .padding()
            }
            .navigationTitle("Follow TCP Stream")
            .navigationBarItems(trailing: Button("Done") { presentationMode.wrappedValue.dismiss() })
        }
    }
}

// MARK: - Color Extension
extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3:
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6:
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}
