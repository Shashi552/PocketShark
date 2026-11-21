import SwiftUI

#if canImport(UIKit)
import UIKit
#endif

// MARK: - Root Tab View: Tactical Mission Command
public struct SharkMobileMainView: View {
    @StateObject private var engine = CaptureEngine()
    @StateObject private var bleScanner = BleAirspaceScanner()
    @State private var selectedTab = 0
    @State private var isNightVisionMode: Bool = true

    public init() {}

    public var body: some View {
        ZStack {
            TabView(selection: $selectedTab) {
                // Tab 1: Live Wireshark Capture & 3-Pane Inspector
                SnifferDashboardView(engine: engine, isNightVision: $isNightVisionMode)
                    .tabItem {
                        Label("Capture", systemImage: "waveform.path.ecg")
                    }
                    .tag(0)

                // Tab 2: Tactical Mission & Case File Command
                TacticalMissionView(engine: engine, isNightVision: $isNightVisionMode)
                    .tabItem {
                        Label("Mission HUD", systemImage: "shield.lefthalf.filled")
                    }
                    .tag(1)

                // Tab 3: Threat Radar & Security Hunter
                SecurityDashboardView(engine: engine, isNightVision: $isNightVisionMode)
                    .tabItem {
                        Label("Threat Radar", systemImage: "radar")
                    }
                    .tag(2)

                // Tab 4: Asset Topology & Visual Flow Ladder
                TopologyAndFlowView(engine: engine, isNightVision: $isNightVisionMode)
                    .tabItem {
                        Label("Flow & Topology", systemImage: "network")
                    }
                    .tag(3)

                // Tab 5: Radios, PCAP-NG Vault & GPS Wardriving
                VaultAndRadiosView(engine: engine, bleScanner: bleScanner, isNightVision: $isNightVisionMode)
                    .tabItem {
                        Label("Vault & GPS", systemImage: "externaldrive.fill")
                    }
                    .tag(4)
            }
            .accentColor(isNightVisionMode ? Color(hex: "#00E5FF") : Color.blue)
            .preferredColorScheme(isNightVisionMode ? .dark : nil)

            // Biometric Privacy Guard Overlay
            if engine.biometricGuard.isLocked {
                BiometricLockOverlayView(guardEngine: engine.biometricGuard)
                    .transition(.opacity)
                    .zIndex(100)
            }
        }
    }
}

// MARK: - Biometric Lock Overlay View
public struct BiometricLockOverlayView: View {
    @ObservedObject var guardEngine: BiometricGuard

    public var body: some View {
        ZStack {
            Color.black.edgesIgnoringSafeArea(.all)
            VStack(spacing: 20) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 64))
                    .foregroundColor(Color(hex: "#FF3B30"))

                Text("TACTICAL EVIDENCE LOCKED")
                    .font(.system(size: 18, weight: .black, design: .monospaced))
                    .foregroundColor(.white)

                Text("CLASSIFIED // TACTICAL EYES ONLY\nAuthenticate with \(guardEngine.biometricTypeString) to access captured packet buffers and case reports.")
                    .font(.system(size: 12, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .foregroundColor(.gray)
                    .padding(.horizontal, 32)

                if let err = guardEngine.authErrorMessage {
                    Text(err)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.red)
                }

                Button(action: {
                    guardEngine.authenticate { _ in }
                }) {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.open.fill")
                        Text("Unlock with \(guardEngine.biometricTypeString)")
                    }
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(.black)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(Color(hex: "#00FF66"))
                    .cornerRadius(8)
                }
            }
        }
    }
}

// MARK: - Tab 1: Sniffer Dashboard
public struct SnifferDashboardView: View {
    @ObservedObject var engine: CaptureEngine
    @Binding var isNightVision: Bool
    @State private var filterText: String = ""
    @State private var inspectedPacket: PacketRecord? = nil
    @State private var showingFollowStream: Bool = false
    @State private var showingFlowLadder: Bool = false
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

                        // Night Vision Toggle
                        Button(action: { isNightVision.toggle() }) {
                            Image(systemName: isNightVision ? "moon.fill" : "sun.max.fill")
                                .font(.system(size: 13))
                                .foregroundColor(isNightVision ? Color(hex: "#FFB000") : .secondary)
                                .padding(7)
                                .background(Color.secondary.opacity(0.12))
                                .cornerRadius(8)
                        }

                        // Visual Flow Ladder Button
                        Button(action: { showingFlowLadder = true }) {
                            Image(systemName: "arrow.triangle.swap")
                                .font(.system(size: 13))
                                .foregroundColor(Color(hex: "#00E5FF"))
                                .padding(7)
                                .background(Color(hex: "#00E5FF").opacity(0.12))
                                .cornerRadius(8)
                        }
                    }
                    .padding(.horizontal, 10)
                    .padding(.top, 6)

                    // Wireshark Display Filter Input
                    HStack {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                            .foregroundColor(.secondary)
                        TextField("Filter (e.g. ip.addr == 1.1.1.1, tcp, quic, ws, dhcp)", text: $filterText)
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
                            FilterPill(title: "TLS", filter: "tls", activeFilter: $filterText)
                            FilterPill(title: "QUIC", filter: "quic", activeFilter: $filterText)
                            FilterPill(title: "DNS", filter: "dns", activeFilter: $filterText)
                            FilterPill(title: "mDNS", filter: "mdns", activeFilter: $filterText)
                            FilterPill(title: "DHCP", filter: "dhcp", activeFilter: $filterText)
                            FilterPill(title: "WS", filter: "ws", activeFilter: $filterText)
                            FilterPill(title: "BLE", filter: "ble", activeFilter: $filterText)
                        }
                        .padding(.horizontal, 10)
                        .padding(.bottom, 4)
                    }

                    // Expert Info Severity Bar
                    ExpertInfoBarView(packets: engine.packets, activeFilter: $filterText)
                        .padding(.horizontal, 10)
                        .padding(.bottom, 6)
                }
                .background(Color.secondary.opacity(0.04))

                Divider()

                // Full-Width Packet Table
                List(filteredPackets) { packet in
                    PacketRowView(packet: packet)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            self.inspectedPacket = packet
                        }
                        .listRowInsets(EdgeInsets(top: 2, leading: 6, bottom: 2, trailing: 6))
                        .listRowBackground(Color(hex: packet.protocolType.colorHex).opacity(0.55))
                }
                .listStyle(PlainListStyle())

                Divider()

                // Real-Time Bottom Telemetry Bar
                HStack {
                    Text("Packets: \(engine.capturedCount)  |  Shown: \(filteredPackets.count)  |  Threats: \(engine.threats.count)")
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
            .navigationTitle("SharkMobile: Command")
            .applyPlatformNavigationInline()
            .sheet(item: $inspectedPacket) { packet in
                PacketInspectorModalView(packet: packet, allPackets: engine.packets) {
                    self.inspectedPacket = nil
                }
            }
            .sheet(isPresented: $showingFollowStream) {
                if let target = followTargetPacket {
                    FollowStreamView(packets: engine.packets, selectedPacket: target)
                }
            }
            .sheet(isPresented: $showingFlowLadder) {
                FlowLadderSheetView(packets: engine.packets)
            }
        }
        .applyPlatformStackNavigation()
    }
}

// MARK: - Expert Info Bar View
struct ExpertInfoBarView: View {
    let packets: [PacketRecord]
    @Binding var activeFilter: String

    var errorCount: Int { packets.filter { $0.expertInfo?.severity == .error }.count }
    var warningCount: Int { packets.filter { $0.expertInfo?.severity == .warning }.count }
    var noteCount: Int { packets.filter { $0.expertInfo?.severity == .note }.count }
    var chatCount: Int { packets.filter { $0.expertInfo?.severity == .chat }.count }

    var body: some View {
        HStack(spacing: 6) {
            ExpertPill(severity: .error, count: errorCount)
            ExpertPill(severity: .warning, count: warningCount)
            ExpertPill(severity: .note, count: noteCount)
            ExpertPill(severity: .chat, count: chatCount)
            Spacer()
        }
    }
}

struct ExpertPill: View {
    let severity: ExpertSeverity
    let count: Int

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: severity.badgeIcon)
                .font(.system(size: 9))
            Text("\(severity.rawValue): \(count)")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .foregroundColor(Color(hex: severity.colorHex))
        .background(Color(hex: severity.colorHex).opacity(0.15))
        .cornerRadius(6)
    }
}

// MARK: - Filter Pill
struct FilterPill: View {
    let title: String
    let filter: String
    @Binding var activeFilter: String

    var isSelected: Bool { activeFilter == filter }

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
                Picker("Inspector Mode", selection: $selectedTab) {
                    Text("Protocol Tree").tag(0)
                    Text("Hex & ASCII").tag(1)
                    Text("Follow Stream").tag(2)
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(8)

                Divider()

                if selectedTab == 0 {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            if let exp = packet.expertInfo {
                                HStack(spacing: 6) {
                                    Image(systemName: exp.severity.badgeIcon)
                                        .foregroundColor(Color(hex: exp.severity.colorHex))
                                    Text("[\(exp.severity.rawValue)] \(exp.message)")
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(Color(hex: exp.severity.colorHex))
                                    Spacer()
                                }
                                .padding(8)
                                .background(Color(hex: exp.severity.colorHex).opacity(0.12))
                                .cornerRadius(6)
                            }

                            if let geo = packet.geoCoord {
                                HStack(spacing: 6) {
                                    Image(systemName: "location.fill")
                                        .foregroundColor(Color(hex: "#00E5FF"))
                                    Text(String(format: "GPS Fix: %.5f, %.5f (±%.1fm)", geo.latitude, geo.longitude, geo.horizontalAccuracy))
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(Color(hex: "#00E5FF"))
                                    Spacer()
                                }
                                .padding(6)
                                .background(Color(hex: "#00E5FF").opacity(0.1))
                                .cornerRadius(6)
                            }

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
                                                .onTapGesture { selectedField = field }
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
                    VStack(alignment: .leading, spacing: 4) {
                        if let field = selectedField {
                            HStack {
                                Text("Field: \(field.name)")
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
            .applyPlatformNavigationInline()
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button("Done") { onClose() }
                        .font(.system(size: 14, weight: .bold))
                }
            }
        }
    }
}

// MARK: - Tab 2: Tactical Mission HUD & Case Files
public struct TacticalMissionView: View {
    @ObservedObject var engine: CaptureEngine
    @Binding var isNightVision: Bool
    @State private var showingReportSheet: Bool = false
    @State private var forensicReportText: String = ""

    public var body: some View {
        NavigationView {
            List {
                Section(header: Text("Active Operation & Parameters")) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(engine.missionManager.caseCodename)
                                .font(.system(size: 16, weight: .black, design: .monospaced))
                                .foregroundColor(Color(hex: "#FFB000"))
                            Spacer()
                            Text(engine.missionManager.classification.rawValue)
                                .font(.system(size: 10, weight: .bold, design: .monospaced))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color(hex: engine.missionManager.classification.colorHex).opacity(0.2))
                                .foregroundColor(Color(hex: engine.missionManager.classification.colorHex))
                                .cornerRadius(4)
                        }

                        HStack {
                            Text("Case ID: \(engine.missionManager.caseNumber)")
                            Spacer()
                            Text("Callsign: \(engine.missionManager.investigatorCallsign)")
                        }
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.secondary)

                        Text("Directives: \(engine.missionManager.missionObjectives)")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }

                Section(header: Text("Evidence Integrity (SHA-256 Seal)")) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(Color(hex: "#00FF66"))
                            Text("TAMPER-PROOF FORENSIC HASH")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .foregroundColor(Color(hex: "#00FF66"))
                        }
                        Text(engine.missionManager.latestSha256)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(2)

                        Button(action: {
                            self.forensicReportText = engine.missionManager.generateForensicReport(
                                packets: engine.packets,
                                threats: engine.threats,
                                findings: engine.securityFindings,
                                assets: engine.discoveredAssets
                            )
                            self.showingReportSheet = true
                        }) {
                            HStack {
                                Image(systemName: "doc.text.fill")
                                Text("Generate Full Forensic Report")
                            }
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundColor(.white)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color(hex: "#FFB000"))
                            .cornerRadius(6)
                        }
                        .padding(.top, 4)
                    }
                    .padding(.vertical, 4)
                }

                Section(header: Text("Tactical Incident Log (\(engine.missionManager.incidentLogs.count))")) {
                    ForEach(engine.missionManager.incidentLogs.prefix(30)) { item in
                        HStack(alignment: .top, spacing: 8) {
                            Text(item.timeString.suffix(8))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text("[\(item.tag)]")
                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                        .foregroundColor(Color(hex: "#00E5FF"))
                                    Text(item.severity)
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 4)
                                        .background(Color.secondary.opacity(0.15))
                                        .cornerRadius(3)
                                }
                                Text(item.message)
                                    .font(.system(size: 11, design: .monospaced))
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .applyPlatformGroupedList()
            .navigationTitle("Mission HUD")
            .sheet(isPresented: $showingReportSheet) {
                ForensicReportModalView(reportMarkdown: forensicReportText)
            }
        }
        .applyPlatformStackNavigation()
    }
}

// MARK: - Forensic Report Modal View
public struct ForensicReportModalView: View {
    public let reportMarkdown: String
    @Environment(\.presentationMode) var presentationMode

    public var body: some View {
        NavigationView {
            ScrollView {
                Text(reportMarkdown)
                    .font(.system(size: 11, design: .monospaced))
                    .padding()
            }
            .navigationTitle("Forensic Report")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { presentationMode.wrappedValue.dismiss() }
                }
                ToolbarItem(placement: .automatic) {
                    Button("Share") { shareReport() }
                }
            }
        }
    }

    private func shareReport() {
        #if canImport(UIKit)
        let av = UIActivityViewController(activityItems: [reportMarkdown], applicationActivities: nil)
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = windowScene.windows.first?.rootViewController {
            root.present(av, animated: true)
        }
        #endif
    }
}

// MARK: - Tab 3: Threat Radar & Security Hunter
public struct SecurityDashboardView: View {
    @ObservedObject var engine: CaptureEngine
    @Binding var isNightVision: Bool

    public var body: some View {
        NavigationView {
            List {
                Section(header: HStack {
                    Image(systemName: "flame.fill")
                        .foregroundColor(.red)
                    Text("Threat Radar IDS Alerts (\(engine.threats.count))")
                        .font(.system(size: 13, weight: .bold))
                }) {
                    if engine.threats.isEmpty {
                        HStack {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundColor(.green)
                            Text("Zero threats detected. Airspace secure.")
                                .font(.system(size: 12))
                                .foregroundColor(.secondary)
                        }
                    } else {
                        ForEach(engine.threats) { t in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Image(systemName: t.severity.badgeIcon)
                                        .foregroundColor(Color(hex: t.severity.colorHex))
                                    Text(t.title)
                                        .font(.system(size: 13, weight: .bold))
                                    Spacer()
                                    Text(t.severity.rawValue)
                                        .font(.system(size: 10, weight: .bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color(hex: t.severity.colorHex).opacity(0.18))
                                        .cornerRadius(4)
                                }
                                Text(t.description)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.secondary)
                                HStack {
                                    Text("Attacker: \(t.attackerIP) ➔ \(t.victimIP)")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.secondary)
                                    Spacer()
                                    Text(t.mitreTactic)
                                        .font(.system(size: 9, design: .monospaced))
                                        .foregroundColor(Color(hex: "#00E5FF"))
                                }
                            }
                            .padding(.vertical, 3)
                        }
                    }
                }

                Section(header: HStack {
                    Image(systemName: "key.fill")
                        .foregroundColor(Color(hex: "#FFB000"))
                    Text("Security Hunter Findings (\(engine.securityFindings.count))")
                        .font(.system(size: 13, weight: .bold))
                }) {
                    if engine.securityFindings.isEmpty {
                        Text("No cleartext passwords or exposed API keys detected.")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(engine.securityFindings) { f in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Image(systemName: f.severity.badgeIcon)
                                        .foregroundColor(Color(hex: f.severity.colorHex))
                                    Text(f.title)
                                        .font(.system(size: 13, weight: .bold))
                                    Spacer()
                                    Text(f.category.rawValue)
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color(hex: f.severity.colorHex).opacity(0.18))
                                        .cornerRadius(4)
                                }
                                Text(f.description)
                                    .font(.system(size: 11))
                                if !f.secretPreview.isEmpty {
                                    Text("Preview: \(f.secretPreview)")
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(.red)
                                        .padding(4)
                                        .background(Color.red.opacity(0.1))
                                        .cornerRadius(4)
                                }
                                HStack {
                                    Text("\(f.sourceIP) ➔ \(f.destinationIP)")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.secondary)
                                    Spacer()
                                    Text("Packet #\(f.packetId)")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.accentColor)
                                }
                            }
                            .padding(.vertical, 3)
                        }
                    }
                }
            }
            .applyPlatformGroupedList()
            .navigationTitle("Threat Radar")
        }
        .applyPlatformStackNavigation()
    }
}

// MARK: - Tab 4: Topology & Visual Flow Ladder View
public struct TopologyAndFlowView: View {
    @ObservedObject var engine: CaptureEngine
    @Binding var isNightVision: Bool
    @State private var selectedSubTab: Int = 0

    public var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                Picker("View", selection: $selectedSubTab) {
                    Text("Asset Inventory").tag(0)
                    Text("TCP Flow Ladders").tag(1)
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(8)

                Divider()

                if selectedSubTab == 0 {
                    List {
                        Section(header: Text("Discovered LAN Assets (\(engine.discoveredAssets.count))")) {
                            if engine.discoveredAssets.isEmpty {
                                Text("Discovering network devices...")
                                    .font(.system(size: 12))
                                    .foregroundColor(.secondary)
                            } else {
                                ForEach(engine.discoveredAssets) { host in
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack {
                                            Text(host.countryFlag ?? "💻")
                                            Text(host.ip)
                                                .font(.system(size: 13, weight: .bold, design: .monospaced))
                                            Spacer()
                                            Text(host.vendor)
                                                .font(.system(size: 11, weight: .medium))
                                                .foregroundColor(.secondary)
                                        }
                                        HStack {
                                            Text("MAC: \(host.mac)")
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundColor(.secondary)
                                            Spacer()
                                            Text(host.osGuess)
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(.blue)
                                        }
                                        if !host.activeRoles.isEmpty {
                                            Text("Roles: \(host.activeRoles.joined(separator: ", "))")
                                                .font(.system(size: 10, design: .monospaced))
                                                .foregroundColor(Color(hex: "#00FF66"))
                                        }
                                    }
                                    .padding(.vertical, 2)
                                }
                            }
                        }
                    }
                    .applyPlatformGroupedList()
                } else {
                    FlowLadderSheetView(packets: engine.packets)
                }
            }
            .navigationTitle("Topology & Flow")
        }
        .applyPlatformStackNavigation()
    }
}

// MARK: - Flow Ladder Sheet View
public struct FlowLadderSheetView: View {
    public let packets: [PacketRecord]
    @Environment(\.presentationMode) var presentationMode

    public var body: some View {
        NavigationView {
            let ladders = VisualFlowLadder.buildLadders(packets: packets)
            if ladders.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "arrow.triangle.swap")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No TCP connections captured yet.")
                        .font(.system(size: 14, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                .navigationTitle("TCP Flow Ladders")
            } else {
                List {
                    ForEach(ladders) { ladder in
                        Section(header: Text("\(ladder.clientHost) ⟷ \(ladder.serverHost)")) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("State: \(ladder.connectionState)")
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(Color(hex: "#00E5FF"))
                                    Spacer()
                                    if let rtt = ladder.handshakeRttMs {
                                        Text(String(format: "Handshake RTT: %.2f ms", rtt))
                                            .font(.system(size: 10, design: .monospaced))
                                            .foregroundColor(.green)
                                    }
                                }
                                if let ttfb = ladder.ttfbMs {
                                    Text(String(format: "TTFB: %.2f ms", ttfb))
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.yellow)
                                }

                                Divider()

                                ForEach(ladder.steps.prefix(15)) { step in
                                    HStack(spacing: 8) {
                                        Text(String(format: "+%.1fms", step.relativeTimeMs))
                                            .font(.system(size: 9, design: .monospaced))
                                            .foregroundColor(.secondary)
                                            .frame(width: 48, alignment: .leading)

                                        Image(systemName: step.isClientToServer ? "arrow.right" : "arrow.left")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(step.isClientToServer ? .blue : .green)

                                        Text("[\(step.flags.joined(separator: ","))] \(step.summary)")
                                            .font(.system(size: 10, design: .monospaced))
                                            .lineLimit(1)
                                    }
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
                .applyPlatformGroupedList()
                .navigationTitle("Visual Flow Ladder")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { presentationMode.wrappedValue.dismiss() }
                    }
                }
            }
        }
    }
}

// MARK: - Tab 5: Radios, Vault & GPS Wardriving
public struct VaultAndRadiosView: View {
    @ObservedObject var engine: CaptureEngine
    @ObservedObject var bleScanner: BleAirspaceScanner
    @Binding var isNightVision: Bool

    public var body: some View {
        NavigationView {
            List {
                Section(header: Text("GPS Wardriving & Route Tracking")) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: "location.fill")
                                .foregroundColor(Color(hex: "#00E5FF"))
                            Text(engine.gpsManager.locationStatusString)
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                        }
                        if let loc = engine.gpsManager.currentCoordinate {
                            Text(String(format: "Latitude: %.6f, Longitude: %.6f", loc.latitude, loc.longitude))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                            Text(String(format: "Distance Traveled: %.1f m  |  Speed: %.1f km/h", engine.gpsManager.totalDistanceMeters, loc.speed * 3.6))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }

                Section(header: Text("PCAP-NG Vault & Sharing")) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Current Buffer")
                                .font(.system(size: 13, weight: .bold))
                            Text("\(engine.capturedCount) Packets | \(String(format: "%.2f", engine.memoryUsageMB)) MB")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button(action: { exportAndShare(isNg: true) }) {
                            Text("Export .pcapng")
                                .font(.system(size: 11, weight: .bold))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 6)
                                .background(Color(hex: "#00E5FF"))
                                .foregroundColor(.black)
                                .cornerRadius(6)
                        }
                    }

                    Button(action: { exportAndShare(isNg: false) }) {
                        HStack {
                            Image(systemName: "square.and.arrow.up")
                            Text("Export Standard .pcap")
                        }
                        .font(.system(size: 12, weight: .bold))
                    }
                }

                Section(header: Text("Biometric Security Guard")) {
                    Button(action: { engine.biometricGuard.lockImmediately() }) {
                        HStack {
                            Image(systemName: "lock.shield.fill")
                                .foregroundColor(.red)
                            Text("Lock Tactical Command Immediately")
                                .foregroundColor(.red)
                                .font(.system(size: 13, weight: .bold))
                        }
                    }
                }
            }
            .applyPlatformGroupedList()
            .navigationTitle("Vault & GPS")
        }
        .applyPlatformStackNavigation()
    }

    private func exportAndShare(isNg: Bool) {
        let data = isNg ? engine.exportPcapNg() : engine.exportPcap()
        let ext = isNg ? "pcapng" : "pcap"
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("sharkmobile_\(Int(Date().timeIntervalSince1970)).\(ext)")
        try? data.write(to: tempURL)

        #if canImport(UIKit)
        let av = UIActivityViewController(activityItems: [tempURL], applicationActivities: nil)
        if let windowScene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first,
           let root = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController ?? windowScene.windows.first?.rootViewController {
            if let popover = av.popoverPresentationController {
                popover.sourceView = root.view
                popover.sourceRect = CGRect(x: root.view.bounds.midX, y: root.view.bounds.midY, width: 0, height: 0)
                popover.permittedArrowDirections = []
            }
            root.present(av, animated: true)
        }
        #endif
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
            if let flag = packet.countryFlag {
                Text(flag)
            }
            Text(packet.info)
                .lineLimit(1)
            Spacer()
        }
        .font(.system(size: 11, design: .monospaced))
        .padding(.vertical, 2)
    }
}

// MARK: - Hex Dump View with Modular Subviews for Instant Compilation
public struct HexDumpView: View {
    public let data: Data
    public let highlightRange: Range<Int>?

    public var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(0..<(data.count + 15) / 16, id: \.self) { row in
                    HexRowView(data: data, rowIndex: row, highlightRange: highlightRange)
                }
            }
            .padding(8)
        }
    }
}

struct HexRowView: View {
    let data: Data
    let rowIndex: Int
    let highlightRange: Range<Int>?

    var body: some View {
        let start = rowIndex * 16
        let end = min(start + 16, data.count)
        let rowData = data.subdata(in: start..<end)
        HStack(spacing: 6) {
            Text(String(format: "%04x", start))
                .foregroundColor(.secondary)

            HStack(spacing: 3) {
                ForEach(0..<16, id: \.self) { col in
                    HexByteCell(data: data, byteIndex: start + col, highlightRange: highlightRange)
                }
            }

            Text(formatAscii(rowData))
                .foregroundColor(.secondary)
                .lineLimit(1)
        }
        .font(.system(size: 10, design: .monospaced))
    }

    private func formatAscii(_ d: Data) -> String {
        return d.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
    }
}

struct HexByteCell: View {
    let data: Data
    let byteIndex: Int
    let highlightRange: Range<Int>?

    var body: some View {
        if byteIndex < data.count {
            let byte = data[byteIndex]
            let isHighlighted = highlightRange?.contains(byteIndex) ?? false
            Text(String(format: "%02x", byte))
                .foregroundColor(isHighlighted ? .accentColor : .primary)
                .font(.system(size: 10, weight: isHighlighted ? .bold : .regular, design: .monospaced))
        } else {
            Text("  ")
        }
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
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { presentationMode.wrappedValue.dismiss() }
                }
            }
        }
    }
}

// MARK: - Platform Compatibility Modifiers
extension View {
    func applyPlatformNavigationInline() -> some View {
        #if os(iOS)
        return self.navigationBarTitleDisplayMode(.inline)
        #else
        return self
        #endif
    }

    func applyPlatformStackNavigation() -> some View {
        #if os(iOS)
        return self.navigationViewStyle(StackNavigationViewStyle())
        #else
        return self
        #endif
    }

    func applyPlatformGroupedList() -> some View {
        #if os(iOS)
        return self.listStyle(InsetGroupedListStyle())
        #else
        return self.listStyle(PlainListStyle())
        #endif
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
