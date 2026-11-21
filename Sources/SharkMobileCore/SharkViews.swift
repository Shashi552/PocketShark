import SwiftUI

#if canImport(UIKit)
import UIKit
#endif

public struct SharkMobileMainView: View {
    @StateObject private var engine = CaptureEngine()
    @State private var filterText: String = ""
    @State private var selectedPacket: PacketRecord? = nil
    @State private var selectedField: FieldDetail? = nil
    @State private var showingFollowStream: Bool = false
    @State private var showingStats: Bool = false

    public init() {}

    private var filteredPackets: [PacketRecord] {
        if filterText.isEmpty {
            return engine.packets
        }
        return engine.packets.filter { DisplayFilter.evaluate(filter: filterText, packet: $0) }
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Header / Toolbar
            HStack(spacing: 12) {
                Button(action: {
                    if engine.isCapturing {
                        engine.stopCapture()
                    } else {
                        engine.startCapture()
                    }
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: engine.isCapturing ? "stop.fill" : "play.fill")
                            .foregroundColor(engine.isCapturing ? .red : .green)
                        Text(engine.isCapturing ? "Stop" : "Capture")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.secondary.opacity(0.15))
                    .cornerRadius(6)
                }

                Button(action: { engine.clear() }) {
                    Image(systemName: "trash")
                        .font(.system(size: 13))
                }

                // Filter Bar
                HStack {
                    Image(systemName: "line.3.horizontal.decrease.circle")
                        .foregroundColor(.secondary)
                    TextField("Apply display filter (e.g. ip.addr == 192.168.63.64, tcp.port == 443)", text: $filterText)
                        .font(.system(size: 12, design: .monospaced))
                    if !filterText.isEmpty {
                        Button(action: { filterText = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .padding(6)
                .background(Color.secondary.opacity(0.1))
                .cornerRadius(6)

                // Actions
                Menu {
                    Button(action: { showingStats = true }) {
                        Label("Protocol Statistics", systemImage: "chart.bar.xaxis")
                    }
                    Button(action: { exportAndSharePcap() }) {
                        Label("Export .pcap to Mac", systemImage: "square.and.arrow.up")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.system(size: 16))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.05))

            Divider()

            // Pane 1: Packet List View
            List(filteredPackets, selection: $selectedPacket) { packet in
                PacketRowView(packet: packet, isSelected: selectedPacket?.id == packet.id)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        selectedPacket = packet
                        selectedField = nil
                    }
                    .contextMenu {
                        if packet.protocolType == .tcp || packet.protocolType == .http {
                            Button("Follow TCP Stream") {
                                selectedPacket = packet
                                showingFollowStream = true
                            }
                        }
                    }
                    .listRowInsets(EdgeInsets(top: 2, leading: 6, bottom: 2, trailing: 6))
                    .listRowBackground(Color(hex: packet.protocolType.colorHex).opacity(0.65))
            }
            .listStyle(.plain)
            .frame(minHeight: 180, maxHeight: .infinity)

            Divider()

            // Pane 2: Packet Details Tree
            if let packet = selectedPacket {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(packet.layers) { layer in
                            DisclosureGroup(
                                isExpanded: .constant(true),
                                content: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        ForEach(layer.fields) { field in
                                            HStack {
                                                Text(field.name + ":")
                                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                                    .foregroundColor(.secondary)
                                                Text(field.value)
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundColor(.primary)
                                                Spacer()
                                            }
                                            .padding(.vertical, 1)
                                            .background(selectedField?.id == field.id ? Color.accentColor.opacity(0.2) : Color.clear)
                                            .onTapGesture {
                                                selectedField = field
                                            }
                                        }
                                    }
                                    .padding(.leading, 12)
                                },
                                label: {
                                    Text(layer.summary)
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(.primary)
                                }
                            )
                            Divider()
                        }
                    }
                    .padding(8)
                }
                .frame(minHeight: 140, maxHeight: 220)
                .background(Color.secondary.opacity(0.04))

                Divider()

                // Pane 3: Hex & ASCII Inspector
                HexDumpView(data: packet.rawData, highlightRange: selectedField?.byteRange)
                    .frame(height: 120)
                    .background(Color.black.opacity(0.03))
            }

            // Bottom Status Bar
            HStack {
                Text("Packets: \(engine.capturedCount)  |  Displayed: \(filteredPackets.count)  |  Dropped: \(engine.droppedCount)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                Spacer()
                Text("Memory: \(String(format: "%.2f", engine.memoryUsageMB)) MB / 12.0 MB Max")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(engine.memoryUsageMB > 10.0 ? .red : .secondary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Color.secondary.opacity(0.08))
        }
        .sheet(isPresented: $showingFollowStream) {
            if let packet = selectedPacket {
                FollowStreamView(packets: engine.packets, selectedPacket: packet)
            }
        }
        .sheet(isPresented: $showingStats) {
            StatisticsView(packets: engine.packets)
        }
    }

    private func exportAndSharePcap() {
        let data = engine.exportPcap()
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("capture_\(Int(Date().timeIntervalSince1970)).pcap")
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

// Packet Row View
public struct PacketRowView: View {
    public let packet: PacketRecord
    public let isSelected: Bool

    public var body: some View {
        HStack(spacing: 8) {
            Text("\(packet.id)")
                .frame(width: 35, alignment: .leading)
            Text(packet.timeString)
                .frame(width: 80, alignment: .leading)
            Text(packet.source)
                .frame(width: 110, alignment: .leading)
            Text(packet.destination)
                .frame(width: 110, alignment: .leading)
            Text(packet.protocolType.rawValue)
                .frame(width: 45, alignment: .center)
                .font(.system(size: 11, weight: .bold))
            Text("\(packet.length)")
                .frame(width: 40, alignment: .trailing)
            Text(packet.info)
                .lineLimit(1)
            Spacer()
        }
        .font(.system(size: 11, design: .monospaced))
        .padding(.vertical, 2)
    }
}

// Hex Dump View
public struct HexDumpView: View {
    public let data: Data
    public let highlightRange: Range<Int>?

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                ForEach(0..<(data.count + 15) / 16, id: \.self) { row in
                    let start = row * 16
                    let end = min(start + 16, data.count)
                    let rowData = data.subdata(in: start..<end)

                    HStack(spacing: 8) {
                        // Offset
                        Text(String(format: "%04x", start))
                            .foregroundColor(.secondary)
                        
                        // Hex bytes
                        HStack(spacing: 4) {
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

                        // ASCII representation
                        Text(formatAscii(rowData))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    .font(.system(size: 10, design: .monospaced))
                }
            }
            .padding(6)
        }
    }

    private func formatAscii(_ d: Data) -> String {
        return d.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
    }
}

// Follow TCP Stream View
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
                            .padding(4)
                            .background(Color.secondary.opacity(0.05))
                            .cornerRadius(4)
                    }
                }
                .padding()
            }
            .navigationTitle("Follow TCP Stream")
            .navigationBarItems(trailing: Button("Done") { presentationMode.wrappedValue.dismiss() })
        }
    }
}

// Statistics View
public struct StatisticsView: View {
    public let packets: [PacketRecord]
    @Environment(\.presentationMode) var presentationMode

    public var body: some View {
        NavigationView {
            List {
                Section(header: Text("Protocol Hierarchy")) {
                    let total = max(1, packets.count)
                    ForEach(ProtocolType.allCases, id: \.self) { proto in
                        let count = packets.filter { $0.protocolType == proto }.count
                        if count > 0 {
                            HStack {
                                Text(proto.rawValue)
                                    .font(.system(size: 13, weight: .bold, design: .monospaced))
                                Spacer()
                                Text("\(count) pkts (\(Int(Double(count)/Double(total)*100))%)")
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Capture Statistics")
            .navigationBarItems(trailing: Button("Done") { presentationMode.wrappedValue.dismiss() })
        }
    }
}

// Helper Extension for Hex Colors
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
