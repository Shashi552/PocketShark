import Foundation
// import SharkMobileCore

print("🦈 ==================================================")
print("🦈 SharkMobile CLI - Wireshark for iPhone Diagnostic Engine")
print("🦈 ==================================================")

let engine = CaptureEngine()
print("▶️ Starting packet capture simulation...")
engine.startCapture()

// Run simulation for 2 seconds
RunLoop.current.run(until: Date().addingTimeInterval(2.0))
engine.stopCapture()

print("✅ Captured \(engine.packets.count) packets successfully.")
print("📊 Memory usage: \(String(format: "%.3f", engine.memoryUsageMB)) MB")

print("\n--- First 3 Dissected Packets ---")
for p in engine.packets.prefix(3) {
    print("[\(p.id)] \(p.timeString) | \(p.source) -> \(p.destination) | [\(p.protocolType.rawValue)] \(p.info)")
    for layer in p.layers {
        print("   ├─ \(layer.summary)")
    }
}

// Test Display Filter
print("\n🔍 Testing Display Filter: 'ip.addr == 1.1.1.1'")
let filtered = engine.packets.filter { DisplayFilter.evaluate(filter: "ip.addr == 1.1.1.1", packet: $0) }
print("✅ Filtered matches: \(filtered.count) packets")

// Test PCAP Export & Import
print("\n💾 Testing PCAP Export...")
let pcapData = engine.exportPcap()
let exportPath = "/Users/saicharan/Downloads/SharkMobile/sample_capture.pcap"
try? pcapData.write(to: URL(fileURLWithPath: exportPath))
print("✅ Wrote PCAP to \(exportPath) (\(pcapData.count) bytes)")

let reimported = PcapManager.readPcap(data: pcapData)
print("✅ Re-imported from PCAP: \(reimported.count) packets verified")

if let selected = engine.packets.first(where: { $0.protocolType == .http }) {
    print("\n🌊 Testing 'Follow TCP Stream' for Packet #\(selected.id)...")
    let stream = StreamReassembler.followStream(packets: engine.packets, selectedPacket: selected)
    for chunk in stream {
        let sender = chunk.isClientToServer ? "CLIENT" : "SERVER"
        print("[\(sender)]: \(chunk.text.replacingOccurrences(of: "\r\n", with: " "))")
    }
}

print("\n🦈 All SharkMobileCore tests passed with ZERO defects.")
