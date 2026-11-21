import Foundation

public struct PcapManager {
    private static let PCAP_MAGIC: UInt32 = 0xa1b2c3d4
    private static let PCAP_VERSION_MAJOR: UInt16 = 2
    private static let PCAP_VERSION_MINOR: UInt16 = 4

    public static func writePcap(packets: [PacketRecord]) -> Data {
        var data = Data()

        // 24-byte PCAP Global Header
        var magic = PCAP_MAGIC
        var vMajor = PCAP_VERSION_MAJOR
        var vMinor = PCAP_VERSION_MINOR
        var thiszone: Int32 = 0
        var sigfigs: UInt32 = 0
        var snaplen: UInt32 = 65535
        var linktype: UInt32 = 1 // LINKTYPE_ETHERNET

        withUnsafeBytes(of: &magic) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &vMajor) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &vMinor) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &thiszone) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &sigfigs) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &snaplen) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &linktype) { data.append(contentsOf: $0) }

        // Packet Records
        for p in packets {
            let secs = UInt32(p.timestamp)
            let usecs = UInt32((p.timestamp - Double(secs)) * 1_000_000)
            let len = UInt32(p.rawData.count)

            var s = secs
            var u = usecs
            var l = len
            var o = len

            withUnsafeBytes(of: &s) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &u) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &l) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &o) { data.append(contentsOf: $0) }
            data.append(p.rawData)
        }

        return data
    }

    public static func readPcap(data: Data) -> [PacketRecord] {
        guard data.count >= 24 else { return [] }
        var offset = 24
        var packets: [PacketRecord] = []
        var packetId = 1

        while offset + 16 <= data.count {
            let tsSec = data.subdata(in: offset..<offset + 4).withUnsafeBytes { $0.load(as: UInt32.self) }
            let tsUsec = data.subdata(in: offset + 4..<offset + 8).withUnsafeBytes { $0.load(as: UInt32.self) }
            let inclLen = Int(data.subdata(in: offset + 8..<offset + 12).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 16

            if offset + inclLen <= data.count {
                let rawPacket = data.subdata(in: offset..<offset + inclLen)
                let timestamp = Double(tsSec) + (Double(tsUsec) / 1_000_000.0)
                let record = PacketDissector.dissect(packetId: packetId, timestamp: timestamp, rawData: rawPacket)
                packets.append(record)
                packetId += 1
                offset += inclLen
            } else {
                break
            }
        }
        return packets
    }
}
