import Foundation

public struct StreamPayloadChunk: Identifiable, Hashable {
    public let id = UUID()
    public let isClientToServer: Bool
    public let text: String
    public let hexData: String
    public let sequenceNumber: UInt32

    public init(isClientToServer: Bool, text: String, hexData: String, sequenceNumber: UInt32 = 0) {
        self.isClientToServer = isClientToServer
        self.text = text
        self.hexData = hexData
        self.sequenceNumber = sequenceNumber
    }
}

public struct StreamReassembler {
    public static func followStream(packets: [PacketRecord], selectedPacket: PacketRecord) -> [StreamPayloadChunk] {
        let epA = selectedPacket.source
        let epB = selectedPacket.destination

        let (selSrcPort, selDstPort) = extractPorts(packet: selectedPacket)

        var rawChunks: [(chunk: StreamPayloadChunk, seq: UInt32, time: Double)] = []
        let maxChunks = 2_000

        for p in packets {
            guard rawChunks.count < maxChunks else { break }
            let (pSrcPort, pDstPort) = extractPorts(packet: p)

            let isForward: Bool
            let isReverse: Bool

            if selSrcPort > 0 && selDstPort > 0 && pSrcPort > 0 && pDstPort > 0 {
                isForward = (p.source == epA && p.destination == epB && pSrcPort == selSrcPort && pDstPort == selDstPort)
                isReverse = (p.source == epB && p.destination == epA && pSrcPort == selDstPort && pDstPort == selSrcPort)
            } else {
                isForward = (p.source == epA && p.destination == epB)
                isReverse = (p.source == epB && p.destination == epA)
            }

            if isForward || isReverse {
                var payloadOffset = 54
                var seq: UInt32 = 0
                if let tcpLayer = p.layers.first(where: { $0.name.contains("Transmission Control Protocol") }) {
                    if let range = tcpLayer.byteRange {
                        payloadOffset = range.upperBound
                    }
                    if let seqField = tcpLayer.fields.first(where: { $0.name == "Sequence Number" }) {
                        seq = UInt32(seqField.value) ?? 0
                    }
                }

                if p.rawData.count > payloadOffset {
                    let payloadData = p.rawData.subdata(in: payloadOffset..<p.rawData.count)
                    if !payloadData.isEmpty {
                        let text = String(decoding: payloadData, as: UTF8.self)
                        let hex = payloadData.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                        let chunk = StreamPayloadChunk(isClientToServer: isForward, text: text, hexData: hex, sequenceNumber: seq)
                        rawChunks.append((chunk: chunk, seq: seq, time: p.timestamp))
                    }
                }
            }
        }

        // Return ordered stream chunks
        return rawChunks.map { $0.chunk }
    }

    private static func extractPorts(packet: PacketRecord) -> (src: Int, dst: Int) {
        guard let tcpLayer = packet.layers.first(where: { $0.name.contains("Transmission Control Protocol") || $0.name.contains("User Datagram Protocol") }) else {
            return (0, 0)
        }
        var src = 0
        var dst = 0
        for f in tcpLayer.fields {
            if f.name == "Source Port" { src = Int(f.value) ?? 0 }
            if f.name == "Destination Port" { dst = Int(f.value) ?? 0 }
        }
        return (src, dst)
    }
}
