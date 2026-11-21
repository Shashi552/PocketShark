import Foundation

public struct StreamPayloadChunk: Identifiable, Hashable {
    public let id = UUID()
    public let isClientToServer: Bool
    public let text: String
    public let hexData: String

    public init(isClientToServer: Bool, text: String, hexData: String) {
        self.isClientToServer = isClientToServer
        self.text = text
        self.hexData = hexData
    }
}

public struct StreamReassembler {
    public static func followStream(packets: [PacketRecord], selectedPacket: PacketRecord) -> [StreamPayloadChunk] {
        let epA = selectedPacket.source
        let epB = selectedPacket.destination

        var chunks: [StreamPayloadChunk] = []
        let maxChunks = 2_000

        for p in packets {
            guard chunks.count < maxChunks else { break }
            let isForward = (p.source == epA && p.destination == epB)
            let isReverse = (p.source == epB && p.destination == epA)

            if isForward || isReverse {
                // Dynamically determine L7 application payload offset beyond TCP/IP headers
                var payloadOffset = 54
                if let tcpLayer = p.layers.first(where: { $0.name.contains("Transmission Control Protocol") }),
                   let range = tcpLayer.byteRange {
                    payloadOffset = range.upperBound
                }

                if p.rawData.count > payloadOffset {
                    let payloadData = p.rawData.subdata(in: payloadOffset..<p.rawData.count)
                    if !payloadData.isEmpty {
                        let text = String(decoding: payloadData, as: UTF8.self)
                        let hex = payloadData.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                        chunks.append(StreamPayloadChunk(isClientToServer: isForward, text: text, hexData: hex))
                    }
                }
            }
        }

        return chunks
    }
}
