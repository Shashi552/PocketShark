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

        for p in packets {
            let isForward = (p.source == epA && p.destination == epB)
            let isReverse = (p.source == epB && p.destination == epA)

            if isForward || isReverse {
                // Extract application payload beyond TCP/IP headers
                if p.rawData.count > 54 {
                    let payloadData = p.rawData.subdata(in: 54..<p.rawData.count)
                    if !payloadData.isEmpty {
                        let text = String(data: payloadData, encoding: .utf8) ??
                                   payloadData.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
                        let hex = payloadData.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
                        chunks.append(StreamPayloadChunk(isClientToServer: isForward, text: text, hexData: hex))
                    }
                }
            }
        }

        return chunks
    }
}
