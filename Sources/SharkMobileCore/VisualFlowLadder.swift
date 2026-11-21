import Foundation

public struct FlowLadderStep: Identifiable, Hashable {
    public let id = UUID()
    public let stepIndex: Int
    public let timestamp: Double
    public let relativeTimeMs: Double
    public let fromHost: String
    public let toHost: String
    public let isClientToServer: Bool
    public let packetId: Int
    public let summary: String
    public let flags: [String]
    public let seq: UInt32
    public let ack: UInt32
    public let payloadBytes: Int
    public let rttMs: Double?
    public let isRetransmission: Bool
    public let isZeroWindow: Bool
    public let isReset: Bool
}

public struct TCPConversationLadder: Identifiable, Hashable {
    public var id: String { "\(clientHost) <-> \(serverHost)" }
    public let clientHost: String
    public let serverHost: String
    public let clientIP: String
    public let serverIP: String
    public let clientPort: Int
    public let serverPort: Int
    public var steps: [FlowLadderStep]
    public var handshakeRttMs: Double?
    public var ttfbMs: Double?
    public var retransmissionCount: Int
    public var totalBytes: Int
    public var connectionState: String
}

public struct VisualFlowLadder {

    public static func buildLadders(packets: [PacketRecord]) -> [TCPConversationLadder] {
        var ladders: [String: TCPConversationLadder] = [:]
        var seenSeqMap: [String: Set<UInt32>] = [:]

        for p in packets where p.protocolType == .tcp || p.protocolType == .http || p.protocolType == .tls {
            guard let tcpLayer = p.layers.first(where: { $0.name.contains("Transmission Control Protocol") }) else {
                continue
            }

            var srcPort = 0
            var dstPort = 0
            var seq: UInt32 = 0
            var ack: UInt32 = 0
            var flagsStr = ""
            var window = 65535

            for f in tcpLayer.fields {
                if f.name == "Source Port" { srcPort = Int(f.value) ?? 0 }
                if f.name == "Destination Port" { dstPort = Int(f.value) ?? 0 }
                if f.name == "Sequence Number" { seq = UInt32(f.value) ?? 0 }
                if f.name == "Acknowledgment Number" { ack = UInt32(f.value) ?? 0 }
                if f.name == "Flags" { flagsStr = f.value }
                if f.name == "Window Size" { window = Int(f.value) ?? 65535 }
            }

            guard srcPort > 0 && dstPort > 0 else { continue }

            // Determine client vs server by ephemeral port or lowest well-known port
            let convKey: String
            let clientIP: String
            let serverIP: String
            let clientPort: Int
            let serverPort: Int

            if dstPort == 80 || dstPort == 443 || dstPort == 22 || dstPort == 8080 || dstPort == 8443 {
                // Client to Server
                convKey = "\(p.source):\(srcPort)-\(p.destination):\(dstPort)"
                clientIP = p.source
                serverIP = p.destination
                clientPort = srcPort
                serverPort = dstPort
            } else if srcPort == 80 || srcPort == 443 || srcPort == 22 || srcPort == 8080 || srcPort == 8443 {
                // Server to Client
                convKey = "\(p.destination):\(dstPort)-\(p.source):\(srcPort)"
                clientIP = p.destination
                serverIP = p.source
                clientPort = dstPort
                serverPort = srcPort
            } else {
                // Arbitrary ports: order canonically
                let key1 = "\(p.source):\(srcPort)"
                let key2 = "\(p.destination):\(dstPort)"
                if key1 < key2 {
                    convKey = "\(key1)-\(key2)"
                    clientIP = p.source
                    serverIP = p.destination
                    clientPort = srcPort
                    serverPort = dstPort
                } else {
                    convKey = "\(key2)-\(key1)"
                    clientIP = p.destination
                    serverIP = p.source
                    clientPort = dstPort
                    serverPort = srcPort
                }
            }

            var ladder = ladders[convKey] ?? TCPConversationLadder(
                clientHost: "\(clientIP):\(clientPort)",
                serverHost: "\(serverIP):\(serverPort)",
                clientIP: clientIP,
                serverIP: serverIP,
                clientPort: clientPort,
                serverPort: serverPort,
                steps: [],
                handshakeRttMs: nil,
                ttfbMs: nil,
                retransmissionCount: 0,
                totalBytes: 0,
                connectionState: "INIT"
            )

            // Flags parsing
            var flagList: [String] = []
            if flagsStr.contains("SYN") { flagList.append("SYN") }
            if flagsStr.contains("ACK") { flagList.append("ACK") }
            if flagsStr.contains("FIN") { flagList.append("FIN") }
            if flagsStr.contains("RST") { flagList.append("RST") }
            if flagsStr.contains("PSH") { flagList.append("PSH") }

            let isReset = flagList.contains("RST")
            let isZeroWindow = window == 0

            // Retransmission check
            var seenSeq = seenSeqMap[convKey] ?? Set<UInt32>()
            let isRetransmission = seq > 0 && seenSeq.contains(seq) && !flagList.contains("ACK")
            if !isRetransmission && seq > 0 {
                seenSeq.insert(seq)
                seenSeqMap[convKey] = seenSeq
            }

            let firstTs = ladder.steps.first?.timestamp ?? p.timestamp
            let relativeMs = (p.timestamp - firstTs) * 1000.0

            // Latency / RTT calculation
            var rtt: Double? = nil
            if let prev = ladder.steps.last {
                if prev.isClientToServer != (p.source == clientIP) {
                    let deltaMs = (p.timestamp - prev.timestamp) * 1000.0
                    if deltaMs >= 0 && deltaMs < 10000.0 {
                        rtt = deltaMs
                    }
                }
            }

            // Connection state transitions
            if flagList.contains("SYN") && !flagList.contains("ACK") {
                ladder.connectionState = "SYN SENT"
            } else if flagList.contains("SYN") && flagList.contains("ACK") {
                ladder.connectionState = "SYN/ACK RECEIVED"
            } else if flagList.contains("ACK") && ladder.connectionState == "SYN/ACK RECEIVED" {
                ladder.connectionState = "ESTABLISHED"
                if ladder.handshakeRttMs == nil, let initialSyn = ladder.steps.first(where: { $0.flags.contains("SYN") }) {
                    ladder.handshakeRttMs = (p.timestamp - initialSyn.timestamp) * 1000.0
                }
            } else if flagList.contains("FIN") {
                ladder.connectionState = "CLOSING (FIN)"
            } else if isReset {
                ladder.connectionState = "ABORTED (RST)"
            }

            // TTFB (Time to First Byte)
            if ladder.ttfbMs == nil && (p.info.contains("200 OK") || p.info.contains("TLS Server Hello")) {
                if let req = ladder.steps.first(where: { $0.summary.contains("GET") || $0.summary.contains("Client Hello") }) {
                    ladder.ttfbMs = (p.timestamp - req.timestamp) * 1000.0
                }
            }

            if isRetransmission {
                ladder.retransmissionCount += 1
            }
            ladder.totalBytes += p.length

            let step = FlowLadderStep(
                stepIndex: ladder.steps.count + 1,
                timestamp: p.timestamp,
                relativeTimeMs: relativeMs,
                fromHost: "\(p.source):\(srcPort)",
                toHost: "\(p.destination):\(dstPort)",
                isClientToServer: (p.source == clientIP),
                packetId: p.id,
                summary: p.info,
                flags: flagList,
                seq: seq,
                ack: ack,
                payloadBytes: p.length,
                rttMs: rtt,
                isRetransmission: isRetransmission,
                isZeroWindow: isZeroWindow,
                isReset: isReset
            )

            ladder.steps.append(step)
            ladders[convKey] = ladder
        }

        return Array(ladders.values).sorted { $0.steps.count > $1.steps.count }
    }
}
