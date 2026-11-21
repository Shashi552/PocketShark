import Foundation

public struct PacketDissector {
    public static func dissect(packetId: Int, timestamp: Double, rawData: Data, interface: String = "en0 (Wi-Fi)") -> PacketRecord {
        var offset = 0
        var layers: [DissectedLayer] = []
        var src = "Unknown"
        var dst = "Unknown"
        var proto: ProtocolType = .unknown
        var info = "Raw Packet Data (\(rawData.count) bytes)"

        // Frame Layer
        layers.append(DissectedLayer(
            name: "Frame \(packetId)",
            summary: "Frame \(packetId): \(rawData.count) bytes on wire, captured on interface \(interface)",
            fields: [
                FieldDetail(name: "Arrival Time", value: String(format: "%.6f", timestamp)),
                FieldDetail(name: "Interface", value: interface),
                FieldDetail(name: "Frame Length", value: "\(rawData.count) bytes"),
                FieldDetail(name: "Capture Length", value: "\(rawData.count) bytes")
            ],
            byteRange: 0..<rawData.count
        ))

        // Check for BLE Pseudo-Header
        if rawData.count >= 8 && rawData[0] == 0x42 && rawData[1] == 0x4C && rawData[2] == 0x45 { // "BLE" magic
            proto = .ble
            src = "BLE Adv Radio"
            dst = "Broadcast (FF:FF:FF:FF:FF:FF)"
            let rssi = Int8(bitPattern: rawData[3])
            let mfgData = rawData.subdata(in: 4..<rawData.count)
            let mfgHex = mfgData.map { String(format: "%02X", $0) }.joined(separator: " ")
            var continuity = "Unknown Manufacturer Data"
            if mfgData.count >= 2 && mfgData[0] == 0x4C && mfgData[1] == 0x00 {
                if mfgData.count > 2 {
                    switch mfgData[2] {
                    case 0x07: continuity = "Apple AirPods Proximity Pairing"
                    case 0x09: continuity = "Apple AirDrop Beacon"
                    case 0x10: continuity = "Apple Handoff / Nearby Action"
                    case 0x12: continuity = "Apple FindMy / AirTag Tracker Beacon"
                    case 0x0D: continuity = "AppleTV / HomePod Proximity Setup"
                    default: continuity = String(format: "Apple Continuity (0x%02X)", mfgData[2])
                    }
                }
            }
            info = "BLE ADV_NONCONN_IND [\(continuity)] RSSI=\(rssi) dBm"
            layers.append(DissectedLayer(
                name: "Bluetooth Low Energy Link Layer",
                summary: info,
                fields: [
                    FieldDetail(name: "Access Address", value: "0x8E89BED6 (Advertising Channel)", byteRange: 0..<4),
                    FieldDetail(name: "Signal Strength (RSSI)", value: "\(rssi) dBm", byteRange: 3..<4),
                    FieldDetail(name: "Continuity Classification", value: continuity),
                    FieldDetail(name: "Raw Manufacturer Payload", value: mfgHex, byteRange: 4..<rawData.count)
                ],
                byteRange: 0..<rawData.count
            ))
            return PacketRecord(id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto, length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface)
        }

        if rawData.count < 14 {
            return PacketRecord(id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto, length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface)
        }

        // Ethernet II vs Raw IP detection
        let isEthernet = (rawData[12] == 0x08 && rawData[13] == 0x00) || (rawData[12] == 0x86 && rawData[13] == 0xDD) || (rawData[12] == 0x08 && rawData[13] == 0x06)
        
        if isEthernet {
            let ethSrc = formatMAC(rawData.subdata(in: 6..<12))
            let ethDst = formatMAC(rawData.subdata(in: 0..<6))
            let etherType = UInt16(rawData[12]) << 8 | UInt16(rawData[13])
            layers.append(DissectedLayer(
                name: "Ethernet II",
                summary: "Ethernet II, Src: \(ethSrc), Dst: \(ethDst)",
                fields: [
                    FieldDetail(name: "Destination MAC", value: ethDst, byteRange: 0..<6),
                    FieldDetail(name: "Source MAC", value: ethSrc, byteRange: 6..<12),
                    FieldDetail(name: "Type", value: String(format: "0x%04X", etherType), byteRange: 12..<14)
                ],
                byteRange: 0..<14
            ))
            offset = 14

            if etherType == 0x0806 && rawData.count >= offset + 28 { // ARP
                proto = .arp
                let hwType = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                let protoType = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                let opcode = Int(rawData[offset + 6]) << 8 | Int(rawData[offset + 7])
                let senderMAC = formatMAC(rawData.subdata(in: offset + 8..<offset + 14))
                let senderIP = formatIPv4(rawData.subdata(in: offset + 14..<offset + 18))
                let targetMAC = formatMAC(rawData.subdata(in: offset + 18..<offset + 24))
                let targetIP = formatIPv4(rawData.subdata(in: offset + 24..<offset + 28))

                src = senderIP
                dst = targetIP
                let opStr = opcode == 1 ? "Who has \(targetIP)? Tell \(senderIP)" : "\(senderIP) is at \(senderMAC)"
                info = "ARP: \(opStr)"
                layers.append(DissectedLayer(
                    name: "Address Resolution Protocol (\(opcode == 1 ? "request" : "reply"))",
                    summary: info,
                    fields: [
                        FieldDetail(name: "Hardware Type", value: "\(hwType)", byteRange: offset..<offset + 2),
                        FieldDetail(name: "Protocol Type", value: String(format: "0x%04x", protoType), byteRange: offset + 2..<offset + 4),
                        FieldDetail(name: "Opcode", value: opcode == 1 ? "request (1)" : "reply (2)", byteRange: offset + 6..<offset + 8),
                        FieldDetail(name: "Sender MAC Address", value: senderMAC, byteRange: offset + 8..<offset + 14),
                        FieldDetail(name: "Sender IP Address", value: senderIP, byteRange: offset + 14..<offset + 18),
                        FieldDetail(name: "Target MAC Address", value: targetMAC, byteRange: offset + 18..<offset + 24),
                        FieldDetail(name: "Target IP Address", value: targetIP, byteRange: offset + 24..<offset + 28)
                    ],
                    byteRange: offset..<offset + 28
                ))
                return PacketRecord(id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto, length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface)
            }
        } else {
            offset = 0
        }

        if offset >= rawData.count {
            return PacketRecord(id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto, length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface)
        }

        let ipVersion = (rawData[offset] >> 4) & 0x0F
        if ipVersion == 4 && rawData.count >= offset + 20 {
            proto = .ipv4
            let ipStart = offset
            let ihl = Int(rawData[offset] & 0x0F) * 4
            let totalLen = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
            let id = Int(rawData[offset + 4]) << 8 | Int(rawData[offset + 5])
            let ttl = Int(rawData[offset + 8])
            let ipProto = rawData[offset + 9]
            src = formatIPv4(rawData.subdata(in: offset + 12..<offset + 16))
            dst = formatIPv4(rawData.subdata(in: offset + 16..<offset + 20))

            layers.append(DissectedLayer(
                name: "Internet Protocol Version 4",
                summary: "IPv4, Src: \(src), Dst: \(dst)",
                fields: [
                    FieldDetail(name: "Version", value: "4", byteRange: ipStart..<ipStart + 1),
                    FieldDetail(name: "Header Length", value: "\(ihl) bytes (\(ihl/4))", byteRange: ipStart..<ipStart + 1),
                    FieldDetail(name: "Total Length", value: "\(totalLen)", byteRange: ipStart + 2..<ipStart + 4),
                    FieldDetail(name: "Identification", value: String(format: "0x%04x (%d)", id, id), byteRange: ipStart + 4..<ipStart + 6),
                    FieldDetail(name: "Time to Live", value: "\(ttl)", byteRange: ipStart + 8..<ipStart + 9),
                    FieldDetail(name: "Protocol", value: "\(ipProto)", byteRange: ipStart + 9..<ipStart + 10),
                    FieldDetail(name: "Source Address", value: src, byteRange: ipStart + 12..<ipStart + 16),
                    FieldDetail(name: "Destination Address", value: dst, byteRange: ipStart + 16..<ipStart + 20)
                ],
                byteRange: ipStart..<ipStart + ihl
            ))

            offset += ihl

            // Transport Layer
            if ipProto == 6 && rawData.count >= offset + 20 { // TCP
                proto = .tcp
                let tcpStart = offset
                let srcPort = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                let dstPort = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                let seq = UInt32(rawData[offset + 4]) << 24 | UInt32(rawData[offset + 5]) << 16 | UInt32(rawData[offset + 6]) << 8 | UInt32(rawData[offset + 7])
                let ack = UInt32(rawData[offset + 8]) << 24 | UInt32(rawData[offset + 9]) << 16 | UInt32(rawData[offset + 10]) << 8 | UInt32(rawData[offset + 11])
                let dataOffset = Int((rawData[offset + 12] >> 4) & 0x0F) * 4
                let flags = rawData[offset + 13]
                let window = Int(rawData[offset + 14]) << 8 | Int(rawData[offset + 15])

                var flagList: [String] = []
                if (flags & 0x02) != 0 { flagList.append("SYN") }
                if (flags & 0x10) != 0 { flagList.append("ACK") }
                if (flags & 0x01) != 0 { flagList.append("FIN") }
                if (flags & 0x04) != 0 { flagList.append("RST") }
                if (flags & 0x08) != 0 { flagList.append("PSH") }
                let flagSummary = flagList.joined(separator: ", ")

                info = "\(srcPort) → \(dstPort) [\(flagSummary)] Seq=\(seq) Ack=\(ack) Win=\(window)"

                layers.append(DissectedLayer(
                    name: "Transmission Control Protocol",
                    summary: "TCP, Src Port: \(srcPort), Dst Port: \(dstPort), Seq: \(seq), Ack: \(ack)",
                    fields: [
                        FieldDetail(name: "Source Port", value: "\(srcPort)", byteRange: tcpStart..<tcpStart + 2),
                        FieldDetail(name: "Destination Port", value: "\(dstPort)", byteRange: tcpStart + 2..<tcpStart + 4),
                        FieldDetail(name: "Sequence Number", value: "\(seq)", byteRange: tcpStart + 4..<tcpStart + 8),
                        FieldDetail(name: "Acknowledgment Number", value: "\(ack)", byteRange: tcpStart + 8..<tcpStart + 12),
                        FieldDetail(name: "Flags", value: String(format: "0x%03x [\(flagSummary)]", flags), byteRange: tcpStart + 12..<tcpStart + 14),
                        FieldDetail(name: "Window Size", value: "\(window)", byteRange: tcpStart + 14..<tcpStart + 16)
                    ],
                    byteRange: tcpStart..<tcpStart + dataOffset
                ))

                offset += dataOffset

                // L7 Detection
                if offset < rawData.count {
                    let payload = rawData.subdata(in: offset..<rawData.count)
                    if payload.count >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
                        proto = .tls
                        let tlsVer = String(format: "0x%02x%02x", payload[1], payload[2])
                        let tlsLen = Int(payload[3]) << 8 | Int(payload[4])
                        var tlsInfo = "TLS Record Layer: Handshake Protocol"
                        var tlsFields = [
                            FieldDetail(name: "Content Type", value: "Handshake (22)", byteRange: offset..<offset + 1),
                            FieldDetail(name: "Version", value: tlsVer, byteRange: offset + 1..<offset + 3),
                            FieldDetail(name: "Length", value: "\(tlsLen)", byteRange: offset + 3..<offset + 5)
                        ]
                        if payload.count >= 9 && payload[5] == 0x01 {
                            tlsInfo = "TLS Client Hello"
                            if let sni = extractSNI(payload: payload) {
                                tlsInfo += " (SNI=\(sni))"
                                tlsFields.append(FieldDetail(name: "Server Name Indication", value: sni))
                            }
                        } else if payload.count >= 9 && payload[5] == 0x02 {
                            tlsInfo = "TLS Server Hello"
                        }
                        info = "\(srcPort) → \(dstPort) \(tlsInfo)"
                        layers.append(DissectedLayer(name: "Transport Layer Security", summary: tlsInfo, fields: tlsFields, byteRange: offset..<rawData.count))
                    } else if srcPort == 22 || dstPort == 22 {
                        proto = .ssh
                        info = "SSH Protocol Packet"
                        if let banner = String(data: payload.prefix(min(payload.count, 64)), encoding: .utf8), banner.hasPrefix("SSH-") {
                            info = "SSH Identification: \(banner.trimmingCharacters(in: .whitespacesAndNewlines))"
                        }
                        layers.append(DissectedLayer(name: "Secure Shell Protocol", summary: info, fields: [FieldDetail(name: "SSH Payload", value: "\(payload.count) bytes")], byteRange: offset..<rawData.count))
                    } else if let httpStr = String(data: payload.prefix(min(payload.count, 2048)), encoding: .utf8),
                              httpStr.hasPrefix("GET ") || httpStr.hasPrefix("POST ") || httpStr.hasPrefix("HTTP/1.") || httpStr.hasPrefix("PUT ") {
                        proto = .http
                        let firstLine = httpStr.components(separatedBy: "\r\n").first ?? ""
                        info = firstLine
                        layers.append(DissectedLayer(
                            name: "Hypertext Transfer Protocol",
                            summary: firstLine,
                            fields: [FieldDetail(name: "Request / Status Line", value: firstLine, byteRange: offset..<offset + min(firstLine.count, payload.count))],
                            byteRange: offset..<rawData.count
                        ))
                    }
                }
            } else if ipProto == 17 && rawData.count >= offset + 8 { // UDP
                proto = .udp
                let udpStart = offset
                let srcPort = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                let dstPort = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                let udpLen = Int(rawData[offset + 4]) << 8 | Int(rawData[offset + 5])

                info = "\(srcPort) → \(dstPort) Len=\(udpLen)"
                layers.append(DissectedLayer(
                    name: "User Datagram Protocol",
                    summary: "UDP, Src Port: \(srcPort), Dst Port: \(dstPort)",
                    fields: [
                        FieldDetail(name: "Source Port", value: "\(srcPort)", byteRange: udpStart..<udpStart + 2),
                        FieldDetail(name: "Destination Port", value: "\(dstPort)", byteRange: udpStart + 2..<udpStart + 4),
                        FieldDetail(name: "Length", value: "\(udpLen)", byteRange: udpStart + 4..<udpStart + 6)
                    ],
                    byteRange: udpStart..<udpStart + 8
                ))

                offset += 8

                if (srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353) && rawData.count >= offset + 12 {
                    proto = .dns
                    let dnsStart = offset
                    let txId = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                    let dnsFlags = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                    let isResponse = (dnsFlags & 0x8000) != 0
                    let qName = extractDNSQueryName(rawData: rawData, startOffset: offset + 12)
                    let protoLabel = (srcPort == 5353 || dstPort == 5353) ? "mDNS" : "DNS"
                    info = "\(protoLabel) \(isResponse ? "response" : "query") 0x\(String(format: "%04x", txId)) \(qName)"
                    layers.append(DissectedLayer(
                        name: "Domain Name System (\(protoLabel))",
                        summary: info,
                        fields: [
                            FieldDetail(name: "Transaction ID", value: String(format: "0x%04x", txId), byteRange: dnsStart..<dnsStart + 2),
                            FieldDetail(name: "Flags", value: String(format: "0x%04x", dnsFlags), byteRange: dnsStart + 2..<dnsStart + 4),
                            FieldDetail(name: "Queried Domain", value: qName)
                        ],
                        byteRange: dnsStart..<rawData.count
                    ))
                } else if srcPort == 1900 || dstPort == 1900 {
                    proto = .ssdp
                    info = "SSDP Discovery M-SEARCH / NOTIFY"
                    layers.append(DissectedLayer(name: "Simple Service Discovery Protocol", summary: info, fields: [FieldDetail(name: "Port", value: "1900 (Multicast)")], byteRange: offset..<rawData.count))
                } else if srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68 {
                    proto = .dhcp
                    info = "DHCP / BOOTP Dynamic Host Configuration"
                    layers.append(DissectedLayer(name: "Dynamic Host Configuration Protocol", summary: info, fields: [FieldDetail(name: "Port", value: "67/68")], byteRange: offset..<rawData.count))
                } else if (srcPort == 443 || dstPort == 443) && rawData.count > offset + 4 {
                    proto = .quic
                    info = "QUIC / HTTP3 UDP Transport"
                    layers.append(DissectedLayer(name: "QUIC Transport Protocol", summary: info, fields: [FieldDetail(name: "Destination Port", value: "\(dstPort)")], byteRange: offset..<rawData.count))
                }
            } else if ipProto == 1 { // ICMP
                proto = .icmp
                let icmpType = rawData[offset]
                let icmpCode = rawData[offset + 1]
                info = "Echo (ping) \(icmpType == 8 ? "request" : "reply") id=0x\(String(format: "%02x", rawData[offset + 4]))"
                layers.append(DissectedLayer(
                    name: "Internet Control Message Protocol",
                    summary: info,
                    fields: [
                        FieldDetail(name: "Type", value: "\(icmpType)", byteRange: offset..<offset + 1),
                        FieldDetail(name: "Code", value: "\(icmpCode)", byteRange: offset + 1..<offset + 2)
                    ],
                    byteRange: offset..<rawData.count
                ))
            }
        }

        return PacketRecord(
            id: packetId,
            timestamp: timestamp,
            source: src,
            destination: dst,
            protocolType: proto,
            length: rawData.count,
            info: info,
            rawData: rawData,
            layers: layers,
            interface: interface
        )
    }

    private static func formatMAC(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    private static func formatIPv4(_ data: Data) -> String {
        return data.map { "\($0)" }.joined(separator: ".")
    }

    private static func extractSNI(payload: Data) -> String? {
        guard payload.count > 43 else { return nil }
        for i in 40..<(payload.count - 5) {
            if payload[i] == 0x00 && payload[i + 1] == 0x00 {
                let extLen = Int(payload[i + 2]) << 8 | Int(payload[i + 3])
                if i + 4 + extLen <= payload.count && extLen > 3 {
                    let nameLen = Int(payload[i + 7]) << 8 | Int(payload[i + 8])
                    if i + 9 + nameLen <= payload.count {
                        let nameData = payload.subdata(in: (i + 9)..<(i + 9 + nameLen))
                        return String(data: nameData, encoding: .utf8)
                    }
                }
            }
        }
        return nil
    }

    private static func extractDNSQueryName(rawData: Data, startOffset: Int) -> String {
        var idx = startOffset
        var parts: [String] = []
        while idx < rawData.count {
            let len = Int(rawData[idx])
            if len == 0 || (len & 0xC0) != 0 { break }
            idx += 1
            if idx + len <= rawData.count {
                if let part = String(data: rawData.subdata(in: idx..<idx + len), encoding: .utf8) {
                    parts.append(part)
                }
                idx += len
            } else { break }
        }
        return parts.isEmpty ? "unknown.domain" : parts.joined(separator: ".")
    }
}
