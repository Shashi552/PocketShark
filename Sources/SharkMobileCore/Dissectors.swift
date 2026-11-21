import Foundation

public struct PacketDissector {
    public static func dissect(packetId: Int, timestamp: Double, rawData: Data, interface: String = "en0 (Wi-Fi)") -> PacketRecord {
        var offset = 0
        var layers: [DissectedLayer] = []
        var src = "Unknown"
        var dst = "Unknown"
        var proto: ProtocolType = .unknown
        var info = "Raw Packet Data (\(rawData.count) bytes)"
        var expert: ExpertInfo? = nil
        var geoFlag: String? = nil
        var geoCountry: String? = nil
        var geoAsn: String? = nil

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
            expert = ExpertInfo(severity: .chat, message: "Bluetooth Low Energy Advertisement Beacon", group: "BLE")
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
            return PacketRecord(
                id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto,
                length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface,
                expertInfo: expert
            )
        }

        if rawData.count < 14 {
            expert = ExpertInfo(severity: .error, message: "Truncated short frame (< 14 bytes)", group: "Frame")
            return PacketRecord(
                id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto,
                length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface,
                expertInfo: expert
            )
        }

        // Ethernet II vs Raw IP detection
        let rawEtherType = UInt16(rawData[12]) << 8 | UInt16(rawData[13])
        let isEthernet = (rawEtherType == 0x0800 || rawEtherType == 0x86DD || rawEtherType == 0x0806 || rawEtherType == 0x8100 || rawEtherType == 0x88A8)

        if isEthernet {
            let ethSrc = formatMAC(rawData.subdata(in: 6..<12))
            let ethDst = formatMAC(rawData.subdata(in: 0..<6))
            var etherType = rawEtherType
            offset = 14

            var ethFields = [
                FieldDetail(name: "Destination MAC", value: ethDst, byteRange: 0..<6),
                FieldDetail(name: "Source MAC", value: ethSrc, byteRange: 6..<12),
                FieldDetail(name: "Type", value: String(format: "0x%04X", etherType), byteRange: 12..<14)
            ]

            // 802.1Q VLAN Tagging (0x8100) or 802.1ad QinQ (0x88A8)
            if (etherType == 0x8100 || etherType == 0x88A8) && rawData.count >= 18 {
                let vlanTCI = UInt16(rawData[14]) << 8 | UInt16(rawData[15])
                let vlanId = vlanTCI & 0x0FFF
                let vlanPrio = (vlanTCI >> 13) & 0x07
                let innerEtherType = UInt16(rawData[16]) << 8 | UInt16(rawData[17])
                ethFields.append(FieldDetail(name: "802.1Q Virtual LAN (VLAN ID)", value: "\(vlanId) (Priority: \(vlanPrio))", byteRange: 14..<16))
                ethFields.append(FieldDetail(name: "Inner Type", value: String(format: "0x%04X", innerEtherType), byteRange: 16..<18))
                etherType = innerEtherType
                offset = 18
            }

            layers.append(DissectedLayer(
                name: "Ethernet II",
                summary: "Ethernet II, Src: \(ethSrc), Dst: \(ethDst)",
                fields: ethFields,
                byteRange: 0..<offset
            ))

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
                expert = ExpertInfo(severity: opcode == 1 ? .chat : .note, message: "ARP \(opcode == 1 ? "Resolution Request" : "Gratuitous / Direct Reply")", group: "ARP")

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
                return PacketRecord(
                    id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto,
                    length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface,
                    expertInfo: expert
                )
            }
        } else {
            offset = 0
        }

        if offset >= rawData.count {
            return PacketRecord(
                id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto,
                length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface
            )
        }

        let ipVersion = (rawData[offset] >> 4) & 0x0F
        if ipVersion == 4 && rawData.count >= offset + 20 {
            proto = .ipv4
            let ipStart = offset
            let rawIhl = Int(rawData[offset] & 0x0F) * 4
            let ihl = (rawIhl >= 20 && offset + rawIhl <= rawData.count) ? rawIhl : 20
            let totalLen = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
            let id = Int(rawData[offset + 4]) << 8 | Int(rawData[offset + 5])
            let ttl = Int(rawData[offset + 8])
            let ipProto = rawData[offset + 9]
            src = formatIPv4(rawData.subdata(in: offset + 12..<offset + 16))
            dst = formatIPv4(rawData.subdata(in: offset + 16..<offset + 20))

            // Offline GeoIP Enrichment
            let lookupTarget = !dst.hasPrefix("192.168.") && !dst.hasPrefix("10.") && !dst.hasPrefix("127.") ? dst : src
            let geo = OfflineGeoIP.lookup(ipString: lookupTarget)
            geoFlag = geo.flagEmoji
            geoCountry = geo.countryName
            geoAsn = geo.asn

            layers.append(DissectedLayer(
                name: "Internet Protocol Version 4",
                summary: "IPv4, Src: \(src), Dst: \(dst) (TTL: \(ttl))",
                fields: [
                    FieldDetail(name: "Version", value: "4", byteRange: ipStart..<ipStart + 1),
                    FieldDetail(name: "Header Length", value: "\(ihl) bytes (\(ihl/4))", byteRange: ipStart..<ipStart + 1),
                    FieldDetail(name: "Total Length", value: "\(totalLen)", byteRange: ipStart + 2..<ipStart + 4),
                    FieldDetail(name: "Identification", value: String(format: "0x%04x (%d)", id, id), byteRange: ipStart + 4..<ipStart + 6),
                    FieldDetail(name: "Time to Live", value: "\(ttl)", byteRange: ipStart + 8..<ipStart + 9),
                    FieldDetail(name: "Protocol", value: "\(ipProto)", byteRange: ipStart + 9..<ipStart + 10),
                    FieldDetail(name: "Source Address", value: src, byteRange: ipStart + 12..<ipStart + 16),
                    FieldDetail(name: "Destination Address", value: dst, byteRange: ipStart + 16..<ipStart + 20),
                    FieldDetail(name: "Geo Location", value: "\(geo.flagEmoji) \(geo.countryName) (\(geo.asn))")
                ],
                byteRange: ipStart..<min(rawData.count, ipStart + ihl)
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
                let rawDataOffset = Int((rawData[offset + 12] >> 4) & 0x0F) * 4
                let dataOffset = (rawDataOffset >= 20 && offset + rawDataOffset <= rawData.count) ? rawDataOffset : 20
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

                // Expert Info evaluation
                if (flags & 0x04) != 0 {
                    expert = ExpertInfo(severity: .error, message: "Connection Reset (RST) - Connection forcibly aborted", group: "TCP")
                } else if window == 0 {
                    expert = ExpertInfo(severity: .error, message: "TCP Zero Window: Receiver buffer exhausted", group: "TCP")
                } else if (flags & 0x02) != 0 && (flags & 0x10) != 0 {
                    expert = ExpertInfo(severity: .note, message: "TCP Handshake [SYN-ACK] Response", group: "TCP")
                } else if (flags & 0x02) != 0 {
                    expert = ExpertInfo(severity: .note, message: "TCP Connection Request [SYN]", group: "TCP")
                } else if (flags & 0x01) != 0 {
                    expert = ExpertInfo(severity: .chat, message: "TCP Connection Closing [FIN]", group: "TCP")
                } else {
                    expert = ExpertInfo(severity: .chat, message: "Normal TCP Segment Transmission", group: "TCP")
                }

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
                    byteRange: tcpStart..<min(rawData.count, tcpStart + dataOffset)
                ))

                offset += dataOffset

                // L7 Detection over TCP
                if offset < rawData.count {
                    let payload = rawData.subdata(in: offset..<rawData.count)

                    // 1. WebSocket Frame Dissection (RFC 6455)
                    if payload.count >= 2 && isWebSocketFrame(payload: payload) {
                        proto = .websocket
                        let fin = (payload[0] & 0x80) != 0
                        let opcodeVal = payload[0] & 0x0F
                        let isMasked = (payload[1] & 0x80) != 0
                        var payLen = Int(payload[1] & 0x7F)
                        var wsOffset = 2

                        if payLen == 126 && payload.count >= wsOffset + 2 {
                            payLen = Int(payload[wsOffset]) << 8 | Int(payload[wsOffset + 1])
                            wsOffset += 2
                        } else if payLen == 127 && payload.count >= wsOffset + 8 {
                            var len64: UInt64 = 0
                            for i in 0..<8 {
                                len64 = (len64 << 8) | UInt64(payload[wsOffset + i])
                            }
                            payLen = Int(min(len64, UInt64(Int.max)))
                            wsOffset += 8
                        }

                        var maskingKey: [UInt8] = []
                        if isMasked && payload.count >= wsOffset + 4 {
                            maskingKey = [payload[wsOffset], payload[wsOffset + 1], payload[wsOffset + 2], payload[wsOffset + 3]]
                            wsOffset += 4
                        }

                        // Unmask payload safely
                        let safeWsStart = min(wsOffset, payload.count)
                        let safeWsEnd = min(payload.count, max(safeWsStart, safeWsStart + max(0, payLen)))
                        let rawPayload = payload.subdata(in: safeWsStart..<safeWsEnd)
                        var unmaskedBytes = [UInt8](rawPayload)
                        if isMasked && !maskingKey.isEmpty {
                            for i in 0..<unmaskedBytes.count {
                                unmaskedBytes[i] ^= maskingKey[i % 4]
                            }
                        }
                        let unmaskedStr = String(decoding: unmaskedBytes, as: UTF8.self)

                        let opcodeName: String
                        switch opcodeVal {
                        case 0x01: opcodeName = "Text"
                        case 0x02: opcodeName = "Binary"
                        case 0x08: opcodeName = "Close"
                        case 0x09: opcodeName = "Ping"
                        case 0x0A: opcodeName = "Pong"
                        default: opcodeName = String(format: "0x%X", opcodeVal)
                        }

                        info = "WebSocket \(opcodeName) [FIN=\(fin ? 1 : 0), Mask=\(isMasked ? 1 : 0)] Len=\(payLen): \(unmaskedStr.prefix(60))"
                        expert = ExpertInfo(severity: .chat, message: "WebSocket Frame [\(opcodeName)]", group: "WebSocket")

                        layers.append(DissectedLayer(
                            name: "WebSocket Protocol (RFC 6455)",
                            summary: info,
                            fields: [
                                FieldDetail(name: "FIN Flag", value: fin ? "Final Frame (1)" : "More fragments follow (0)"),
                                FieldDetail(name: "Opcode", value: "\(opcodeName) (\(opcodeVal))"),
                                FieldDetail(name: "Mask", value: isMasked ? "Masked by client (1)" : "Unmasked (0)"),
                                FieldDetail(name: "Payload Length", value: "\(payLen) bytes"),
                                FieldDetail(name: "Masking Key", value: maskingKey.map { String(format: "%02x", $0) }.joined(separator: " ")),
                                FieldDetail(name: "Unmasked Payload", value: unmaskedStr)
                            ],
                            byteRange: offset..<rawData.count
                        ))
                    } else if payload.count >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
                        // TLS Handshake
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
                            expert = ExpertInfo(severity: .note, message: "TLS Handshake Initiation [Client Hello]", group: "TLS")
                        } else if payload.count >= 9 && payload[5] == 0x02 {
                            tlsInfo = "TLS Server Hello"
                            expert = ExpertInfo(severity: .note, message: "TLS Cipher Suite Accepted [Server Hello]", group: "TLS")
                        }
                        info = "\(srcPort) → \(dstPort) \(tlsInfo)"
                        layers.append(DissectedLayer(name: "Transport Layer Security", summary: tlsInfo, fields: tlsFields, byteRange: offset..<rawData.count))
                    } else if srcPort == 22 || dstPort == 22 {
                        proto = .ssh
                        info = "SSH Protocol Packet"
                        let banner = String(decoding: payload.prefix(min(payload.count, 64)), as: UTF8.self)
                        if banner.hasPrefix("SSH-") {
                            info = "SSH Identification: \(banner.trimmingCharacters(in: .whitespacesAndNewlines))"
                        }
                        expert = ExpertInfo(severity: .chat, message: "Encrypted SSH Transport Traffic", group: "SSH")
                        layers.append(DissectedLayer(name: "Secure Shell Protocol", summary: info, fields: [FieldDetail(name: "SSH Payload", value: "\(payload.count) bytes")], byteRange: offset..<rawData.count))
                    } else {
                        let httpStr = String(decoding: payload.prefix(min(payload.count, 2048)), as: UTF8.self)
                        if httpStr.hasPrefix("GET ") || httpStr.hasPrefix("POST ") || httpStr.hasPrefix("HTTP/1.") || httpStr.hasPrefix("PUT ") || httpStr.hasPrefix("HEAD ") || httpStr.hasPrefix("DELETE ") || httpStr.hasPrefix("OPTIONS ") {
                            proto = .http
                            let firstLine = httpStr.components(separatedBy: "\r\n").first ?? ""
                            info = firstLine

                            if firstLine.contains("200 OK") {
                                expert = ExpertInfo(severity: .chat, message: "HTTP 200 OK Successful Response", group: "HTTP")
                            } else if firstLine.contains("301") || firstLine.contains("302") {
                                expert = ExpertInfo(severity: .note, message: "HTTP Redirection", group: "HTTP")
                            } else if firstLine.contains("401") || firstLine.contains("403") || firstLine.contains("500") {
                                expert = ExpertInfo(severity: .error, message: "HTTP Status Error: \(firstLine)", group: "HTTP")
                            } else {
                                expert = ExpertInfo(severity: .note, message: "HTTP Client Request: \(firstLine.prefix(40))", group: "HTTP")
                            }

                            layers.append(DissectedLayer(
                                name: "Hypertext Transfer Protocol",
                                summary: firstLine,
                                fields: [FieldDetail(name: "Request / Status Line", value: firstLine, byteRange: offset..<offset + min(firstLine.utf8.count, payload.count))],
                                byteRange: offset..<rawData.count
                            ))
                        }
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

                // Deep UDP Dissection: DNS, mDNS, DHCP, QUIC, SSDP
                if (srcPort == 5353 || dstPort == 5353) && rawData.count >= offset + 12 {
                    // mDNS / Bonjour
                    proto = .mdns
                    let dnsStart = offset
                    let txId = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                    let dnsFlags = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                    let isResponse = (dnsFlags & 0x8000) != 0
                    let qName = extractDNSQueryName(rawData: rawData, startOffset: offset + 12)
                    info = "mDNS \(isResponse ? "response" : "query") 0x\(String(format: "%04x", txId)) \(qName)"
                    expert = ExpertInfo(severity: .chat, message: "mDNS Bonjour Service Discovery", group: "mDNS")

                    layers.append(DissectedLayer(
                        name: "Multicast DNS (Bonjour / ZeroConf)",
                        summary: info,
                        fields: [
                            FieldDetail(name: "Transaction ID", value: String(format: "0x%04x", txId), byteRange: dnsStart..<dnsStart + 2),
                            FieldDetail(name: "Flags", value: String(format: "0x%04x (Authoritative mDNS)", dnsFlags), byteRange: dnsStart + 2..<dnsStart + 4),
                            FieldDetail(name: "Queried / Announced Service", value: qName)
                        ],
                        byteRange: dnsStart..<rawData.count
                    ))
                } else if (srcPort == 53 || dstPort == 53) && rawData.count >= offset + 12 {
                    // Standard DNS
                    proto = .dns
                    let dnsStart = offset
                    let txId = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                    let dnsFlags = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                    let isResponse = (dnsFlags & 0x8000) != 0
                    let qName = extractDNSQueryName(rawData: rawData, startOffset: offset + 12)
                    info = "DNS \(isResponse ? "response" : "query") 0x\(String(format: "%04x", txId)) \(qName)"
                    expert = ExpertInfo(severity: .chat, message: isResponse ? "DNS Resolution Answer" : "DNS Domain Lookup", group: "DNS")

                    layers.append(DissectedLayer(
                        name: "Domain Name System",
                        summary: info,
                        fields: [
                            FieldDetail(name: "Transaction ID", value: String(format: "0x%04x", txId), byteRange: dnsStart..<dnsStart + 2),
                            FieldDetail(name: "Flags", value: String(format: "0x%04x", dnsFlags), byteRange: dnsStart + 2..<dnsStart + 4),
                            FieldDetail(name: "Queried Domain", value: qName)
                        ],
                        byteRange: dnsStart..<rawData.count
                    ))
                } else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) && rawData.count >= offset + 240 {
                    // DHCPv4 / BOOTP Dissector with full Options parsing
                    proto = .dhcp
                    let dhcpStart = offset
                    let op = rawData[offset]
                    let xid = UInt32(rawData[offset + 4]) << 24 | UInt32(rawData[offset + 5]) << 16 | UInt32(rawData[offset + 6]) << 8 | UInt32(rawData[offset + 7])
                    let clientIP = formatIPv4(rawData.subdata(in: offset + 12..<offset + 16))
                    let yourIP = formatIPv4(rawData.subdata(in: offset + 16..<offset + 20))
                    let serverIP = formatIPv4(rawData.subdata(in: offset + 20..<offset + 24))
                    let clientMAC = formatMAC(rawData.subdata(in: offset + 28..<offset + 34))

                    var optionsMap: [String: String] = [:]
                    var msgType = "BootRequest"
                    if op == 2 { msgType = "BootReply" }

                    // Options start at byte 240 (after 4-byte magic cookie 0x63 0x82 0x53 0x63)
                    var optIdx = offset + 240
                    while optIdx < rawData.count {
                        let optCode = rawData[optIdx]
                        if optCode == 255 { break } // End option
                        if optCode == 0 { optIdx += 1; continue } // Pad
                        guard optIdx + 1 < rawData.count else { break }
                        let optLen = Int(rawData[optIdx + 1])
                        guard optIdx + 2 + optLen <= rawData.count else { break }

                        let optData = rawData.subdata(in: (optIdx + 2)..<(optIdx + 2 + optLen))
                        switch optCode {
                        case 53: // Message Type
                            if let typeByte = optData.first {
                                switch typeByte {
                                case 1: msgType = "DHCP Discover"
                                case 2: msgType = "DHCP Offer"
                                case 3: msgType = "DHCP Request"
                                case 4: msgType = "DHCP Decline"
                                case 5: msgType = "DHCP ACK"
                                case 6: msgType = "DHCP NAK"
                                case 7: msgType = "DHCP Release"
                                case 8: msgType = "DHCP Inform"
                                default: msgType = "DHCP Type \(typeByte)"
                                }
                            }
                            optionsMap["DHCP Message Type"] = msgType
                        case 1: // Subnet Mask
                            optionsMap["Subnet Mask"] = formatIPv4(optData)
                        case 3: // Router
                            optionsMap["Router / Gateway"] = formatIPv4(optData)
                        case 6: // DNS
                            optionsMap["Domain Name Server"] = formatIPv4(optData)
                        case 12: // Host Name
                            optionsMap["Host Name"] = String(data: optData, encoding: .utf8) ?? "N/A"
                        case 51: // Lease Time
                            if optData.count >= 4 {
                                let lease = UInt32(optData[0]) << 24 | UInt32(optData[1]) << 16 | UInt32(optData[2]) << 8 | UInt32(optData[3])
                                optionsMap["IP Address Lease Time"] = "\(lease)s"
                            }
                        default:
                            break
                        }
                        optIdx += 2 + optLen
                    }

                    info = "\(msgType) - Transaction ID 0x\(String(format: "%08x", xid))"
                    if yourIP != "0.0.0.0" { info += " (Assigned: \(yourIP))" }
                    expert = ExpertInfo(severity: .note, message: "DHCP Network Configuration Lease [\(msgType)]", group: "DHCP")

                    var dhcpFields: [FieldDetail] = [
                        FieldDetail(name: "Message Opcode", value: op == 1 ? "BOOTREQUEST (1)" : "BOOTREPLY (2)", byteRange: dhcpStart..<dhcpStart + 1),
                        FieldDetail(name: "Transaction ID", value: String(format: "0x%08x", xid), byteRange: dhcpStart + 4..<dhcpStart + 8),
                        FieldDetail(name: "Client IP (ciaddr)", value: clientIP, byteRange: dhcpStart + 12..<dhcpStart + 16),
                        FieldDetail(name: "Your IP (yiaddr)", value: yourIP, byteRange: dhcpStart + 16..<dhcpStart + 20),
                        FieldDetail(name: "Server IP (siaddr)", value: serverIP, byteRange: dhcpStart + 20..<dhcpStart + 24),
                        FieldDetail(name: "Client MAC Address", value: clientMAC, byteRange: dhcpStart + 28..<dhcpStart + 34)
                    ]
                    for (k, v) in optionsMap {
                        dhcpFields.append(FieldDetail(name: k, value: v))
                    }

                    layers.append(DissectedLayer(
                        name: "Dynamic Host Configuration Protocol",
                        summary: info,
                        fields: dhcpFields,
                        byteRange: dhcpStart..<rawData.count
                    ))
                } else if (srcPort == 443 || dstPort == 443 || srcPort == 8443 || dstPort == 8443) && rawData.count > offset + 4 {
                    // QUIC / HTTP3 Deep Dissector
                    proto = .quic
                    let quicStart = offset
                    let firstByte = rawData[offset]
                    let isLongHeader = (firstByte & 0x80) != 0

                    if isLongHeader {
                        let pktTypeVal = (firstByte & 0x30) >> 4
                        let typeName: String
                        switch pktTypeVal {
                        case 0x00: typeName = "Initial"
                        case 0x01: typeName = "0-RTT"
                        case 0x02: typeName = "Handshake"
                        case 0x03: typeName = "Retry"
                        default: typeName = "Long Header"
                        }

                        var versionStr = "Unknown"
                        if rawData.count >= offset + 5 {
                            let ver = UInt32(rawData[offset + 1]) << 24 | UInt32(rawData[offset + 2]) << 16 | UInt32(rawData[offset + 3]) << 8 | UInt32(rawData[offset + 4])
                            if ver == 0x00000001 { versionStr = "QUIC v1 (RFC 9000)" }
                            else if ver == 0xff00001d { versionStr = "draft-29" }
                            else { versionStr = String(format: "0x%08x", ver) }
                        }

                        info = "QUIC \(typeName) [\(versionStr)] Len=\(rawData.count - offset)"
                        expert = ExpertInfo(severity: .chat, message: "QUIC/HTTP3 Handshake Transport Packet", group: "QUIC")

                        layers.append(DissectedLayer(
                            name: "QUIC Transport Protocol",
                            summary: info,
                            fields: [
                                FieldDetail(name: "Header Form", value: "Long Header (1)", byteRange: quicStart..<quicStart + 1),
                                FieldDetail(name: "Packet Type", value: "\(typeName) (\(pktTypeVal))"),
                                FieldDetail(name: "Version", value: versionStr, byteRange: quicStart + 1..<quicStart + 5),
                                FieldDetail(name: "Payload Bytes", value: "\(rawData.count - offset - 5) bytes")
                            ],
                            byteRange: quicStart..<rawData.count
                        ))
                    } else {
                        // Short Header (1-RTT)
                        info = "QUIC 1-RTT Protected Application Data"
                        expert = ExpertInfo(severity: .chat, message: "QUIC 1-RTT Stream Data", group: "QUIC")
                        layers.append(DissectedLayer(
                            name: "QUIC Transport Protocol",
                            summary: info,
                            fields: [
                                FieldDetail(name: "Header Form", value: "Short Header (0)", byteRange: quicStart..<quicStart + 1),
                                FieldDetail(name: "Payload", value: "\(rawData.count - offset) bytes (Encrypted)")
                            ],
                            byteRange: quicStart..<rawData.count
                        ))
                    }
                } else if srcPort == 1900 || dstPort == 1900 {
                    proto = .ssdp
                    info = "SSDP Discovery M-SEARCH / NOTIFY"
                    expert = ExpertInfo(severity: .chat, message: "SSDP UPnP Service Announcement", group: "SSDP")
                    layers.append(DissectedLayer(name: "Simple Service Discovery Protocol", summary: info, fields: [FieldDetail(name: "Port", value: "1900 (Multicast)")], byteRange: offset..<rawData.count))
                }
            } else if ipProto == 1 { // ICMP
                proto = .icmp
                guard rawData.count >= offset + 2 else {
                    info = "ICMP Fragment (\(rawData.count - offset) bytes)"
                    layers.append(DissectedLayer(name: "Internet Control Message Protocol", summary: info, fields: [], byteRange: offset..<rawData.count))
                    return PacketRecord(id: packetId, timestamp: timestamp, source: src, destination: dst, protocolType: proto, length: rawData.count, info: info, rawData: rawData, layers: layers, interface: interface, expertInfo: ExpertInfo(severity: .warning, message: "Truncated ICMP Header", group: "ICMP"), countryFlag: geoFlag, countryName: geoCountry, asnInfo: geoAsn)
                }
                let icmpType = rawData[offset]
                let icmpCode = rawData[offset + 1]
                let isReq = (icmpType == 8)
                let isReply = (icmpType == 0)

                if isReq || isReply {
                    let idStr: String
                    if rawData.count >= offset + 6 {
                        let icmpId = UInt16(rawData[offset + 4]) << 8 | UInt16(rawData[offset + 5])
                        idStr = " id=0x\(String(format: "%04x", icmpId))"
                    } else {
                        idStr = ""
                    }
                    info = "Echo (ping) \(isReq ? "request" : "reply")\(idStr)"
                    expert = ExpertInfo(severity: .chat, message: "ICMP Echo \(isReq ? "Request" : "Reply")", group: "ICMP")
                } else if icmpType == 3 {
                    info = "Destination Unreachable (Code: \(icmpCode))"
                    expert = ExpertInfo(severity: .error, message: "ICMP Destination Unreachable", group: "ICMP")
                } else {
                    info = "ICMP Message Type=\(icmpType) Code=\(icmpCode)"
                    expert = ExpertInfo(severity: .warning, message: "ICMP Control Message", group: "ICMP")
                }

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
        } else if ipVersion == 6 && rawData.count >= offset + 40 {
            proto = .ipv6
            let ipStart = offset
            let nextHeader = rawData[offset + 6]
            let hopLimit = rawData[offset + 7]
            src = formatIPv6(rawData.subdata(in: offset + 8..<offset + 24))
            dst = formatIPv6(rawData.subdata(in: offset + 24..<offset + 40))

            layers.append(DissectedLayer(
                name: "Internet Protocol Version 6",
                summary: "IPv6, Src: \(src), Dst: \(dst) (Next: \(nextHeader), Hop Limit: \(hopLimit))",
                fields: [
                    FieldDetail(name: "Version", value: "6", byteRange: ipStart..<ipStart + 1),
                    FieldDetail(name: "Next Header", value: "\(nextHeader)", byteRange: ipStart + 6..<ipStart + 7),
                    FieldDetail(name: "Hop Limit", value: "\(hopLimit)", byteRange: ipStart + 7..<ipStart + 8),
                    FieldDetail(name: "Source Address", value: src, byteRange: ipStart + 8..<ipStart + 24),
                    FieldDetail(name: "Destination Address", value: dst, byteRange: ipStart + 24..<ipStart + 40)
                ],
                byteRange: ipStart..<ipStart + 40
            ))

            offset += 40
            if nextHeader == 6 && rawData.count >= offset + 20 { // TCP over IPv6
                proto = .tcp
                let srcPort = Int(rawData[offset]) << 8 | Int(rawData[offset + 1])
                let dstPort = Int(rawData[offset + 2]) << 8 | Int(rawData[offset + 3])
                info = "IPv6 TCP \(srcPort) → \(dstPort)"
                layers.append(DissectedLayer(name: "Transmission Control Protocol", summary: info, fields: [
                    FieldDetail(name: "Source Port", value: "\(srcPort)", byteRange: offset..<offset + 2),
                    FieldDetail(name: "Destination Port", value: "\(dstPort)", byteRange: offset + 2..<offset + 4)
                ], byteRange: offset..<rawData.count))
            } else if nextHeader == 58 && rawData.count >= offset + 4 { // ICMPv6
                proto = .icmp
                let icmpType = rawData[offset]
                let icmpCode = rawData[offset + 1]
                let typeStr: String
                switch icmpType {
                case 128: typeStr = "Echo Request (ping6)"
                case 129: typeStr = "Echo Reply (ping6)"
                case 133: typeStr = "Router Solicitation"
                case 134: typeStr = "Router Advertisement"
                case 135: typeStr = "Neighbor Solicitation"
                case 136: typeStr = "Neighbor Advertisement"
                default: typeStr = "ICMPv6 Type \(icmpType)"
                }
                info = "\(typeStr) Code=\(icmpCode)"
                layers.append(DissectedLayer(name: "Internet Control Message Protocol v6", summary: info, fields: [
                    FieldDetail(name: "Type", value: "\(icmpType) (\(typeStr))", byteRange: offset..<offset + 1),
                    FieldDetail(name: "Code", value: "\(icmpCode)", byteRange: offset + 1..<offset + 2)
                ], byteRange: offset..<rawData.count))
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
            interface: interface,
            expertInfo: expert,
            countryFlag: geoFlag,
            countryName: geoCountry,
            asnInfo: geoAsn
        )
    }

    private static func isWebSocketFrame(payload: Data) -> Bool {
        guard payload.count >= 2 else { return false }
        // Exclude HTTP text headers (GET, POST, PUT, DELETE, HTTP/1.x, HEAD, OPTIONS)
        let prefix4 = String(decoding: payload.prefix(5), as: UTF8.self).uppercased()
        if prefix4.hasPrefix("GET ") || prefix4.hasPrefix("POST") || prefix4.hasPrefix("PUT ") ||
           prefix4.hasPrefix("DELE") || prefix4.hasPrefix("HTTP") || prefix4.hasPrefix("HEAD") {
            return false
        }
        // RFC 6455: Reserved bits (bits 4, 5, 6) MUST be 0 unless an extension is negotiated
        if (payload[0] & 0x70) != 0 {
            return false
        }
        let opcode = payload[0] & 0x0F
        // Valid opcodes: 0x1 (text), 0x2 (binary), 0x8 (close), 0x9 (ping), 0xA (pong)
        return (opcode == 0x01 || opcode == 0x02 || opcode == 0x08 || opcode == 0x09 || opcode == 0x0A)
    }

    private static func formatMAC(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    private static func formatIPv4(_ data: Data) -> String {
        return data.map { "\($0)" }.joined(separator: ".")
    }

    private static func formatIPv6(_ data: Data) -> String {
        guard data.count >= 16 else { return "::" }
        var parts: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let val = UInt16(data[i]) << 8 | UInt16(data[i + 1])
            parts.append(String(format: "%x", val))
        }
        return parts.joined(separator: ":")
    }

    private static func extractSNI(payload: Data) -> String? {
        guard payload.count >= 43 else { return nil }
        guard payload[0] == 0x16, payload.count >= 6, payload[5] == 0x01 else { return nil }

        var idx = 9 // Skip Record Header (5) + Handshake Type (1) + Length (3)
        guard idx + 34 <= payload.count else { return nil }
        idx += 2 // Skip Client Version
        idx += 32 // Skip Client Random

        // Session ID
        guard idx < payload.count else { return nil }
        let sessionIDLen = Int(payload[idx])
        idx += 1 + sessionIDLen

        // Cipher Suites
        guard idx + 2 <= payload.count else { return nil }
        let cipherLen = Int(payload[idx]) << 8 | Int(payload[idx + 1])
        idx += 2 + cipherLen

        // Compression Methods
        guard idx < payload.count else { return nil }
        let compLen = Int(payload[idx])
        idx += 1 + compLen

        // Extensions
        guard idx + 2 <= payload.count else { return nil }
        let extsLen = Int(payload[idx]) << 8 | Int(payload[idx + 1])
        idx += 2

        let endExts = min(payload.count, idx + extsLen)
        while idx + 4 <= endExts {
            let extType = Int(payload[idx]) << 8 | Int(payload[idx + 1])
            let extLen = Int(payload[idx + 2]) << 8 | Int(payload[idx + 3])
            idx += 4
            guard idx + extLen <= endExts else { break }

            if extType == 0x0000 && extLen >= 5 { // Server Name Indication (SNI)
                let nameType = payload[idx + 2]
                let nameLen = Int(payload[idx + 3]) << 8 | Int(payload[idx + 4])
                if nameType == 0 && idx + 5 + nameLen <= idx + extLen {
                    let nameData = payload.subdata(in: (idx + 5)..<(idx + 5 + nameLen))
                    let name = String(decoding: nameData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    return name.isEmpty ? nil : name
                }
            }
            idx += extLen
        }
        return nil
    }

    private static func extractDNSQueryName(rawData: Data, startOffset: Int) -> String {
        var idx = startOffset
        var parts: [String] = []
        var steps = 0
        var jumps = 0

        while idx < rawData.count && steps < 64 {
            steps += 1
            let len = Int(rawData[idx])
            if len == 0 {
                break
            }
            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                guard idx + 1 < rawData.count, jumps < 10 else { break }
                let ptrOffset = (Int(len & 0x3F) << 8) | Int(rawData[idx + 1])
                idx = ptrOffset
                jumps += 1
                continue
            }
            idx += 1
            if idx + len <= rawData.count {
                let partData = rawData.subdata(in: idx..<idx + len)
                let part = String(decoding: partData, as: UTF8.self).filter { $0.isASCII && !$0.isNewline }
                if !part.isEmpty {
                    parts.append(part)
                }
                idx += len
            } else { break }
        }
        return parts.isEmpty ? "unknown.domain" : parts.joined(separator: ".")
    }
}
