import Foundation

public struct PcapManager {
    // Classic PCAP Constants
    private static let PCAP_MAGIC: UInt32 = 0xa1b2c3d4
    private static let PCAP_MAGIC_SWAPPED: UInt32 = 0xd4c3b2a1
    private static let PCAP_VERSION_MAJOR: UInt16 = 2
    private static let PCAP_VERSION_MINOR: UInt16 = 4

    // PCAP-NG Constants
    public static let PCAPNG_SHB_MAGIC: UInt32 = 0x0A0D0D0A
    private static let PCAPNG_BOM: UInt32 = 0x1A2B3C4D
    private static let PCAPNG_IDB_TYPE: UInt32 = 0x00000001
    private static let PCAPNG_EPB_TYPE: UInt32 = 0x00000006

    // MARK: - Classic PCAP Writer
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
            let safeTs = (p.timestamp.isFinite && !p.timestamp.isNaN && p.timestamp >= 0) ? min(p.timestamp, Double(UInt32.max)) : 0.0
            let secs = UInt32(safeTs)
            let remainder = max(0.0, safeTs - Double(secs))
            let usecs = UInt32(min(999_999, max(0, Int(remainder * 1_000_000))))
            let len = UInt32(min(p.rawData.count, 65535))

            var s = secs
            var u = usecs
            var l = len
            var o = len

            withUnsafeBytes(of: &s) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &u) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &l) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &o) { data.append(contentsOf: $0) }
            data.append(p.rawData.prefix(Int(len)))
        }

        return data
    }

    // MARK: - PCAP-NG Next-Generation Writer
    public static func writePcapNg(packets: [PacketRecord]) -> Data {
        var data = Data()

        // 1. Section Header Block (SHB)
        var shbType = PCAPNG_SHB_MAGIC
        var shbLen: UInt32 = 28 // 4+4+4+2+2+8+4
        var byteOrderMagic = PCAPNG_BOM
        var major: UInt16 = 1
        var minor: UInt16 = 0
        var sectionLen: UInt64 = 0xFFFFFFFFFFFFFFFF

        withUnsafeBytes(of: &shbType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &shbLen) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &byteOrderMagic) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &major) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &minor) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &sectionLen) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &shbLen) { data.append(contentsOf: $0) }

        // 2. Interface Description Block (IDB)
        var idbType = PCAPNG_IDB_TYPE
        var idbLen: UInt32 = 20 // 4+4+2+2+4+4
        var linkType: UInt16 = 1 // LINKTYPE_ETHERNET
        var reserved: UInt16 = 0
        var snapLen: UInt32 = 65535

        withUnsafeBytes(of: &idbType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &idbLen) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &linkType) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &reserved) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &snapLen) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: &idbLen) { data.append(contentsOf: $0) }

        // 3. Enhanced Packet Blocks (EPB)
        for p in packets {
            let rawCount = min(p.rawData.count, 65535)
            let padCount = (4 - (rawCount % 4)) % 4
            let blockLen: UInt32 = UInt32(32 + rawCount + padCount)

            var epbType = PCAPNG_EPB_TYPE
            var bLen = blockLen
            var ifId: UInt32 = 0

            let safeTs = (p.timestamp.isFinite && !p.timestamp.isNaN && p.timestamp >= 0) ? min(p.timestamp, Double(UInt32.max)) : 0.0
            let micros = UInt64(safeTs * 1_000_000.0)
            var tsHigh = UInt32((micros >> 32) & 0xFFFFFFFF)
            var tsLow = UInt32(micros & 0xFFFFFFFF)
            var capLen = UInt32(rawCount)
            var origLen = UInt32(rawCount)

            withUnsafeBytes(of: &epbType) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &bLen) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &ifId) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &tsHigh) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &tsLow) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &capLen) { data.append(contentsOf: $0) }
            withUnsafeBytes(of: &origLen) { data.append(contentsOf: $0) }

            data.append(p.rawData.prefix(rawCount))
            if padCount > 0 {
                data.append(Data(repeating: 0, count: padCount))
            }
            withUnsafeBytes(of: &bLen) { data.append(contentsOf: $0) }
        }

        return data
    }

    // MARK: - Auto-Detecting Universal Reader
    public static func readAny(data: Data) -> [PacketRecord] {
        guard data.count >= 4 else { return [] }
        let magic = data.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self) }
        if magic == PCAPNG_SHB_MAGIC {
            return readPcapNg(data: data)
        } else if magic == PCAP_MAGIC || magic == PCAP_MAGIC_SWAPPED || magic == 0xa1b23c4d || magic == 0x4d3cb2a1 {
            return readPcap(data: data)
        } else {
            // Check if magic exists anywhere or fallback
            return readPcap(data: data)
        }
    }

    // MARK: - Classic PCAP Reader
    public static func readPcap(data: Data) -> [PacketRecord] {
        guard data.count >= 24 else { return [] }

        let magic = data.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self) }
        let isSwapped = (magic == PCAP_MAGIC_SWAPPED || magic == 0x4d3cb2a1)
        let isNano = (magic == 0xa1b23c4d || magic == 0x4d3cb2a1)

        // If magic matches PCAP-NG, redirect safely
        if magic == PCAPNG_SHB_MAGIC {
            return readPcapNg(data: data)
        }

        // Validate valid PCAP magic or recover gracefully
        let isValidMagic = (magic == PCAP_MAGIC || magic == PCAP_MAGIC_SWAPPED || magic == 0xa1b23c4d || magic == 0x4d3cb2a1)
        guard isValidMagic else {
            // Corrupt file without recognizable PCAP header
            return []
        }

        var offset = 24
        var packets: [PacketRecord] = []
        var packetId = 1
        let maxPackets = 50_000

        while offset + 16 <= data.count && packets.count < maxPackets {
            var tsSec = data.subdata(in: offset..<offset + 4).withUnsafeBytes { $0.load(as: UInt32.self) }
            var tsUsec = data.subdata(in: offset + 4..<offset + 8).withUnsafeBytes { $0.load(as: UInt32.self) }
            var rawInclLen = data.subdata(in: offset + 8..<offset + 12).withUnsafeBytes { $0.load(as: UInt32.self) }

            if isSwapped {
                tsSec = tsSec.byteSwapped
                tsUsec = tsUsec.byteSwapped
                rawInclLen = rawInclLen.byteSwapped
            }

            let inclLen = Int(rawInclLen)
            offset += 16

            // Defense against zero-length or oversized corrupt frames
            guard inclLen > 0 && inclLen <= 65535 && offset + inclLen <= data.count else {
                break
            }

            let rawPacket = data.subdata(in: offset..<offset + inclLen)
            let divisor = isNano ? 1_000_000_000.0 : 1_000_000.0
            let safeUsec = min(Double(tsUsec), divisor)
            let timestamp = Double(tsSec) + (safeUsec / divisor)
            let record = PacketDissector.dissect(packetId: packetId, timestamp: timestamp, rawData: rawPacket)
            packets.append(record)
            packetId += 1
            offset += inclLen
        }
        return packets
    }

    // MARK: - PCAP-NG Reader
    public static func readPcapNg(data: Data) -> [PacketRecord] {
        guard data.count >= 12 else { return [] }
        var offset = 0
        var packets: [PacketRecord] = []
        var packetId = 1
        let maxPackets = 50_000

        var isSwapped = false

        while offset + 8 <= data.count && packets.count < maxPackets {
            var blockType = data.subdata(in: offset..<offset + 4).withUnsafeBytes { $0.load(as: UInt32.self) }
            var rawBlockLen = data.subdata(in: offset + 4..<offset + 8).withUnsafeBytes { $0.load(as: UInt32.self) }

            // Check Section Header Block (SHB) for Byte Order Magic
            if blockType == PCAPNG_SHB_MAGIC && offset + 12 <= data.count {
                let bom = data.subdata(in: offset + 8..<offset + 12).withUnsafeBytes { $0.load(as: UInt32.self) }
                if bom == 0x4D3C2B1A {
                    isSwapped = true
                } else if bom == PCAPNG_BOM {
                    isSwapped = false
                }
            }

            if isSwapped {
                blockType = blockType.byteSwapped
                rawBlockLen = rawBlockLen.byteSwapped
            }

            let blockLen = Int(rawBlockLen)
            // Block length must be a multiple of 4, at least 12 bytes, and within remaining data
            guard blockLen >= 12 && blockLen <= 10_000_000 && (blockLen % 4 == 0) && offset + blockLen <= data.count else {
                break
            }

            if blockType == PCAPNG_EPB_TYPE && blockLen >= 32 {
                // Parse EPB: ifId(4), tsHigh(4), tsLow(4), capLen(4), origLen(4)
                var rawTsHigh = data.subdata(in: offset + 12..<offset + 16).withUnsafeBytes { $0.load(as: UInt32.self) }
                var rawTsLow = data.subdata(in: offset + 16..<offset + 20).withUnsafeBytes { $0.load(as: UInt32.self) }
                var rawCapLen = data.subdata(in: offset + 20..<offset + 24).withUnsafeBytes { $0.load(as: UInt32.self) }

                if isSwapped {
                    rawTsHigh = rawTsHigh.byteSwapped
                    rawTsLow = rawTsLow.byteSwapped
                    rawCapLen = rawCapLen.byteSwapped
                }

                let tsHigh = UInt64(rawTsHigh)
                let tsLow = UInt64(rawTsLow)
                let capLen = Int(rawCapLen)

                let micros = (tsHigh << 32) | tsLow
                let timestamp = Double(micros) / 1_000_000.0

                let dataStart = offset + 28
                if capLen > 0 && capLen <= 65535 && dataStart + capLen <= offset + blockLen - 4 {
                    let rawPacket = data.subdata(in: dataStart..<dataStart + capLen)
                    let record = PacketDissector.dissect(packetId: packetId, timestamp: timestamp, rawData: rawPacket)
                    packets.append(record)
                    packetId += 1
                }
            } else if blockType == 0x00000003 && blockLen >= 16 { // Simple Packet Block (SPB)
                let dataStart = offset + 8
                let capLen = blockLen - 12
                if capLen > 0 && capLen <= 65535 && dataStart + capLen <= offset + blockLen - 4 {
                    let rawPacket = data.subdata(in: dataStart..<dataStart + capLen)
                    let record = PacketDissector.dissect(packetId: packetId, timestamp: Date().timeIntervalSince1970, rawData: rawPacket)
                    packets.append(record)
                    packetId += 1
                }
            }

            offset += blockLen
        }

        return packets
    }

    // MARK: - Filtered Export
    public static func writeFilteredPcap(packets: [PacketRecord], filter: String?) -> Data {
        guard let f = filter, !f.isEmpty else {
            return writePcap(packets: packets)
        }
        let matching = packets.filter { DisplayFilter.evaluate(filter: f, packet: $0) }
        return writePcap(packets: matching)
    }

    public static func writeFilteredPcapNg(packets: [PacketRecord], filter: String?) -> Data {
        guard let f = filter, !f.isEmpty else {
            return writePcapNg(packets: packets)
        }
        let matching = packets.filter { DisplayFilter.evaluate(filter: f, packet: $0) }
        return writePcapNg(packets: matching)
    }

    // MARK: - Forensic JSON Dump
    public static func exportJsonDump(packets: [PacketRecord]) -> Data {
        var jsonArray: [[String: Any]] = []

        for p in packets {
            var item: [String: Any] = [
                "id": p.id,
                "timestamp": p.timestamp,
                "timeString": p.timeString,
                "source": p.source,
                "destination": p.destination,
                "protocol": p.protocolType.rawValue,
                "length": p.length,
                "info": p.info,
                "interface": p.interface
            ]

            var layersDict: [[String: Any]] = []
            for l in p.layers {
                var layerItem: [String: Any] = [
                    "name": l.name,
                    "summary": l.summary
                ]
                var fieldsDict: [[String: String]] = []
                for f in l.fields {
                    fieldsDict.append(["name": f.name, "value": f.value])
                }
                layerItem["fields"] = fieldsDict
                layersDict.append(layerItem)
            }
            item["layers"] = layersDict

            if let exp = p.expertInfo {
                item["expertInfo"] = [
                    "severity": exp.severity.rawValue,
                    "group": exp.group,
                    "message": exp.message
                ]
            }

            if let geo = p.geoCoord {
                item["location"] = [
                    "latitude": geo.latitude,
                    "longitude": geo.longitude,
                    "accuracy": geo.horizontalAccuracy
                ]
            }

            jsonArray.append(item)
        }

        return (try? JSONSerialization.data(withJSONObject: jsonArray, options: [.prettyPrinted])) ?? Data()
    }
}
