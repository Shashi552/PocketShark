import Foundation

public struct GeoIPLookupResult: Hashable, Codable {
    public let ip: String
    public let countryCode: String
    public let countryName: String
    public let flagEmoji: String
    public let asn: String
    public let organization: String
    public let isPrivate: Bool

    public init(
        ip: String,
        countryCode: String,
        countryName: String,
        flagEmoji: String,
        asn: String,
        organization: String,
        isPrivate: Bool
    ) {
        self.ip = ip
        self.countryCode = countryCode
        self.countryName = countryName
        self.flagEmoji = flagEmoji
        self.asn = asn
        self.organization = organization
        self.isPrivate = isPrivate
    }
}

public struct OfflineGeoIP {

    private struct IPRangeEntry {
        let startIP: UInt32
        let endIP: UInt32
        let countryCode: String
        let countryName: String
        let flag: String
        let asn: String
        let org: String
    }

    // Static sorted lookup database
    private static let database: [IPRangeEntry] = [
        // Cloudflare
        makeCIDR(ip: "1.0.0.0", prefix: 24, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS13335", org: "Cloudflare, Inc."),
        makeCIDR(ip: "1.1.1.0", prefix: 24, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS13335", org: "Cloudflare, Inc."),
        makeCIDR(ip: "104.16.0.0", prefix: 12, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS13335", org: "Cloudflare, Inc."),
        makeCIDR(ip: "172.64.0.0", prefix: 13, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS13335", org: "Cloudflare, Inc."),

        // Apple Inc.
        makeCIDR(ip: "17.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS714", org: "Apple Inc."),

        // Google LLC
        makeCIDR(ip: "8.8.4.0", prefix: 24, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS15169", org: "Google LLC"),
        makeCIDR(ip: "8.8.8.0", prefix: 24, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS15169", org: "Google LLC"),
        makeCIDR(ip: "142.250.0.0", prefix: 15, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS15169", org: "Google LLC"),
        makeCIDR(ip: "172.217.0.0", prefix: 16, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS15169", org: "Google LLC"),
        makeCIDR(ip: "216.58.192.0", prefix: 19, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS15169", org: "Google LLC"),

        // Amazon AWS
        makeCIDR(ip: "3.0.0.0", prefix: 9, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS16509", org: "Amazon.com, Inc. (AWS)"),
        makeCIDR(ip: "13.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS16509", org: "Amazon.com, Inc. (AWS)"),
        makeCIDR(ip: "18.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS16509", org: "Amazon.com, Inc. (AWS)"),
        makeCIDR(ip: "52.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS16509", org: "Amazon.com, Inc. (AWS)"),
        makeCIDR(ip: "54.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS16509", org: "Amazon.com, Inc. (AWS)"),

        // Microsoft Corporation
        makeCIDR(ip: "20.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS8075", org: "Microsoft Corporation (Azure)"),
        makeCIDR(ip: "40.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS8075", org: "Microsoft Corporation (Azure)"),
        makeCIDR(ip: "51.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS8075", org: "Microsoft Corporation (Azure)"),

        // GitHub / Fastly
        makeCIDR(ip: "140.82.112.0", prefix: 20, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS36459", org: "GitHub, Inc."),
        makeCIDR(ip: "185.199.108.0", prefix: 22, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS36459", org: "GitHub, Inc."),
        makeCIDR(ip: "151.101.0.0", prefix: 16, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS54113", org: "Fastly, Inc."),

        // Meta (Facebook / WhatsApp / Instagram)
        makeCIDR(ip: "31.13.64.0", prefix: 18, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS32934", org: "Meta Platforms, Inc."),
        makeCIDR(ip: "157.240.0.0", prefix: 16, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS32934", org: "Meta Platforms, Inc."),

        // Akamai
        makeCIDR(ip: "23.0.0.0", prefix: 8, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS20940", org: "Akamai Technologies"),

        // Telegram Messenger
        makeCIDR(ip: "91.108.4.0", prefix: 22, cc: "GB", name: "United Kingdom", flag: "🇬🇧", asn: "AS62041", org: "Telegram Messenger Inc"),
        makeCIDR(ip: "149.154.160.0", prefix: 20, cc: "AE", name: "United Arab Emirates", flag: "🇦🇪", asn: "AS62041", org: "Telegram Messenger Inc"),

        // Quad9 & Cisco Umbrella
        makeCIDR(ip: "9.9.9.0", prefix: 24, cc: "CH", name: "Switzerland", flag: "🇨🇭", asn: "AS19281", org: "Quad9 DNS"),
        makeCIDR(ip: "208.67.220.0", prefix: 22, cc: "US", name: "United States", flag: "🇺🇸", asn: "AS36692", org: "Cisco Umbrella (OpenDNS)"),

        // European Providers (Hetzner, OVH, Deutsche Telekom)
        makeCIDR(ip: "88.99.0.0", prefix: 16, cc: "DE", name: "Germany", flag: "🇩🇪", asn: "AS24940", org: "Hetzner Online GmbH"),
        makeCIDR(ip: "51.254.0.0", prefix: 16, cc: "FR", name: "France", flag: "🇫🇷", asn: "AS16276", org: "OVH SAS"),
        makeCIDR(ip: "193.159.0.0", prefix: 16, cc: "DE", name: "Germany", flag: "🇩🇪", asn: "AS3320", org: "Deutsche Telekom AG"),

        // Asian Providers (NTT, Tata, Airtel, Singtel)
        makeCIDR(ip: "129.250.0.0", prefix: 16, cc: "JP", name: "Japan", flag: "🇯🇵", asn: "AS2914", org: "NTT Communications"),
        makeCIDR(ip: "182.72.0.0", prefix: 15, cc: "IN", name: "India", flag: "🇮🇳", asn: "AS9498", org: "Bharti Airtel Ltd."),
        makeCIDR(ip: "115.112.0.0", prefix: 14, cc: "IN", name: "India", flag: "🇮🇳", asn: "AS4755", org: "Tata Communications"),
        makeCIDR(ip: "165.21.0.0", prefix: 16, cc: "SG", name: "Singapore", flag: "🇸🇬", asn: "AS7473", org: "Singapore Telecommunications")
    ].sorted { $0.startIP < $1.startIP }

    public static func lookup(ip: String) -> GeoIPLookupResult {
        return lookup(ipString: ip)
    }

    public static func lookup(ipString: String) -> GeoIPLookupResult {
        guard let ipVal = parseIPv4(ipString) else {
            let lower = ipString.lowercased()
            if lower == "::1" {
                return GeoIPLookupResult(ip: ipString, countryCode: "LOC", countryName: "IPv6 Loopback (RFC 4291)", flagEmoji: "🔄", asn: "AS-LOCAL", organization: "Local Host Loopback", isPrivate: true)
            } else if lower.hasPrefix("fe80:") {
                return GeoIPLookupResult(ip: ipString, countryCode: "LL", countryName: "IPv6 Link-Local (RFC 4291)", flagEmoji: "🔗", asn: "AS-LINKLOCAL", organization: "Local Link Segment", isPrivate: true)
            } else if lower.hasPrefix("fc") || lower.hasPrefix("fd") {
                return GeoIPLookupResult(ip: ipString, countryCode: "ULA", countryName: "IPv6 Unique Local (RFC 4193)", flagEmoji: "🏠", asn: "AS-PRIVATE", organization: "Private IPv6 Intranet", isPrivate: true)
            } else if lower.hasPrefix("2001:4860:") {
                return GeoIPLookupResult(ip: ipString, countryCode: "US", countryName: "United States (Google IPv6)", flagEmoji: "🇺🇸", asn: "AS15169", organization: "Google LLC", isPrivate: false)
            } else if lower.hasPrefix("2606:4700:") {
                return GeoIPLookupResult(ip: ipString, countryCode: "US", countryName: "United States (Cloudflare IPv6)", flagEmoji: "🇺🇸", asn: "AS13335", organization: "Cloudflare, Inc.", isPrivate: false)
            }
            return GeoIPLookupResult(
                ip: ipString,
                countryCode: "--",
                countryName: "Non-IPv4 / Link Frame",
                flagEmoji: "🌐",
                asn: "N/A",
                organization: "Local Link Layer",
                isPrivate: false
            )
        }

        // 1. Private RFC 1918 / Loopback checks
        // 10.0.0.0/8 (0x0A000000 - 0x0AFFFFFF)
        if (ipVal & 0xFF000000) == 0x0A000000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "LAN", countryName: "Private Network (RFC 1918)", flagEmoji: "🏠", asn: "AS-PRIVATE", organization: "Local Private Intranet", isPrivate: true)
        }
        // 172.16.0.0/12 (0xAC100000 - 0xAC1FFFFF)
        if (ipVal & 0xFFF00000) == 0xAC100000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "LAN", countryName: "Private Network (RFC 1918)", flagEmoji: "🏠", asn: "AS-PRIVATE", organization: "Enterprise DMZ / Private", isPrivate: true)
        }
        // 192.168.0.0/16 (0xC0A80000 - 0xC0A8FFFF)
        if (ipVal & 0xFFFF0000) == 0xC0A80000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "LAN", countryName: "Private Network (RFC 1918)", flagEmoji: "🏠", asn: "AS-PRIVATE", organization: "Home / Office Wi-Fi LAN", isPrivate: true)
        }
        // 127.0.0.0/8 (0x7F000000 - 0x7FFFFFFF)
        if (ipVal & 0xFF000000) == 0x7F000000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "LOC", countryName: "Loopback Interface (RFC 1122)", flagEmoji: "🔄", asn: "AS-LOCAL", organization: "Host Loopback IPC", isPrivate: true)
        }
        // 169.254.0.0/16 (0xA9FE0000 - 0xA9FEFFFF)
        if (ipVal & 0xFFFF0000) == 0xA9FE0000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "LL", countryName: "Link-Local Address (RFC 3927)", flagEmoji: "🔗", asn: "AS-APIPA", organization: "Zero-Conf Auto-IP", isPrivate: true)
        }
        // Multicast 224.0.0.0/4 (0xE0000000 - 0xEFFFFFFF)
        if (ipVal & 0xF0000000) == 0xE0000000 {
            return GeoIPLookupResult(ip: ipString, countryCode: "MC", countryName: "Multicast Group (RFC 5771)", flagEmoji: "📡", asn: "AS-MCAST", organization: "IGMP/mDNS/SSDP Group", isPrivate: true)
        }

        // 2. Binary search through embedded database
        guard !database.isEmpty else {
            return GeoIPLookupResult(ip: ipString, countryCode: "WAN", countryName: "Public Internet Host", flagEmoji: "🌐", asn: "AS-PUBLIC", organization: "Global Internet Route", isPrivate: false)
        }
        var low = 0
        var high = database.count - 1

        while low <= high {
            let mid = (low + high) / 2
            let entry = database[mid]

            if ipVal >= entry.startIP && ipVal <= entry.endIP {
                return GeoIPLookupResult(
                    ip: ipString,
                    countryCode: entry.countryCode,
                    countryName: entry.countryName,
                    flagEmoji: entry.flag,
                    asn: entry.asn,
                    organization: entry.org,
                    isPrivate: false
                )
            } else if ipVal < entry.startIP {
                high = mid - 1
            } else {
                low = mid + 1
            }
        }

        // Fallback for public IP outside explicit prefix list
        return GeoIPLookupResult(
            ip: ipString,
            countryCode: "WAN",
            countryName: "Public Internet Host",
            flagEmoji: "🌐",
            asn: "AS-PUBLIC",
            organization: "Global Internet Route",
            isPrivate: false
        )
    }

    private static func parseIPv4(_ ip: String) -> UInt32? {
        let parts = ip.components(separatedBy: ".")
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for p in parts {
            guard let b = UInt8(p) else { return nil }
            result = (result << 8) | UInt32(b)
        }
        return result
    }

    private static func makeCIDR(ip: String, prefix: Int, cc: String, name: String, flag: String, asn: String, org: String) -> IPRangeEntry {
        let base = parseIPv4(ip) ?? 0
        let clampedPrefix = max(0, min(32, prefix))
        let mask: UInt32
        if clampedPrefix == 0 {
            mask = 0
        } else if clampedPrefix == 32 {
            mask = 0xFFFFFFFF
        } else {
            mask = (~0 as UInt32) << (32 - clampedPrefix)
        }
        let start = base & mask
        let end = start | ~mask
        return IPRangeEntry(startIP: start, endIP: end, countryCode: cc, countryName: name, flag: flag, asn: asn, org: org)
    }
}
