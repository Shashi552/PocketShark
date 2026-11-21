import Foundation

public enum SecuritySeverity: String, Codable, CaseIterable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"

    public var colorHex: String {
        switch self {
        case .critical: return "#FF1744"
        case .high: return "#FF5252"
        case .medium: return "#FFAB00"
        case .low: return "#00E676"
        }
    }

    public var badgeIcon: String {
        switch self {
        case .critical: return "shield.slash.fill"
        case .high: return "exclamationmark.shield.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .low: return "checkmark.shield.fill"
        }
    }
}

public enum SecurityCategory: String, Codable, CaseIterable {
    case cleartextPassword = "Cleartext Password"
    case decodedBasicAuth = "Decoded Basic Auth"
    case jwtToken = "Exposed JWT Token"
    case leakedCloudKey = "Cloud Secret / API Key"
    case insecureTransmission = "Insecure Data Transmission"
}

public struct SecurityFinding: Identifiable, Hashable, Codable {
    public let id: UUID
    public let timestamp: Double
    public let packetId: Int
    public let category: SecurityCategory
    public let severity: SecuritySeverity
    public let title: String
    public let description: String
    public let secretPreview: String
    public let fullDecodedContent: String
    public let sourceIP: String
    public let destinationIP: String
    public let protocolType: ProtocolType

    public init(
        id: UUID = UUID(),
        timestamp: Double,
        packetId: Int,
        category: SecurityCategory,
        severity: SecuritySeverity,
        title: String,
        description: String,
        secretPreview: String,
        fullDecodedContent: String,
        sourceIP: String,
        destinationIP: String,
        protocolType: ProtocolType
    ) {
        self.id = id
        self.timestamp = timestamp
        self.packetId = packetId
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.secretPreview = secretPreview
        self.fullDecodedContent = fullDecodedContent
        self.sourceIP = sourceIP
        self.destinationIP = destinationIP
        self.protocolType = protocolType
    }
}

public struct JWTClaimInfo: Hashable {
    public let header: String
    public let payload: String
    public let algorithm: String
    public let subject: String?
    public let issuer: String?
    public let expiration: Date?
    public let isExpired: Bool
}

public struct SecurityHunter {

    // Regex matchers for cloud credentials & API keys
    private static let awsKeyPattern = try? NSRegularExpression(pattern: "\\b(AKIA[0-9A-Z]{16})\\b", options: [])
    private static let githubTokenPattern = try? NSRegularExpression(pattern: "\\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\\b", options: [])
    private static let stripeKeyPattern = try? NSRegularExpression(pattern: "\\b(sk_live_[0-9a-zA-Z]{24,32})\\b", options: [])
    private static let openaiKeyPattern = try? NSRegularExpression(pattern: "\\b(sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_\\-]{48,})\\b", options: [])
    private static let googleKeyPattern = try? NSRegularExpression(pattern: "\\b(AIza[0-9A-Za-z\\-_]{35})\\b", options: [])
    private static let slackTokenPattern = try? NSRegularExpression(pattern: "\\b(xox[baprs]-[0-9a-zA-Z]{10,48})\\b", options: [])
    private static let basicAuthPattern = try? NSRegularExpression(pattern: "(?i)Authorization:\\s*Basic\\s+([A-Za-z0-9+/=]+)", options: [])
    private static let jwtPattern = try? NSRegularExpression(pattern: "(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})", options: [])
    private static let passwordParamPattern = try? NSRegularExpression(pattern: "(?i)(password|passwd|pwd|auth_pass|secret|apiKey)=([^&\\s\\r\\n]+)", options: [])
    private static let ftpUserPassPattern = try? NSRegularExpression(pattern: "(?i)^(USER|PASS)\\s+([^\r\n]+)", options: [.anchorsMatchLines])

    public static func inspect(packet: PacketRecord) -> [SecurityFinding] {
        var findings: [SecurityFinding] = []

        // Extract lossy ASCII/UTF-8 representation of the payload safely (capped to 16KB for inspection performance)
        guard packet.rawData.count > 0 else { return findings }
        let inspectedData = packet.rawData.prefix(16384)
        var lossyChars = [Character]()
        lossyChars.reserveCapacity(inspectedData.count)
        for b in inspectedData {
            if (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9 {
                lossyChars.append(Character(UnicodeScalar(b)))
            } else {
                lossyChars.append(" ")
            }
        }
        let lossyString = String(lossyChars)

        let fullRange = NSRange(location: 0, length: lossyString.utf16.count)

        // 1. Check for Basic Auth Leaks
        if let basicRegex = basicAuthPattern {
            let matches = basicRegex.matches(in: lossyString, options: [], range: fullRange)
            for match in matches where match.numberOfRanges > 1 {
                if let b64Range = Range(match.range(at: 1), in: lossyString) {
                    let b64Str = String(lossyString[b64Range]).trimmingCharacters(in: .whitespacesAndNewlines)
                    if let decodedData = Data(base64Encoded: b64Str),
                       let decodedString = String(data: decodedData, encoding: .utf8) {
                        let parts = decodedString.components(separatedBy: ":")
                        let user = parts.first ?? "unknown"
                        let pass = parts.count > 1 ? parts.dropFirst().joined(separator: ":") : ""
                        let maskedPass = pass.count > 2 ? String(pass.prefix(1)) + String(repeating: "*", count: max(1, pass.count - 2)) + String(pass.suffix(1)) : "***"

                        findings.append(SecurityFinding(
                            timestamp: packet.timestamp,
                            packetId: packet.id,
                            category: .decodedBasicAuth,
                            severity: .critical,
                            title: "Exposed Cleartext Basic Auth Credentials",
                            description: "Discovered unencrypted HTTP Basic Authentication transmitting username and password on the wire.",
                            secretPreview: "User: \(user) | Pass: \(maskedPass)",
                            fullDecodedContent: "Decoded Credentials: \(decodedString)\nBase64 Payload: \(b64Str)",
                            sourceIP: packet.source,
                            destinationIP: packet.destination,
                            protocolType: packet.protocolType
                        ))
                    }
                }
            }
        }

        // 2. Check for Cloud API Keys & Secrets
        scanRegex(regex: awsKeyPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .critical, title: "Exposed Amazon AWS Access Key", desc: "Detected AWS Access Key ID (AKIA) transmitting unencrypted in network payload.", findings: &findings)
        scanRegex(regex: githubTokenPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .critical, title: "Exposed GitHub Personal Access Token", desc: "Found sensitive GitHub personal access token (ghp_/github_pat_) exposed in wire capture.", findings: &findings)
        scanRegex(regex: stripeKeyPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .critical, title: "Exposed Stripe Live Secret Key", desc: "High-value financial Stripe live secret API key (sk_live_) captured in payload.", findings: &findings)
        scanRegex(regex: openaiKeyPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .high, title: "Exposed OpenAI API Key", desc: "Detected OpenAI developer API key exposed over cleartext network stream.", findings: &findings)
        scanRegex(regex: googleKeyPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .high, title: "Exposed Google Cloud API Key", desc: "Detected Google Cloud Platform API key (AIza) in packet data.", findings: &findings)
        scanRegex(regex: slackTokenPattern, in: lossyString, packet: packet, category: .leakedCloudKey, severity: .high, title: "Exposed Slack Token", desc: "Detected active Slack Bot or User OAuth Token in packet payload.", findings: &findings)

        // 3. Check for Cleartext Password Parameters
        if let pwdRegex = passwordParamPattern {
            let matches = pwdRegex.matches(in: lossyString, options: [], range: fullRange)
            for match in matches where match.numberOfRanges > 2 {
                if let keyRange = Range(match.range(at: 1), in: lossyString),
                   let valRange = Range(match.range(at: 2), in: lossyString) {
                    let key = String(lossyString[keyRange])
                    let val = String(lossyString[valRange])
                    let maskedVal = val.count > 2 ? String(val.prefix(1)) + String(repeating: "*", count: max(1, val.count - 2)) + String(val.suffix(1)) : "***"

                    findings.append(SecurityFinding(
                        timestamp: packet.timestamp,
                        packetId: packet.id,
                        category: .cleartextPassword,
                        severity: .critical,
                        title: "Cleartext Password Parameter Discovered",
                        description: "Found parameter '\(key)' containing cleartext authentication secrets in application body or URL.",
                        secretPreview: "\(key)=\(maskedVal)",
                        fullDecodedContent: "\(key)=\(val)",
                        sourceIP: packet.source,
                        destinationIP: packet.destination,
                        protocolType: packet.protocolType
                    ))
                }
            }
        }

        // 4. Check for FTP USER / PASS
        if let ftpRegex = ftpUserPassPattern {
            let matches = ftpRegex.matches(in: lossyString, options: [], range: fullRange)
            for match in matches where match.numberOfRanges > 2 {
                if let cmdRange = Range(match.range(at: 1), in: lossyString),
                   let argRange = Range(match.range(at: 2), in: lossyString) {
                    let cmd = String(lossyString[cmdRange]).uppercased()
                    let arg = String(lossyString[argRange]).trimmingCharacters(in: .whitespacesAndNewlines)

                    let isPass = (cmd == "PASS")
                    let masked = isPass ? (arg.count > 2 ? String(arg.prefix(1)) + String(repeating: "*", count: max(1, arg.count - 2)) + String(arg.suffix(1)) : "***") : arg

                    findings.append(SecurityFinding(
                        timestamp: packet.timestamp,
                        packetId: packet.id,
                        category: .cleartextPassword,
                        severity: isPass ? .critical : .medium,
                        title: "Plaintext FTP \(cmd) Authentication",
                        description: "FTP protocol transmitting authentication credentials in plaintext.",
                        secretPreview: "\(cmd) \(masked)",
                        fullDecodedContent: "\(cmd) \(arg)",
                        sourceIP: packet.source,
                        destinationIP: packet.destination,
                        protocolType: packet.protocolType
                    ))
                }
            }
        }

        // 5. Check for JSON Web Tokens (JWT)
        if let jwtRegex = jwtPattern {
            let matches = jwtRegex.matches(in: lossyString, options: [], range: fullRange)
            for match in matches where match.numberOfRanges > 1 {
                if let tokenRange = Range(match.range(at: 1), in: lossyString) {
                    let token = String(lossyString[tokenRange])
                    if let parsed = parseJWT(token: token) {
                        var sev: SecuritySeverity = .medium
                        var note = "Valid structure"
                        if parsed.algorithm.lowercased() == "none" {
                            sev = .critical
                            note = "INSECURE: Alg=none (Unsigned Token Vulnerability)"
                        } else if parsed.isExpired {
                            sev = .low
                            note = "Expired token"
                        } else {
                            sev = .high
                            note = "Live active session token"
                        }

                        let expStr = parsed.expiration.map { "\($0)" } ?? "Never"
                        let maskedToken = String(token.prefix(16)) + "..." + String(token.suffix(10))

                        findings.append(SecurityFinding(
                            timestamp: packet.timestamp,
                            packetId: packet.id,
                            category: .jwtToken,
                            severity: sev,
                            title: "Exposed JSON Web Token (JWT) [\(parsed.algorithm)]",
                            description: "Captured JWT token over network: \(note). Subject: \(parsed.subject ?? "N/A"), Expires: \(expStr)",
                            secretPreview: maskedToken,
                            fullDecodedContent: "Header:\n\(parsed.header)\n\nPayload:\n\(parsed.payload)",
                            sourceIP: packet.source,
                            destinationIP: packet.destination,
                            protocolType: packet.protocolType
                        ))
                    }
                }
            }
        }

        // 6. Check for Private Keys
        if lossyString.contains("BEGIN RSA PRIVATE KEY") || lossyString.contains("BEGIN PRIVATE KEY") || lossyString.contains("BEGIN OPENSSH PRIVATE KEY") {
            findings.append(SecurityFinding(
                timestamp: packet.timestamp,
                packetId: packet.id,
                category: .leakedCloudKey,
                severity: .critical,
                title: "Exposed Cryptographic Private Key",
                description: "Critical risk: PEM-encoded private key discovered in wire data transmission.",
                secretPreview: "-----BEGIN PRIVATE KEY----- ...",
                fullDecodedContent: "PEM Private Key header detected in payload.",
                sourceIP: packet.source,
                destinationIP: packet.destination,
                protocolType: packet.protocolType
            ))
        }

        return findings
    }

    private static func scanRegex(
        regex: NSRegularExpression?,
        in text: String,
        packet: PacketRecord,
        category: SecurityCategory,
        severity: SecuritySeverity,
        title: String,
        desc: String,
        findings: inout [SecurityFinding]
    ) {
        guard let regex = regex else { return }
        let fullRange = NSRange(location: 0, length: text.utf16.count)
        let matches = regex.matches(in: text, options: [], range: fullRange)
        for match in matches where match.numberOfRanges > 1 {
            if let secretRange = Range(match.range(at: 1), in: text) {
                let secret = String(text[secretRange])
                let masked = secret.count > 6 ? String(secret.prefix(4)) + String(repeating: "*", count: max(2, secret.count - 8)) + String(secret.suffix(4)) : "****"

                findings.append(SecurityFinding(
                    timestamp: packet.timestamp,
                    packetId: packet.id,
                    category: category,
                    severity: severity,
                    title: title,
                    description: desc,
                    secretPreview: masked,
                    fullDecodedContent: secret,
                    sourceIP: packet.source,
                    destinationIP: packet.destination,
                    protocolType: packet.protocolType
                ))
            }
        }
    }

    public static func parseJWT(token: String) -> JWTClaimInfo? {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else { return nil }

        guard let headerJson = base64UrlDecode(parts[0]),
              let payloadJson = base64UrlDecode(parts[1]) else {
            return nil
        }

        var algorithm = "UNKNOWN"
        if let hData = headerJson.data(using: .utf8),
           let hDict = try? JSONSerialization.jsonObject(with: hData) as? [String: Any],
           let alg = hDict["alg"] as? String {
            algorithm = alg
        }

        var subject: String? = nil
        var issuer: String? = nil
        var expiration: Date? = nil
        var isExpired = false

        if let pData = payloadJson.data(using: .utf8),
           let pDict = try? JSONSerialization.jsonObject(with: pData) as? [String: Any] {
            subject = pDict["sub"] as? String
            issuer = pDict["iss"] as? String
            if let expVal = pDict["exp"] as? Double, expVal.isFinite && !expVal.isNaN && expVal >= 0 {
                let expDate = Date(timeIntervalSince1970: expVal)
                expiration = expDate
                isExpired = Date() > expDate
            } else if let expInt = pDict["exp"] as? Int, expInt >= 0 {
                let expDate = Date(timeIntervalSince1970: Double(expInt))
                expiration = expDate
                isExpired = Date() > expDate
            }
        }

        return JWTClaimInfo(
            header: headerJson,
            payload: payloadJson,
            algorithm: algorithm,
            subject: subject,
            issuer: issuer,
            expiration: expiration,
            isExpired: isExpired
        )
    }

    public static func base64UrlDecode(_ base64Url: String) -> String? {
        var base64 = base64Url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let mod = base64.count % 4
        if mod > 0 {
            base64 += String(repeating: "=", count: 4 - mod)
        }

        guard let data = Data(base64Encoded: base64) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
