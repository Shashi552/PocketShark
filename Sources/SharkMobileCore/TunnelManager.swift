import Foundation
import NetworkExtension

#if canImport(UIKit)
import UIKit
#endif

// MARK: - 1. SharkMobile Local VPN & Packet Interceptor Manager
@MainActor
public final class SharkVPNManager: ObservableObject {
    public static let shared = SharkVPNManager()

    public enum VPNState: String {
        case disconnected = "Disconnected"
        case connecting = "Connecting..."
        case connected = "Connected (utun0 Tap Active)"
        case disconnecting = "Disconnecting..."
        case profileInstalled = "VPN Profile Installed (Ready)"
        case error = "Configuration Error"
    }

    @Published public var state: VPNState = .disconnected
    @Published public var statusMessage: String = "Standby"
    @Published public var isInstalled: Bool = false
    @Published public var interceptedPacketCount: Int = 0

    private var tunnelManager: NETunnelProviderManager?

    public init() {
        refreshVPNStatus()
    }

    public func refreshVPNStatus() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let err = error {
                    self.statusMessage = "Load error: \(err.localizedDescription)"
                    return
                }
                if let existing = managers?.first {
                    self.tunnelManager = existing
                    self.isInstalled = true
                    let status = existing.connection.status
                    switch status {
                    case .connected:
                        self.state = .connected
                        self.statusMessage = "100% Device Traffic Intercepted on utun0"
                    case .connecting:
                        self.state = .connecting
                        self.statusMessage = "Establishing local tunnel..."
                    case .disconnecting:
                        self.state = .disconnecting
                        self.statusMessage = "Halting tunnel..."
                    default:
                        self.state = .profileInstalled
                        self.statusMessage = "Profile installed in iOS/macOS Settings"
                    }
                } else {
                    self.isInstalled = false
                    self.state = .disconnected
                    self.statusMessage = "No local VPN profile installed"
                }
            }
        }
    }

    public func setupAndEnableVPN(completion: ((Bool) -> Void)? = nil) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.shashank.sharkmobile.tunnel"
            proto.serverAddress = "127.0.0.1"
            proto.disconnectOnSleep = false

            manager.protocolConfiguration = proto
            manager.localizedDescription = "SharkMobile Packet Interceptor"
            manager.isEnabled = true

            manager.saveToPreferences { [weak self] saveError in
                Task { @MainActor [weak self] in
                    guard let self = self else { return }
                    if let err = saveError {
                        self.state = .error
                        self.statusMessage = "Failed to save profile: \(err.localizedDescription)"
                        completion?(false)
                        return
                    }
                    self.tunnelManager = manager
                    self.isInstalled = true
                    self.startTunnelSession(manager: manager, completion: completion)
                }
            }
        }
    }

    public func startTunnelSession(manager: NETunnelProviderManager, completion: ((Bool) -> Void)? = nil) {
        manager.loadFromPreferences { [weak self] loadError in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let err = loadError {
                    self.state = .error
                    self.statusMessage = "Preference reload failed: \(err.localizedDescription)"
                    completion?(false)
                    return
                }
                do {
                    try manager.connection.startVPNTunnel(options: nil)
                    self.state = .connected
                    self.statusMessage = "Local VPN Active: Intercepting Wi-Fi & Cellular on utun0"
                    PacketTunnelBridge.shared.start()
                    completion?(true)
                } catch {
                    self.state = .profileInstalled
                    self.statusMessage = "VPN Profile saved. Activate in Settings > VPN or via .mobileconfig"
                    completion?(false)
                }
            }
        }
    }

    public func stopVPN() {
        guard let manager = tunnelManager else { return }
        manager.connection.stopVPNTunnel()
        self.state = .disconnected
        self.statusMessage = "Tunnel stopped"
        PacketTunnelBridge.shared.stop()
    }

    /// Generates a standard Apple .mobileconfig Configuration Profile
    /// Anyone can install this profile on iOS (Settings > Profile Downloaded) without jailbreak or root.
    /// It automatically routes device HTTP/HTTPS traffic through SharkMobile's local proxy tap on 127.0.0.1:8888!
    public func generateMobileConfig() -> Data {
        let uuidPayload = UUID().uuidString
        let uuidProfile = UUID().uuidString
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Configures local loopback packet interceptor for SharkMobile Wireshark Sniffer</string>
                    <key>PayloadDisplayName</key>
                    <string>SharkMobile Packet Interceptor</string>
                    <key>PayloadIdentifier</key>
                    <string>com.shashank.sharkmobile.vpn.\(uuidPayload)</string>
                    <key>PayloadType</key>
                    <string>com.apple.vpn.managed</string>
                    <key>PayloadUUID</key>
                    <string>\(uuidPayload)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>Proxies</key>
                    <dict>
                        <key>HTTPEnable</key>
                        <integer>1</integer>
                        <key>HTTPPort</key>
                        <integer>8888</integer>
                        <key>HTTPProxy</key>
                        <string>127.0.0.1</string>
                        <key>HTTPSEnable</key>
                        <integer>1</integer>
                        <key>HTTPSPort</key>
                        <integer>8888</integer>
                        <key>HTTPSProxy</key>
                        <string>127.0.0.1</string>
                    </dict>
                    <key>UserDefinedName</key>
                    <string>SharkMobile Local Interceptor</string>
                    <key>VPNType</key>
                    <string>VPN</string>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>SharkMobile Wireshark Sniffer Configuration</string>
            <key>PayloadIdentifier</key>
            <string>com.shashank.sharkmobile.profile.\(uuidProfile)</string>
            <key>PayloadOrganization</key>
            <string>SharkMobile Security</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuidProfile)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
        return Data(xml.utf8)
    }
}

// MARK: - 2. Native Apple NEPacketTunnelProvider Implementation
open class SharkPacketTunnelProvider: NEPacketTunnelProvider {
    open override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // Route all IPv4 traffic (0.0.0.0/0) through the tunnel interface
        let ipv4 = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // DNS Servers
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let err = error {
                completionHandler(err)
                return
            }
            self?.readPacketsContinuously()
            completionHandler(nil)
        }
    }

    private func readPacketsContinuously() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            PacketTunnelBridge.shared.handleIncomingPackets(packets: packets, protocols: protocols, interface: "utun0 (VPN Interceptor)")
            // Loop for continuous uninterrupted ingestion
            self.readPacketsContinuously()
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        PacketTunnelBridge.shared.stop()
        completionHandler()
    }
}
