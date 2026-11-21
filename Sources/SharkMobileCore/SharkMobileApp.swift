#if !BUILDING_CLI
import SwiftUI

@main
public struct SharkMobileApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup("AetherShark // Tactical Airspace & Network Forensics") {
            SharkMobileMainView()
                #if os(macOS)
                .frame(minWidth: 960, minHeight: 680)
                #endif
        }
    }
}
#endif
