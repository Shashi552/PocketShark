#if canImport(UIKit) && !os(macOS)
import SwiftUI

@main
public struct SharkMobileApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup {
            SharkMobileMainView()
        }
    }
}
#endif
