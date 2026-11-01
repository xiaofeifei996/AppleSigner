import Foundation
import SideSign

/// Narrow application-facing boundary around SideSign.
/// Keep Apple ID credentials and authentication state inside the SideSign layer;
/// the UIKit application should only receive safe status and operation results.
public actor AppleSignerEngine {
    public static let shared = AppleSignerEngine()

    public enum State: Sendable, Equatable {
        case notConfigured
        case ready
    }

    public init() {}

    public func currentState() -> State {
        // Authentication/session APIs will be wired after validating the
        // exact SideSign public API and iOS/RootHide runtime compatibility.
        return .notConfigured
    }
}
