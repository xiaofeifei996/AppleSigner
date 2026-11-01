import Foundation
import SideSign

/// Application-facing authentication boundary around SideSign.
/// Credentials are passed directly to SideSign and are never persisted by this engine.
public actor AppleSignerEngine {
    public static let shared = AppleSignerEngine()

    public enum State: Sendable, Equatable {
        case notConfigured
        case ready
        case authenticating
        case authenticated
    }

    private var state: State = .notConfigured
    private var authSession: AuthSession?

    public init() {}

    public func currentState() -> State {
        state
    }

    /// Authenticate using caller-provided Anisette data.
    /// The verification handler is invoked by SideSign when Apple requires 2FA.
    public func signIn(
        appleID: String,
        password: String,
        anisetteData: AnisetteData,
        xcodeVersion: String,
        verificationHandler: DeveloperPortal.VerificationHandler? = nil
    ) async throws {
        state = .authenticating
        do {
            let result = try await DeveloperPortal.shared.authenticate(
                appleID: appleID,
                password: password,
                anisetteData: anisetteData,
                xcodeVersion: xcodeVersion,
                verificationHandler: verificationHandler
            )
            authSession = result
            state = .authenticated
        } catch {
            authSession = nil
            state = .ready
            throw error
        }
    }

    /// Clears the in-memory authenticated session.
    public func signOut() {
        authSession = nil
        state = .ready
    }

    /// Internal application access for subsequent Developer Portal operations.
    public func currentAuthSession() -> AuthSession? {
        authSession
    }
}
