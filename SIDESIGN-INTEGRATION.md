# SideSign integration plan

Target branch: `roothide-rewrite`. The existing `roothide` branch and `main` remain untouched.

## Architecture

- Keep AppleSigner as a standalone RootHide application installed by Sileo.
- Keep the existing Objective-C/UIKit shell and Debian packaging while the Swift core is validated independently.
- Add `SideSignCore` as a Swift Package boundary. The app must not handle Apple SRP, Anisette, 2FA, or Developer Portal protocol details itself.
- Expose only narrow, typed operations to the UI: account/session status, authentication challenge, certificate list/create/revoke, profile list/create, and IPA signing.
- Store secrets in Keychain; never log passwords, 2FA codes, anisette data, or session tokens.

## Migration sequence

1. Validate SideSign and all transitive dependencies compile for iOS 15+ on the macOS CI runner.
2. Verify the SideSign public API and runtime requirements on the target RootHide jailbreak environment.
3. Implement authentication and 2FA as a separate Swift service, with explicit cancellation and session expiry handling.
4. Add certificate and provisioning-profile management.
5. Integrate the IPA signing pipeline only after the authentication and signing APIs pass tests.
6. Replace the old experimental signing buttons with a small account / certificates / IPA workflow.

## Important constraints

- This is an integration scaffold, not a working Apple ID login or signer yet.
- SideSign uses Swift 6 and external packages. The current Theos Objective-C app does not automatically link Swift Package products; a dedicated iOS-targeted build/link step is required before calling the Swift engine from UIKit.
- Review and satisfy SideSign's GPL-3.0 licensing obligations before distributing a combined derivative.
- Apple authentication endpoints are private and may change. Never promise permanent login compatibility.
