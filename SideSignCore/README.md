# AppleSignerCore

Swift package boundary for integrating SideStore/SideSign into the AppleSigner RootHide app.

This package is initially isolated from the Theos UIKit target. It must compile for iOS before any Objective-C bridge or production UI integration is attempted.

Current status: scaffold only. No Apple ID authentication, 2FA, certificate enrollment, or IPA signing is exposed yet.
