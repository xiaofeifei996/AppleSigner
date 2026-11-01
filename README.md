# AppleSigner

Rootless iOS IPA signing and signature-audit tool.

## Source

This repository is being prepared for AppleSigner 1.41.0. Upload the release source archive `AppleSigner-1.41.0-source.zip` to the repository root. The archive should contain the `AppleSigner-1.41.0/` directory with its Theos `Makefile`.

## Automated build

After the source archive is committed, GitHub Actions will:
1. Set up Theos and the iOS SDKs on a macOS runner.
2. Build the rootless Debian package.
3. Publish the resulting `.deb` as a workflow artifact.

Open the **Actions** tab to view build logs and download artifacts.

## Important

A successful package build does not by itself prove installation or runtime compatibility on a jailbroken device. Test the generated package on a supported device before relying on it.
