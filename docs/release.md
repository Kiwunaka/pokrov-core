# Core build and release

The [build manifest](../config/release.json) and [VERSION](../VERSION) own the source version and tool pins. POKROV-app selects the AAR and DLL through its runtime manifest. It also owns device acceptance and the app release. A private Core build for a targeted source change may keep the existing version.

## Build and verify

1. Use the [build commands](../README.md#build) for the affected platform. The Android script verifies the Go, NDK, gomobile and gobind pins. It checks cached Go tools and installs the configured versions when needed. `-Arm64Only` is for an explicit private build. The default AAR contains the ABIs listed in the README. Check the intended app release matrix before binding it.
2. For Windows pass the `libcronet.dll` selected by `engine.cronet_windows_amd64` in the build manifest with `-CronetLibrary`. The Windows script verifies the dependency version, the DLL and the exported C ABI. Keep the sidecar with the built Core DLL.
3. Run `scripts/test.ps1` before a release. It checks [ABI](../config/abi-contract.json) and [events](../config/core-event-abi.json), runs root and engine tests using the shipped module graph and checks formatting. During development run the test for the changed package with the matching client tags. For a changed Windows DLL, run the app lifecycle backtest against that DLL.
4. Bind the built library to the App through its runtime manifest. Verify the affected platform's loaded capabilities and operation before using it in a public app release.

## Publish

1. Set the intended Core version in `VERSION` and `config/release.json`. Use the artifact from that source.
2. After publication approval, create the annotated `vX.Y.Z` tag on the checked source and attach the libraries and required notices to the GitHub release. Keep release assets out of git.
3. For an app rollback, select the retained App artifact and its manifest through the App and Platform release procedure. For a Core-only correction, publish a new tag and update the App binding when ready.
