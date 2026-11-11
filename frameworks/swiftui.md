# SwiftUI

SwiftUI is Apple's declarative UI framework for building apps across iOS, iPadOS, macOS, watchOS, tvOS, and visionOS. It is written in `swift` and describes the UI as a function of state. The framework diffs that description and updates the native views it manages. Teams use it for concise code, live previews, and one UI model across Apple platforms.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with SwiftUI, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,250 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a SwiftUI application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Swift](/languages/swift.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Flutter](/frameworks/flutter.md), [Jetpack Compose](/frameworks/jetpack-compose.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Apple introduced SwiftUI in 2019 as the successor to imperative UIKit and AppKit layouts. It uses `swift` and its result builders to express view hierarchies as nested values. Each release added capabilities such as `NavigationStack`, the `Observation` framework, and richer layout.

SwiftUI coexists with UIKit and AppKit, and apps often mix the two. Views are value types, cheap to create and discard, and the framework owns their lifecycle. This page covers the mobile-relevant storage, transport, and permission concerns.

## Architecture

A SwiftUI view is a `struct` conforming to the `View` protocol with a `body` property. The `body` returns a tree of other views built by a result builder. Views are lightweight descriptions, not long-lived objects, so the framework recreates them freely.

State drives the UI. `@State` holds a view's own mutable value, and `@Binding` passes a mutable reference to a child. The `@Observable` macro marks a model class whose property reads are tracked, so views that read a property update when it changes.

When state changes, SwiftUI recomputes the affected `body` values and diffs them against the previous tree. It then applies the minimal set of updates to the underlying native views. This update cycle is automatic, so views stay a pure function of their inputs.

## Navigation, state, and platform integration

`NavigationStack` models a push-and-pop stack with a typed path you can read and set. Value-based destinations with `navigationDestination` map a data type to a view. Sheets, popovers, and alerts present over the current view through state bindings.

State scopes to its owner. `@State` is local, `@Binding` shares write access, and `@Environment` reads values injected down the tree. Shared models use `@Observable` classes held with `@State` and passed into the environment.

SwiftUI bridges to UIKit through `UIViewRepresentable` and to AppKit through `NSViewRepresentable`. Asynchronous work uses `swift` concurrency with `async`/`await` and the `.task` modifier. Combine remains available for reactive pipelines where it fits.

## A minimal example

```swift
import SwiftUI

struct CounterView: View {
    @State private var count = 0

    var body: some View {
        VStack {
            Text("Count: \(count)")
            Button("Add") {
                count += 1
            }
        }
    }
}
```

## Ecosystem and tooling

Xcode is the primary tool, with live previews that render views as you edit. The Swift Package Manager pulls dependencies and builds them into the app. Instruments profiles CPU, memory, and energy use.

Apple frameworks cover storage, networking, and device features that SwiftUI calls into. The Observation and Combine frameworks handle reactive state. Previews and snapshot tests give fast visual feedback during development.

## Security relevance

This section is the threat-facing view of SwiftUI: how an app built with it appears to an attacker or an auditor who holds the device or the compiled binary, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Compiled native apps across Apple platforms, shipped as signed bundles. The attack surface is the local device and the app's network calls, not a server the framework runs, so review starts from the installed app rather than a URL.
- A SwiftUI app is recognized by inspecting the Mach-O binary and bundle: Swift and SwiftUI symbols, embedded frameworks, and the `Info.plist`.
- Offensive tooling is the mobile set: Frida and objection for runtime instrumentation, Hopper or Ghidra and class-dump for static analysis, Keychain-dumper on a jailbroken device, and MobSF for automated scanning of the bundle.
- The dependency surface is Swift Package Manager and CocoaPods. A third-party SDK runs with full app privilege and can read the same storage and traffic the app does.

### Dominant weakness classes

SwiftUI runs on Swift, a memory-managed language with automatic reference counting, so the dominant classes in app code are insecure storage, transport, and platform-trust flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) when tokens or credentials sit in `UserDefaults` or unprotected files instead of the Keychain and Data Protection.
- Improper certificate validation ([CWE-295](https://cwe.mitre.org/data/definitions/295.html)) from a broad App Transport Security exception or missing certificate pinning, which opens traffic to interception.
- Improper authentication ([CWE-287](https://cwe.mitre.org/data/definitions/287.html)) when a local biometric gate is treated as the authorization control, leaving a bypass on a compromised device.
- Improper input validation ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)) of incoming deep links and universal links whose host and path are not confirmed.

### Why it matters

Recognizing a SwiftUI app tells an auditor to pull the bundle and work from the device inward: enumerate Keychain versus `UserDefaults` storage, check the `Info.plist` for App Transport Security exceptions and the network layer for pinning, and exercise every deep-link handler. MobSF and the OWASP MASTG procedures are the mobile-specific audit tools for that work. See [the mobile security reference](/MOBILE_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Apple sandboxes each app, but local data is only as protected as where you put it. Align controls with the OWASP Mobile Top 10 and MASVS, and see /SECURE_CODING_REFERENCE.md for the shared baseline. Assume the device may be lost, jailbroken, or inspected.

Store secrets, tokens, and credentials in the Keychain, which encrypts items and ties them to the device and app. Do not keep sensitive values in `UserDefaults`, which writes a plaintext property list inside the app container (CWE-312, cleartext storage of sensitive information). Choose a Keychain accessibility class such as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` to limit exposure.

Use Data Protection so files are encrypted while the device is locked. Set a file protection class such as `.completeFileProtection` on files that hold sensitive data, rather than leaving them unprotected (CWE-311, missing encryption of sensitive data). Data Protection keys derive from the device passcode, so it only helps when a passcode is set.

App Transport Security requires TLS by default; do not add broad `NSAllowsArbitraryLoads` exceptions to disable it. For stronger assurance, pin certificates or public keys with a `URLSession` delegate and reject a mismatch (CWE-295, improper certificate validation). Keep any exceptions narrow and documented.

Gate sensitive actions with `LocalAuthentication` using Face ID or Touch ID, and fall back to the passcode. Treat biometric checks as a local gate, not as a replacement for server-side authorization. Validate incoming deep links and universal links: confirm the host and path, and prefer universal links whose domain ownership is verified.

## Performance

SwiftUI recomputes `body` often, so keep it fast and free of heavy work. Narrow the scope of state so a change updates a small part of the tree. Use `@State` and observed models precisely to avoid updating unrelated views.

Lazy containers such as `LazyVStack` and `List` build only visible rows. Stable identities with `id` help the diffing algorithm reuse views. Profile with Instruments to find slow `body` recomputation and oversized view hierarchies.

## Common pitfalls

Putting sensitive data in `UserDefaults` is a common storage mistake. Doing network or disk work directly in `body` runs it on every recomputation. Overusing a single large observable model forces wide updates across the screen.

Forgetting identities in a `ForEach` causes wrong animations and reused state. Adding a blanket ATS exception to ship quickly leaves traffic open to downgrade. Relying on biometrics alone without server checks leaves a bypass on a compromised device.

## Resources

- The Apple SwiftUI documentation and Human Interface Guidelines (official).
- The Swift language guide (official).
- The OWASP Mobile Application Security project, including the MASVS and MASTG.

## Related pages

- [Swift](/languages/swift.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Flutter](/frameworks/flutter.md)
- [Jetpack Compose](/frameworks/jetpack-compose.md)
- [React Native](/frameworks/react-native.md)
