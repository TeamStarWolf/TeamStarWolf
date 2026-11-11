# Jetpack Compose

Jetpack Compose is Android's declarative UI toolkit from Google, written in `kotlin`. UI is expressed as composable functions that describe the screen from the current state. Compose Multiplatform extends the same model to desktop, iOS, and web. Teams use it to replace XML layouts with typed `kotlin` code and less boilerplate.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Jetpack Compose, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,227 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Jetpack Compose application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Kotlin](/languages/kotlin.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Flutter](/frameworks/flutter.md), [SwiftUI](/frameworks/swiftui.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Compose reached a stable 1.0 release in 2021 as the modern way to build Android UI. It uses `kotlin` and its compiler plugin to turn composable functions into UI updates. Earlier Android UI used XML layouts with imperative view code.

Compose Multiplatform, built on the same compiler and runtime, targets more platforms. The toolkit integrates with Android lifecycle, navigation, and the existing view system. This page emphasizes the Android storage, permission, and transport concerns.

## Architecture

A composable is a `kotlin` function annotated with `@Composable` that emits UI. The Compose runtime records which composables read which state during composition. When that state changes, the runtime recomposes only the affected functions.

Recomposition is the heart of the model: the framework re-runs composables whose inputs changed and skips the rest. State lives outside the function call so it survives recomposition. `remember` caches a value across recompositions, and `mutableStateOf` creates an observable value that triggers recomposition when written.

Compose follows unidirectional data flow: state flows down into composables, and events flow up through callbacks. A composable should not hold hidden mutable state; it reads state and reports events. This keeps the UI a predictable function of its inputs.

## Navigation, state, and platform integration

Navigation uses the Navigation Compose library with a `NavController` and a graph of destinations. Routes carry typed arguments, and deep links map external URIs to destinations. The library handles the back stack and transitions.

State uses `remember` and `mutableStateOf` for local values and a `ViewModel` for screen-scoped state that survives configuration changes. `StateFlow` and `collectAsStateWithLifecycle` bridge coroutine state into composition. Hoisting state to the caller keeps composables reusable and testable.

Compose runs inside an `Activity` and respects the Android lifecycle. `LaunchedEffect` and `DisposableEffect` tie coroutines and cleanup to composition. `AndroidView` embeds classic Android views where a Compose equivalent is missing.

## A minimal example

```kotlin
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.*

@Composable
fun Counter() {
    var count by remember { mutableStateOf(0) }
    Column {
        Text("Count: $count")
        Button(onClick = { count++ }) {
            Text("Add")
        }
    }
}
```

## Ecosystem and tooling

Android Studio provides Compose previews, a layout inspector, and live edit. Gradle builds the app and applies the Compose compiler plugin. The AndroidX libraries supply navigation, lifecycle, and Material components.

Material 3 ships ready-made components and theming. Testing uses the Compose test rule to find and assert on nodes by semantics. The Compose compiler reports on recomposition stability to help tune performance.

## Security relevance

This section is the threat-facing view of Jetpack Compose: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Compiled Android apps, where the shipped APK or App Bundle is the attack surface. A Compose build is recognizable from the `androidx.compose` runtime and Material packages visible once the app is decompiled.
- Reverse engineering drives the offensive work: jadx and apktool unpack and decompile the app, Frida and objection instrument it at runtime, and MobSF performs static analysis.
- Defensive and audit work follows the OWASP Mobile Application Security project, with MobSF and the MASTG test procedures run against the extracted build, and Android lint on the source.
- The dependency surface is Gradle resolving Maven artifacts, including AndroidX and third-party AARs. A compromised library is compiled in with the full permissions of the app, the pattern covered in [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Jetpack Compose runs on [Kotlin](/languages/kotlin.md) on the Android runtime, a memory-managed platform, so the dominant classes are storage, component-exposure, and transport flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)), when tokens are written to plain `SharedPreferences` rather than an encrypted store backed by the Android Keystore.
- Improper export of Android application components ([CWE-926](https://cwe.mitre.org/data/definitions/926.html)), where an activity, service, receiver, or provider left exported is reachable and triggerable by other apps on the device.
- Improper certificate validation ([CWE-295](https://cwe.mitre.org/data/definitions/295.html)), typically a `TrustManager` that accepts every certificate and defeats transport security.
- Cross-site scripting in a `WebView` ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)), where enabling JavaScript or `addJavascriptInterface` for untrusted content exposes an injection path into native methods.

### Why it matters

Private per-app storage is isolation, not encryption, so recognizing a Compose app tells an auditor to unpack it and look for plaintext secrets, exported components reachable by other apps, and disabled certificate checks rather than server-side bugs. jadx, Frida, and MobSF are the mobile tools to pair with the review, and the component manifest shows the local attack surface at a glance. See [the mobile security reference](/MOBILE_SECURITY_REFERENCE.md) for the cross-cutting method.

## Security model and common vulnerabilities

Android isolates each app with its own user ID and private storage, but that is not encryption at rest. Align controls with the OWASP Mobile Top 10 and MASVS, and see /SECURE_CODING_REFERENCE.md for the shared baseline. Assume rooted devices and inspectable storage.

Store secrets and tokens with the Android Keystore, which keeps key material in hardware-backed storage where available. Use an encrypted store built on the Keystore rather than plain `SharedPreferences`, which writes an unencrypted XML file (CWE-312, cleartext storage of sensitive information). The older `EncryptedSharedPreferences` provided this through Jetpack Security; check its current status and choose a maintained encrypted-storage option backed by the Keystore.

Review exported components. An `activity`, `service`, `receiver`, or `provider` with `android:exported="true"` or an intent filter is reachable by other apps (CWE-926, improper export of Android application components). Set `exported` to `false` unless external access is required, and enforce permissions and validate every incoming `Intent` extra.

Set a network security configuration that disables cleartext traffic with `cleartextTrafficPermitted="false"`. Pin certificates in that config or with an OkHttp `CertificatePinner`, and reject a mismatch (CWE-295, improper certificate validation). Do not ship a `TrustManager` that accepts all certificates.

A `WebView` that enables JavaScript or `addJavascriptInterface` with untrusted content is an injection risk. Limit loaded origins, avoid exposing native methods to remote pages, and validate any bridge payload. Treat deep links as untrusted input, and verify ownership with Android App Links instead of unverified custom schemes.

## Performance

Compose skips recomposing functions whose inputs are unchanged when their parameters are stable. Keep state reads narrow so a change recomposes a small subtree. Avoid reading frequently changing state high in the tree.

Use `key` in `LazyColumn` items so the runtime reuses nodes correctly. Defer reads with lambdas, such as passing a state provider instead of a value, to limit recomposition scope. Enable R8 with full mode for smaller, optimized release builds and profile with the Layout Inspector.

## Common pitfalls

Writing secrets to plain `SharedPreferences` is a common storage mistake. Leaving components exported by default exposes them to other apps. Reading an unstable or ever-changing value at the top of a screen causes constant recomposition.

Doing work directly in a composable body, rather than in an effect, runs it on every recomposition. Forgetting `remember` recreates state on each pass and resets the UI. Enabling JavaScript in a `WebView` for untrusted content opens an injection path.

## Resources

- The Android Jetpack Compose documentation (official).
- The Kotlin documentation (official).
- The OWASP Mobile Application Security project, including the MASVS and MASTG.

## Related pages

- [Kotlin](/languages/kotlin.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Flutter](/frameworks/flutter.md)
- [SwiftUI](/frameworks/swiftui.md)
- [React Native](/frameworks/react-native.md)
