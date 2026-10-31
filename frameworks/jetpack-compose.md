# Jetpack Compose

Jetpack Compose is Android's declarative UI toolkit from Google, written in `kotlin`. UI is expressed as composable functions that describe the screen from the current state. Compose Multiplatform extends the same model to desktop, iOS, and web. Teams use it to replace XML layouts with typed `kotlin` code and less boilerplate.

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

- /languages/kotlin.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /frameworks/flutter.md
- /frameworks/swiftui.md
- /frameworks/react-native.md
