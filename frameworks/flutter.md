# Flutter

Flutter is an open-source UI toolkit from Google for building apps from a single `dart` codebase. It targets iOS, Android, web, Windows, macOS, and Linux. Flutter draws its own widgets instead of wrapping native controls, which gives consistent rendering across platforms. Teams use it for one codebase, fast iteration through hot reload, and close-to-native performance.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Flutter, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,316 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Flutter application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Dart](/languages/dart.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [React Native](/frameworks/react-native.md), [SwiftUI](/frameworks/swiftui.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Flutter launched in 2017 and reached a stable 1.0 release in late 2018. It uses `dart`, a typed language that compiles ahead of time to native machine code for release builds. Early versions rendered through the Skia engine; newer versions use Impeller for lower-latency shaders.

The framework grew from mobile into web and desktop support over later releases. Its model is declarative: the UI is a function of state, and the framework rebuilds affected parts when state changes. This page focuses on the mobile targets, where storage and transport risks matter most.

## Architecture

Everything visible in Flutter is a widget, and widgets compose into a tree. A widget describes a part of the UI given its current configuration and state. The framework builds three parallel trees: the widget tree, the element tree, and the render tree.

`StatelessWidget` describes UI that depends only on its inputs and does not change on its own. `StatefulWidget` pairs with a `State` object that holds mutable data and triggers rebuilds with `setState`. The render tree handles layout and painting through the engine.

Rendering runs on Skia or Impeller, which rasterize the render tree to the screen. `BuildContext` locates a widget within the tree and gives access to inherited data and theme. Hot reload injects changed `dart` code into the running Dart VM during development, preserving app state.

## Navigation, state, and platform integration

Navigation uses the `Navigator` with a stack of routes, or the declarative `Router` API and packages such as `go_router`. Named routes and typed route objects both work, and deep links map to routes through the platform.

State management ranges from built-in `setState` to packages like `Provider`, `Riverpod`, and `Bloc`. These spread state above the widgets that read it and rebuild only the dependent subtree. Inherited widgets propagate data down the tree without manual passing.

Platform integration uses platform channels, a message-passing bridge between `dart` and native code. A `MethodChannel` sends a method name and arguments to Kotlin or Swift and receives a result. Plugins wrap native SDKs such as the camera, location, and secure storage behind these channels.

## A minimal example

```dart
import 'package:flutter/material.dart';

class Counter extends StatefulWidget {
  const Counter({super.key});

  @override
  State<Counter> createState() => _CounterState();
}

class _CounterState extends State<Counter> {
  int _count = 0;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text('Count: $_count'),
        ElevatedButton(
          onPressed: () => setState(() => _count++),
          child: const Text('Add'),
        ),
      ],
    );
  }
}
```

## Ecosystem and tooling

The Flutter SDK ships the `flutter` command-line tool for building, testing, and running apps. The `pub` package manager pulls dependencies from `pub.dev`. The analyzer and `dart format` enforce style and catch errors before runtime.

DevTools gives a widget inspector, a timeline, and a memory view. Official plugins cover secure storage, HTTP, and platform services. Editor support exists for VS Code and Android Studio with debugging and hot reload wired in.

## Security relevance

This section is the threat-facing view of Flutter: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Compiled mobile apps on Android and iOS, where the shipped package is the attack surface. A Flutter build is recognizable inside an APK or IPA from the engine library `libflutter.so`, the compiled Dart in `libapp.so`, and the `flutter_assets` directory.
- Reverse engineering is the main offensive activity. reFlutter repacks a Flutter app to redirect its traffic, because the engine bundles its own TLS stack and ignores the system proxy and user certificate store; Frida instruments the running process, and MobSF performs static analysis of the package.
- Defensive and audit work follows the OWASP Mobile Application Security project, using MobSF and the MASTG test procedures against the extracted build.
- The dependency surface is pub.dev. A plugin runs with the full permissions of the app, so a compromised or malicious package is a supply-chain exposure, the pattern covered in [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Flutter compiles [Dart](/languages/dart.md), a memory-managed language, to native code, so the dominant classes are storage, transport, and platform-boundary flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)), when tokens or credentials are written to `shared_preferences` instead of the Keychain or Keystore through `flutter_secure_storage`.
- Use of hard-coded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)), since API keys and signing secrets compiled into Dart source or asset files are recoverable from the shipped binary.
- Improper certificate validation ([CWE-295](https://cwe.mitre.org/data/definitions/295.html)), typically a `badCertificateCallback` that returns `true` and defeats transport security.
- Improper input validation ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)) at platform channels and deep links, where arguments crossing to native code or arriving through an unverified link scheme are trusted without checks.

### Why it matters

A Flutter build is readable once unpacked, so recognizing the engine artifacts tells an auditor to look for embedded secrets, plaintext storage, and disabled certificate checks rather than server-side bugs, and signals that ordinary proxy interception will fail without a tool such as reFlutter. MobSF and the MASTG are the mobile-specific references to pair with the review. See [the mobile security reference](/MOBILE_SECURITY_REFERENCE.md) for the cross-cutting method.

## Security model and common vulnerabilities

Flutter apps compile `dart` to native code, but that is not encryption, and the binary can be reverse engineered. Treat the shipped app as readable by an attacker, and map controls to the OWASP Mobile Top 10 and MASVS. See /SECURE_CODING_REFERENCE.md for the cross-language baseline.

Store secrets and tokens in `flutter_secure_storage`, which uses the iOS Keychain and the Android Keystore. Do not keep credentials or tokens in `shared_preferences`, which writes plaintext to disk and maps to CWE-312 (cleartext storage of sensitive information). On Android, `shared_preferences` files sit in app-private storage but are not encrypted.

Hardcoded API keys and signing secrets in `dart` source or asset files are CWE-798 (use of hard-coded credentials). Strings compiled into the app are recoverable with standard tooling, so move secrets server-side and fetch short-lived tokens. Dart obfuscation with `--obfuscate --split-debug-info` raises the cost of reverse engineering but does not hide embedded secrets.

Use HTTPS for all network calls and pin certificates when the threat model needs it. Configure a `SecurityContext` or a pinning package, and reject connections whose certificate or public key does not match (CWE-295, improper certificate validation). Do not disable certificate checks with a custom `badCertificateCallback` that returns `true`.

Platform channels cross a trust boundary, so validate every argument that native code receives from `dart` and the reverse. Treat deep links and incoming intents as untrusted input, and verify link ownership with App Links and Universal Links. Audit third-party plugins, since a plugin runs with the full permissions of the app.

## Performance

Flutter compiles to native ARM or x86 code for release, so there is no JavaScript bridge at runtime. The Impeller engine precompiles shaders to avoid first-run jank during animations. Keep `build` methods cheap, since they can run every frame.

Use `const` constructors so the framework can skip rebuilding unchanged widgets. Split large widgets so `setState` rebuilds a small subtree rather than a whole screen. Profile with DevTools to find layout thrash, expensive painting, and oversized images.

## Common pitfalls

Calling `setState` in a tight loop or inside `build` causes excessive rebuilds and dropped frames. Rebuilding a large subtree for a small change wastes work; lift state only as high as needed. Holding a `BuildContext` after a widget is disposed throws or leaks.

Shipping secrets in assets or `dart` constants exposes them to anyone who unpacks the app. Forgetting to dispose controllers and streams leaks memory over a session. Blocking the UI isolate with heavy work freezes the frame; move it to a background isolate with `compute`.

## Resources

- The Flutter documentation (official).
- The Dart language tour (official).
- The OWASP Mobile Application Security project, including the MASVS and MASTG.

## Related pages

- [Dart](/languages/dart.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [React Native](/frameworks/react-native.md)
- [SwiftUI](/frameworks/swiftui.md)
- [.NET MAUI](/frameworks/dotnet-maui.md)
