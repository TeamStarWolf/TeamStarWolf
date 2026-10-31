# Flutter

Flutter is an open-source UI toolkit from Google for building apps from a single `dart` codebase. It targets iOS, Android, web, Windows, macOS, and Linux. Flutter draws its own widgets instead of wrapping native controls, which gives consistent rendering across platforms. Teams use it for one codebase, fast iteration through hot reload, and close-to-native performance.

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

- /languages/dart.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /frameworks/react-native.md
- /frameworks/swiftui.md
- /frameworks/dotnet-maui.md
