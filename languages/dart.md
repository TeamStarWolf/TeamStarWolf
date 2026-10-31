# Dart

Dart is a statically typed, object-oriented language created by Google and first released in 2011. It compiles to native machine code and to JavaScript, and it is the language of the Flutter user-interface toolkit. It is used primarily for cross-platform mobile, web, and desktop applications built with Flutter, and for command-line tools and back-end services.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, class-based, with functional features |
| Typing | Static, strong, with sound null safety and inference |
| First appeared | 2011 |
| Memory model | Automatic garbage collection |
| Reference implementation | [Dart SDK](https://github.com/dart-lang/sdk) |
| Typical uses | Flutter apps (mobile, web, desktop), command-line tools, back ends |
| Governance | [Google](https://dart.dev/) with the ECMA TC52 standard |

Related: [Swift](/languages/swift.md), [Kotlin](/languages/kotlin.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Google released Dart in 2011, originally aimed at web programming as an alternative to JavaScript. Its trajectory changed with [Flutter](https://flutter.dev/), Google's cross-platform user-interface toolkit, for which Dart is the application language. Dart 2 (2018) made the type system sound, and Dart 2.12 (2021) introduced sound null safety. The language is standardized as [ECMA-408](https://ecma-international.org/publications-and-standards/standards/ecma-408/) and documented at [dart.dev](https://dart.dev/).

Dart has two execution paths: a just-in-time compiler with hot reload for fast development, and an ahead-of-time compiler that produces native machine code for release builds. It can also compile to JavaScript and WebAssembly for the web.

## Paradigm and type system

Dart is class-based and object-oriented, where every value is an object, including numbers and functions. The type system is sound and statically checked with inference, and null safety makes a type non-nullable by default: a value that may be null has a type with a trailing `?`, and the compiler requires a check before use. Generics are reified, so type arguments are available at run time, unlike Java's erased generics.

```dart
double total(List<double> prices, [double tax = 0]) =>
    prices.fold(0, (a, b) => a + b) * (1 + tax);

String? name;
final length = name?.length ?? 0; // null-aware access and default
```

The `late` keyword defers initialization of a non-nullable field, and `sealed` classes (Dart 3) support exhaustive pattern matching with `switch` expressions.

## Toolchain and ecosystem

- SDK and runtime: the `dart` CLI compiles, runs, and tests code; the `flutter` CLI wraps it for application development.
- Packaging and dependencies: packages publish to [pub.dev](https://pub.dev/) and are declared in `pubspec.yaml`; `dart pub get` resolves them.
- Formatting and linting: `dart format` formats code, and the built-in analyzer with the [lints](https://pub.dev/packages/lints) package reports style and defect issues.

```bash
dart create -t console app
cd app
dart run
```

## Syntax tour

```dart
// Entry point, variables, and string interpolation
void main() {
  final name = 'world';
  print('hello, $name');

  // Collections and functional transforms
  final squares = [for (var n = 0; n < 5; n++) n * n];
  final lookup = {'a': 1, 'b': 2};

  // Null safety
  String? maybe;
  final length = maybe?.length ?? 0;

  // Pattern matching with sealed classes (Dart 3)
  final shape = Circle(2.0);
  final describe = switch (shape) {
    Circle(:final radius) => 'circle $radius',
    Square(:final side) => 'square $side',
  };
  print(describe);
}

sealed class Shape {}
class Circle extends Shape {
  final double radius;
  Circle(this.radius);
}
class Square extends Shape {
  final double side;
  Square(this.side);
}
```

## Idioms and different approaches

- Use `final` for bindings that do not change and `const` for compile-time constants.
- Model absence with nullable types and the null-aware operators `?.`, `??`, and `??=` rather than sentinel values.
- Prefer collection `if` and `for` and spread (`...`) inside list and map literals to build collections declaratively.
- In Flutter, compose user interfaces from small widgets and keep `build` methods pure functions of state.
- Use `async`/`await` and `Stream` for asynchronous work instead of manual callbacks.

## Design principles

Dart aims for productive application development: fast iteration through hot reload during development, predictable native performance in release builds, and a type system that is sound so the compiler can trust type information. Null safety is designed to be sound, meaning a non-nullable type genuinely cannot hold null, which removes a class of runtime errors. The language favors a familiar C-style syntax to lower the barrier for new developers.

## Standard library and notable packages

The core libraries include `dart:core` (numbers, strings, collections), `dart:async` (`Future`, `Stream`), `dart:io` for files and sockets on native platforms, and `dart:convert` for JSON and other encodings. The dominant framework is [Flutter](https://flutter.dev/) for user interfaces. Notable packages on [pub.dev](https://pub.dev/) include [http](https://pub.dev/packages/http) for networking, [provider](https://pub.dev/packages/provider) and [riverpod](https://pub.dev/packages/riverpod) for state management, and [json_serializable](https://pub.dev/packages/json_serializable) for code-generated serialization.

## Testing and packaging

The [test](https://pub.dev/packages/test) package is the standard test framework, and Flutter adds `flutter_test` for widget tests, run with `dart test` or `flutter test`.

```dart
import 'package:test/test.dart';

void main() {
  test('adds two numbers', () {
    expect(2 + 3, equals(5));
  });
}
```

Libraries package as pub packages described by `pubspec.yaml` and publish to [pub.dev](https://pub.dev/). Native applications compile ahead-of-time to standalone executables; Flutter apps build to platform bundles such as APK, AAB, and IPA.

## Performance and concurrency

The development workflow uses a just-in-time compiler with hot reload, and release builds use ahead-of-time compilation to native code for fast startup and predictable performance. Concurrency uses isolates: each isolate has its own memory and runs on its own thread, and isolates communicate by passing messages rather than sharing memory, so there are no data races between them. Within an isolate, the event loop drives `Future` and `Stream` based asynchronous code.

- `async`/`await` and `Future` handle single asynchronous results.
- `Stream` handles sequences of asynchronous events.
- `Isolate.spawn` and `Isolate.run` move CPU-bound work off the main isolate without shared mutable state.

## Common pitfalls

- The `late` keyword defers a non-nullable initialization; reading it before assignment throws at run time, which reintroduces a null-like failure.
- A null-assertion `!` on a nullable value throws if the value is null; prefer explicit checks.
- Long synchronous work on the main isolate blocks the event loop and, in Flutter, freezes the user interface; offload it to another isolate.
- Forgetting to `await` a `Future` lets work run unordered and swallows errors.
- In Flutter, rebuilding large widget subtrees unnecessarily hurts performance; keep state local and use `const` widgets.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Cross-site scripting in Dart web output: escape or sanitize untrusted data before inserting it into the DOM, and avoid unsafe HTML sinks, which addresses [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- SQL injection: use parameterized queries with bound values in database packages rather than string interpolation, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Insecure data storage on mobile: store secrets with platform secure storage (Keychain or Keystore through a plugin) rather than shared preferences or plain files, addressing [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Improper certificate validation: do not override `badCertificateCallback` to accept all certificates, which maps to [CWE-295](https://cwe.mitre.org/data/definitions/295.html).
- Dependency supply chain: pin and review pub.dev dependencies, including transitive ones; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the built-in `dart analyze` with the [lints](https://pub.dev/packages/lints) rule set flags risky and low-quality code, and `dart pub outdated` surfaces dependency updates. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [dart.dev](https://dart.dev/) documentation and the [language tour](https://dart.dev/language), the primary sources.
- [Flutter documentation](https://docs.flutter.dev/) for application development.
- [Effective Dart](https://dart.dev/effective-dart) for style and design guidance.

## Related pages

- [Swift](/languages/swift.md)
- [Kotlin](/languages/kotlin.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
