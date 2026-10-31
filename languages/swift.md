# Swift

Swift is a statically typed, compiled language created by Apple and first released in 2014 as a successor to Objective-C for Apple platforms. It compiles to native code through LLVM and manages memory with automatic reference counting rather than a tracing garbage collector. It is used for iOS, macOS, watchOS, and tvOS applications, and increasingly for server-side back ends and cross-platform code.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: object-oriented, protocol-oriented, functional |
| Typing | Static, strong, with inference and null tracking (optionals) |
| First appeared | 2014 |
| Memory model | Automatic reference counting (ARC), deterministic |
| Reference implementation | [Apple Swift (swiftlang)](https://github.com/swiftlang/swift) |
| Typical uses | iOS and macOS apps, server back ends, cross-platform code |
| Governance | [Swift.org](https://www.swift.org/) open-source project led by Apple |

Related: [Objective-C](/languages/objective-c.md), [Kotlin](/languages/kotlin.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Apple announced Swift at its 2014 developer conference and open-sourced it in 2015 under the Apache License with a runtime library exception. It was designed by a team led by Chris Lattner, who also created LLVM, and it interoperates with Objective-C so existing Apple frameworks remain usable. The language is developed in the open at [Swift.org](https://www.swift.org/) through the Swift Evolution proposal process, and it runs on Apple platforms, Linux, and Windows.

Major milestones include a stable application binary interface in Swift 5 (2019) and the concurrency model with `async`/`await` and actors in Swift 5.5 (2021). The compiler and standard library are hosted under the [swiftlang](https://github.com/swiftlang/swift) organization.

## Paradigm and type system

Swift is statically typed with type inference, generics, and protocols that support both classes and value types. Its defining safety feature is the optional: a type is non-optional by default, and a value that may be absent has an optional type written with a trailing `?`, which the compiler forces the programmer to unwrap before use. Structures and enumerations are value types with value semantics; classes are reference types. Protocol-oriented programming, with protocol extensions providing default implementations, is a central idiom.

```swift
func total(prices: [Double], tax: Double = 0) -> Double {
    prices.reduce(0, +) * (1 + tax)
}

let name: String? = nil
let length = name?.count ?? 0   // optional chaining and nil-coalescing
```

Enumerations can carry associated values, which models sum types, and the compiler checks that a `switch` over them is exhaustive.

## Toolchain and ecosystem

- Compiler and runtime: `swiftc` compiles source to native code; `swift` runs scripts and a read-eval-print loop.
- Build and dependencies: the [Swift Package Manager](https://www.swift.org/package-manager/) builds projects and resolves dependencies declared in `Package.swift`. On Apple platforms, Xcode is the common development environment.
- Formatting and linting: [swift-format](https://github.com/swiftlang/swift-format) formats code, and [SwiftLint](https://github.com/realm/SwiftLint) enforces style and conventions.

```bash
swift package init --type executable
swift build
swift run
```

## Syntax tour

```swift
// Constants, variables, and string interpolation
let name = "world"
print("hello, \(name)")

// Collections and functional transforms
let squares = (0..<5).map { $0 * $0 }
let lookup = ["a": 1, "b": 2]

// Optionals and safe unwrapping
let maybe: String? = readLine()
if let value = maybe {
    print(value)
}

// Enum with associated values and exhaustive switch
enum Shape {
    case circle(radius: Double)
    case square(side: Double)
}

func area(_ shape: Shape) -> Double {
    switch shape {
    case .circle(let r): return .pi * r * r
    case .square(let s): return s * s
    }
}

// Struct (value type) with a protocol
struct Point: Equatable {
    var x: Int
    var y: Int
}
```

## Idioms and different approaches

- Prefer value types (`struct`, `enum`) over classes unless identity or shared mutable state is required.
- Model absence with optionals and unwrap them with `if let`, `guard let`, or `??`; avoid force-unwrapping with `!`.
- Use `guard` for early exit so the happy path stays unindented.
- Define shared behavior with protocols and protocol extensions rather than base classes.
- Prefer `let` for immutable bindings and mark mutating struct methods explicitly.

## Design principles

Swift's stated goals are safety, speed, and expressiveness. Safety comes from optionals, bounds checks, exclusive access to memory, and value semantics; speed comes from compiling to native code with LLVM and avoiding a tracing collector; expressiveness comes from inference, generics, and protocol-oriented design. The language is designed to make the safe path the default and the unsafe path explicit.

## Standard library and notable frameworks

The standard library provides value-type collections (`Array`, `Dictionary`, `Set`), `String` with full Unicode handling, `Optional`, `Result`, and the concurrency primitives. On Apple platforms, [SwiftUI](https://developer.apple.com/xcode/swiftui/) and UIKit build user interfaces, and Foundation provides dates, networking, and file access. On the server, [Vapor](https://vapor.codes/) and [Hummingbird](https://hummingbird.codes/) build web services, and [swift-nio](https://github.com/apple/swift-nio) provides asynchronous networking.

## Testing and packaging

The [XCTest](https://developer.apple.com/documentation/xctest) framework and the newer [Swift Testing](https://github.com/swiftlang/swift-testing) library are the test frameworks, run with `swift test` or through Xcode.

```swift
import Testing

@Test func addsTwoNumbers() {
    #expect(2 + 3 == 5)
}
```

Libraries package as Swift Package Manager packages described by `Package.swift` and distributed through Git repositories. Apple applications bundle as `.app` packages and ship through the App Store.

## Performance and concurrency

Swift compiles to native machine code and uses automatic reference counting, which frees objects deterministically when their last reference goes away rather than at a collector's discretion. Reference cycles must be broken with `weak` or `unowned` references. The concurrency model is built into the language:

- `async`/`await` expresses asynchronous work without callbacks.
- Actors isolate mutable state so that only one task touches it at a time, preventing data races by construction.
- Structured concurrency with task groups ties child task lifetimes to their parent, and the compiler's strict concurrency checking flags unsafe sharing.

## Common pitfalls

- Force-unwrapping an optional with `!` crashes if the value is `nil`; unwrap safely instead.
- Strong reference cycles between objects (and in closures that capture `self`) leak memory; use `weak`/`unowned` and capture lists.
- Value semantics mean a `struct` is copied on assignment, which surprises developers expecting shared mutation.
- Implicitly unwrapped optionals (`String!`) defer the crash rather than removing it.
- Blocking inside an `async` context or a `@MainActor` method stalls the UI; keep long work off the main actor.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Memory safety in interop: calling C or using `Unsafe` pointer APIs bypasses Swift's checks and can cause out-of-bounds access, which maps to [CWE-787](https://cwe.mitre.org/data/definitions/787.html); keep unsafe code minimal and audited.
- SQL injection: use parameterized queries (for example with bound parameters in SQLite or a database library) rather than string interpolation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Insecure transport and data storage: use App Transport Security and the Keychain for secrets rather than plist or `UserDefaults`, addressing [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Command and code injection: pass arguments as an array to `Process` rather than building a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin Swift Package Manager dependencies by revision and review them; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [SwiftLint](https://github.com/realm/SwiftLint) enforces conventions and can flag risky constructs, and Xcode's static analyzer and sanitizers (address and thread) catch memory and concurrency errors. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Swift Programming Language](https://docs.swift.org/swift-book/), the primary language guide.
- [Swift.org documentation](https://www.swift.org/documentation/) and the Swift Evolution proposals.
- [Apple Developer documentation](https://developer.apple.com/documentation/) for platform frameworks.

## Related pages

- [Objective-C](/languages/objective-c.md)
- [Kotlin](/languages/kotlin.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
