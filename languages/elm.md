# Elm

Elm is a statically typed, purely functional language for building web front ends, created by Evan Czaplicki and first released in 2012. It compiles to JavaScript, enforces immutability and managed effects, and is known for a type system and compiler designed to eliminate run-time exceptions in practice. It is used to build browser user interfaces with a single architecture pattern (the Elm Architecture) that later inspired state-management libraries in the wider JavaScript ecosystem.

| Attribute | Value |
|---|---|
| Paradigm | Purely functional, with managed effects |
| Typing | Static, strong, inferred (Hindley-Milner style) |
| First appeared | 2012 |
| Memory model | Automatic: inherits the host JavaScript engine's garbage collection |
| Reference implementation | [Elm compiler](https://github.com/elm/compiler) (written in Haskell) |
| Typical uses | Browser user interfaces and single-page web applications |
| Governance | Evan Czaplicki as lead; curated core packages |

Related: [JavaScript](/languages/javascript.md), [PureScript](/languages/purescript.md), [languages index](/languages/README.md).

## Overview and history

Elm began as Evan Czaplicki's thesis work in 2012, exploring functional reactive programming for user interfaces. Over time it dropped the reactive-streams model in favor of the Elm Architecture: a single loop of model, update, and view that handles all state and effects. The language is deliberately small and curated, with a compiler that produces specific, readable error messages and a design that aims for "no run-time exceptions" in typical application code by making impossible states unrepresentable through types.

Elm releases are infrequent and backward-incompatible changes are rare; version 0.19 has been the stable line for several years. The compiler is written in Haskell and emits JavaScript, so Elm applications run in any modern browser.

## Paradigm and type system

Elm is purely functional: functions have no side effects, data is immutable, and all input and output is managed by the runtime rather than performed inline. The type system uses Hindley-Milner inference, so most code needs no explicit annotations yet is fully checked. Features include algebraic data types (custom types), records, type aliases, and parametric polymorphism. There is no `null` and no exceptions in user code; absence is modeled with the `Maybe` type and failure with the `Result` type.

```elm
total : List Float -> Float -> Float
total prices tax =
    List.sum prices * (1 + tax)
```

## Toolchain and ecosystem

- Compiler: the `elm` binary compiles projects, runs a reactor development server, and manages packages.
- Packaging: packages publish to the [Elm package registry](https://package.elm-lang.org/); `elm install` adds them and `elm.json` records dependencies. The registry enforces semantic versioning automatically by diffing public APIs.
- Interop: Elm talks to JavaScript through ports (message passing) and flags (initial data); it does not call JavaScript functions directly.
- Formatting: [elm-format](https://github.com/avh4/elm-format) applies one canonical layout, so style is not debated.

```bash
elm init
elm install elm/http
elm make src/Main.elm --output=main.js
```

## Syntax tour

```elm
module Main exposing (main)

-- Custom types (algebraic data types)
type Shape
    = Circle Float
    | Square Float

area : Shape -> Float
area shape =
    case shape of
        Circle radius ->
            pi * radius ^ 2

        Square side ->
            side ^ 2

-- Records and update syntax (produces a new record)
type alias Point =
    { x : Int, y : Int }

moveRight : Point -> Point
moveRight point =
    { point | x = point.x + 1 }

-- Maybe models absence instead of null
first : List a -> Maybe a
first list =
    List.head list

-- Pipes read left to right
sumOfSquares : List Int -> Int
sumOfSquares nums =
    nums
        |> List.map (\n -> n * n)
        |> List.sum
```

## Idioms and different approaches

- Structure applications with the Elm Architecture: a `Model`, a `Msg` type, an `update` function, and a `view` function, with the runtime wiring them together.
- Make impossible states unrepresentable: design custom types so that invalid combinations cannot be constructed, which removes whole classes of bugs.
- Handle absence with `Maybe` and failure with `Result`; the compiler forces every case to be addressed in a `case` expression.
- Use the pipe operator `|>` to chain transformations in reading order.
- Isolate all JavaScript interaction behind ports so the typed core stays pure.

## Design principles

Elm optimizes for reliability and a gentle developer experience over feature breadth. The language is intentionally small, the core packages are curated rather than open to anyone, and the compiler invests heavily in clear error messages that suggest fixes. Purity and managed effects mean the runtime, not the programmer, decides when side effects happen, which is what lets the compiler guarantee the absence of many run-time failures. The trade-offs are a slower pace of change and limited escape hatches: you cannot call arbitrary JavaScript inline, by design.

## Standard library and notable packages

The curated core packages cover lists, dictionaries, sets, strings, JSON encoding and decoding (`elm/json`), HTTP (`elm/http`), and the browser runtime (`elm/browser`). Widely used community packages include [elm-ui](https://package.elm-lang.org/packages/mdgriffith/elm-ui/latest/) for layout without raw CSS, [elm/url](https://package.elm-lang.org/packages/elm/url/latest/) for routing, and various form and graphics libraries, all distributed through the enforced-semver registry.

## Testing and packaging

[elm-test](https://github.com/elm-explorations/test) is the standard testing library and runner.

```elm
import Expect
import Test exposing (Test, test)

addition : Test
addition =
    test "addition works" <|
        \_ -> Expect.equal 5 (2 + 3)
```

A publishable package declares its exposed modules in `elm.json`; `elm publish` checks that the version number matches the actual API change before accepting it, which keeps the registry's semantic versioning honest.

## Performance and concurrency

Elm compiles to JavaScript, so it runs on the same just-in-time engines with the same single-threaded event loop as [JavaScript](/languages/javascript.md). Immutability is implemented with structural sharing, so updating part of a large data structure does not copy all of it. The compiler and runtime apply virtual-DOM diffing so that view updates touch only the changed parts of the page. There is no language-level threading; concurrency is the browser's asynchronous model, and long computations should be chunked or delegated so they do not block rendering.

## Common pitfalls

- Interop is restricted to ports and flags; developers expecting to call JavaScript functions directly must restructure around message passing.
- The curated ecosystem is smaller than JavaScript's, so a given library may not exist and must be wrapped through a port or reimplemented.
- JSON from the network must be decoded with an explicit decoder; a mismatch surfaces as a handled `Result` error rather than a crash, which is safer but needs upfront work.
- The pace of releases is slow; teams should not expect frequent language changes.
- Modeling with custom types takes design effort initially, though it pays off in fewer invalid states later.

## Secure coding

Elm's purity and type system remove several common front-end bug classes, but it still produces web pages, so web risks remain:

- Cross-site scripting: Elm's `Html` module escapes text by default, which prevents most injection. The escape hatch is `Html.Attributes.property "innerHTML"` or injecting markup through a port; treat any raw-HTML path as a potential [CWE-79](https://cwe.mitre.org/data/definitions/79.html) sink and avoid it for untrusted data. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Port boundaries: data crossing a port to JavaScript leaves the typed, escaped world; a port that passes a string into a dangerous JavaScript sink reintroduces the risks of plain JavaScript, so validate on both sides.
- Absence of `null` and exceptions removes a class of run-time failures ([CWE-476](https://cwe.mitre.org/data/definitions/476.html) null dereference does not arise in pure Elm code), but logic errors and incorrect decoders are still possible.
- Client-side trust: as with any front end, never treat client-side validation as a security control; enforce authorization and validation on the server.
- Dependency supply chain: packages come from the Elm registry with enforced semver; still review them and pin versions. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the compiler itself is the first line of defense; for the JavaScript that ports touch, scan with [ESLint](https://eslint.org/) or [semgrep](https://semgrep.dev/). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [An Introduction to Elm](https://guide.elm-lang.org/), the official guide, including the Elm Architecture.
- [Elm package documentation](https://package.elm-lang.org/), the core and community package reference.
- [Elm syntax reference](https://elm-lang.org/docs/syntax), a concise overview.

## Related pages

- [JavaScript](/languages/javascript.md)
- [PureScript](/languages/purescript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
