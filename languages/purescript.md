# PureScript

PureScript is a statically typed, purely functional language with a type system close to Haskell's, created by Phil Freeman and first released in 2013. It compiles to JavaScript (and can target other back ends) and is used mainly for web front ends and full-stack applications where developers want Haskell-style types and purity with direct access to the JavaScript ecosystem. Unlike Elm, it keeps a full type-class system, type-level programming, and unrestricted foreign interop.

| Attribute | Value |
|---|---|
| Paradigm | Purely functional, with type classes and higher-kinded types |
| Typing | Static, strong, inferred, with row polymorphism and type classes |
| First appeared | 2013 |
| Memory model | Automatic: inherits the host JavaScript engine's garbage collection |
| Reference implementation | [PureScript compiler (purs)](https://github.com/purescript/purescript) (written in Haskell) |
| Typical uses | Web front ends and full-stack applications targeting JavaScript |
| Governance | PureScript core team on [GitHub](https://github.com/purescript) |

Related: [Elm](/languages/elm.md), [JavaScript](/languages/javascript.md), [languages index](/languages/README.md).

## Overview and history

Phil Freeman created PureScript to bring a Haskell-like language to the JavaScript platform without a run-time of its own, compiling to readable JavaScript. It keeps features that Haskell programmers expect: type classes, higher-kinded types, and type-level programming, while using strict (eager) evaluation rather than Haskell's laziness, which maps more predictably onto JavaScript. Where Elm restricts interop and curates packages for safety, PureScript gives full access to JavaScript through a foreign function interface and a more open package ecosystem.

The compiler, `purs`, is written in Haskell. The modern build tool is [Spago](https://github.com/purescript/spago), and packages are distributed through a package set and the [PureScript registry](https://github.com/purescript/registry).

## Paradigm and type system

PureScript is purely functional with strict evaluation. Its type system is among the more expressive of languages that compile to JavaScript: Hindley-Milner inference extended with type classes (for ad hoc polymorphism), higher-kinded types, row polymorphism (types that are generic over the set of fields in a record), and functional dependencies. Effects are tracked in types through the `Effect` monad for synchronous effects and `Aff` for asynchronous ones, so the signature of a function tells you whether it touches the outside world.

```purescript
total :: Array Number -> Number -> Number
total prices tax = sum prices * (1.0 + tax)
```

Row polymorphism lets a function accept any record that has at least the fields it needs, which is a close fit for JavaScript objects.

## Toolchain and ecosystem

- Compiler: `purs` compiles modules to JavaScript; it is usually driven through a build tool.
- Build tool and packaging: [Spago](https://github.com/purescript/spago) builds projects and resolves dependencies from a package set and the [registry](https://github.com/purescript/registry).
- Interop: the foreign function interface lets a module declare a `foreign import` and provide the implementation in a paired JavaScript file.
- Editor support: the `purs ide` server and purty or the formatter `purs-tidy` provide tooling and consistent layout.

```bash
spago init
spago install prelude
spago build
```

## Syntax tour

```purescript
module Main where

import Prelude
import Data.Maybe (Maybe(..))
import Data.Array (head, filter)

-- Algebraic data types
data Shape
  = Circle Number
  | Square Number

area :: Shape -> Number
area = case _ of
  Circle radius -> pi * radius * radius
  Square side   -> side * side

-- Records with row polymorphism: accepts any record with an x field
getX :: forall r. { x :: Int | r } -> Int
getX rec = rec.x

-- Maybe models absence
firstPositive :: Array Int -> Maybe Int
firstPositive = filter (_ > 0) >>> head

-- Type classes: show works for any type with an instance
describe :: forall a. Show a => a -> String
describe value = "value is " <> show value
```

## Idioms and different approaches

- Track effects in types: use `Effect` for synchronous side effects and `Aff` for asynchronous work, so effectful code is visible in signatures.
- Use type classes for shared behavior (`Show`, `Eq`, `Ord`, `Functor`, `Monad`) rather than ad hoc overloading.
- Use row polymorphism to write functions over records that require only certain fields, which fits JavaScript object shapes.
- Prefer function composition (`>>>` and `<<<`) and the `Prelude` combinators for data pipelines.
- Wrap JavaScript libraries behind typed foreign imports so the typed core stays honest about effects and shapes.

## Design principles

PureScript's design brings a Haskell-class type system to the JavaScript platform while compiling to code that interoperates cleanly and reads clearly. It chooses strict evaluation over laziness to match JavaScript's execution and to make performance and resource use easier to reason about. It favors expressiveness and composability (type classes, higher-kinded and type-level features) over Elm's smaller, more guarded surface, and it trusts the programmer with an open foreign function interface rather than restricting interop. The cost is a steeper learning curve and the responsibility that comes with unrestricted interop.

## Standard library and notable packages

The `prelude` package and the core libraries provide the type classes (`Functor`, `Applicative`, `Monad`), data structures (`Data.Array`, `Data.Map`, `Data.List`), `Maybe` and `Either`, and the `Effect` and `Aff` effect types. Widely used packages include [Halogen](https://github.com/purescript-halogen/purescript-halogen) for building component-based user interfaces, [purescript-react-basic](https://github.com/lumihq/purescript-react-basic) for React bindings, and `argonaut` for JSON. Packages come from a curated package set resolved by Spago.

## Testing and packaging

Common testing libraries include [purescript-spec](https://github.com/purescript-spec/purescript-spec) and `purescript-test-unit`.

```purescript
import Test.Spec (describe, it)
import Test.Spec.Assertions (shouldEqual)

spec = describe "addition" do
  it "works" do
    (2 + 3) `shouldEqual` 5
```

A publishable package declares its dependencies for Spago and submits to the PureScript registry; the compiler emits one JavaScript module per PureScript module, which bundlers then tree-shake and package for the browser.

## Performance and concurrency

PureScript compiles to JavaScript and runs on the same just-in-time engines and single-threaded event loop as [JavaScript](/languages/javascript.md), with strict evaluation that avoids the space-leak surprises of lazy languages. The compiler produces one JavaScript module per source module; bundlers remove unused code (tree shaking) to keep output small. Asynchronous concurrency is expressed through the `Aff` monad, which composes asynchronous effects with cancellation and error handling and ultimately drives the browser's event loop. CPU-bound parallelism uses the host's Web Workers, called through foreign imports, rather than a language-level thread model.

## Common pitfalls

- The learning curve is steep for developers new to Haskell-style types, type classes, and monadic effects.
- The open foreign function interface means a mistaken `foreign import` type signature can lie about what the JavaScript does, reintroducing run-time errors the types claimed to prevent; write FFI bindings carefully.
- Strict evaluation differs from Haskell, so Haskell code and idioms do not always transfer directly.
- The ecosystem is smaller than JavaScript's, and package-set curation means a library must be in (or added to) the set to be used easily.
- Compile times and the conceptual overhead of effect types are real costs to weigh against the type-safety benefits.

## Secure coding

PureScript's types and purity remove several bug classes, but it compiles to JavaScript and offers open interop, so web and interop risks remain:

- Foreign function interface trust: a `foreign import` with an inaccurate type lets unchecked JavaScript masquerade as typed, pure code; a string passed through the FFI into a DOM sink such as `innerHTML` is a [CWE-79](https://cwe.mitre.org/data/definitions/79.html) cross-site scripting risk. Validate and escape at the FFI boundary. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Cross-site scripting in UI libraries: use the escaping provided by Halogen or the React bindings, and avoid raw-HTML insertion of untrusted data.
- Absence of `null` in pure code removes null-dereference failures ([CWE-476](https://cwe.mitre.org/data/definitions/476.html)) within PureScript, but values that arrive through the FFI can still be `null` or `undefined`; model them as `Maybe` and check.
- Client-side trust: never rely on client-side checks for authorization; enforce on the server.
- Dependency supply chain: review package-set and registry dependencies and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the compiler's type checker catches many errors before run time; scan the JavaScript produced and the FFI files with [ESLint](https://eslint.org/) or [semgrep](https://semgrep.dev/). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [PureScript by Example](https://book.purescript.org/), the official book.
- [PureScript documentation](https://github.com/purescript/documentation), guides and language references.
- [Pursuit](https://pursuit.purescript.org/), the searchable package and API index.

## Related pages

- [Elm](/languages/elm.md)
- [JavaScript](/languages/javascript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
