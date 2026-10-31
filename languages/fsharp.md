# F#

F# is a statically typed, functional-first language on the .NET platform, created by Don Syme at Microsoft Research and first released in 2005. It descends from the ML family and combines type inference and immutability with access to the full .NET ecosystem. It is used for data analysis, financial and scientific modeling, back-end services, and domain modeling where correctness matters.

| Attribute | Value |
|---|---|
| Paradigm | Functional-first, also object-oriented and imperative |
| Typing | Static, strong, inferred (Hindley-Milner style) |
| First appeared | 2005 |
| Memory model | Automatic garbage collection on the managed heap |
| Reference implementation | [F# compiler](https://github.com/dotnet/fsharp) |
| Typical uses | Data analysis, financial modeling, back ends, domain modeling |
| Governance | [F# Software Foundation](https://fsharp.org/) and Microsoft |

Related: [C#](/languages/csharp.md), [Visual Basic .NET](/languages/visual-basic-net.md), [Scala](/languages/scala.md).

## Overview and history

Don Syme and colleagues at Microsoft Research developed F# from the ML and OCaml tradition, with the first supported release in 2005 and integration into Visual Studio in 2010. It runs on the same .NET runtime as C# and Visual Basic, so F# code calls .NET libraries and vice versa. The language and compiler are open source under the [.NET Foundation](https://dotnetfoundation.org/), and the [F# Software Foundation](https://fsharp.org/) coordinates community work.

The language specification is published by Microsoft Research, and language changes are proposed in the open through the [F# language suggestions](https://github.com/fsharp/fslang-suggestions) process.

## Paradigm and type system

F# is functional-first: values are immutable by default, functions are curried and first class, and the type system infers most types through a Hindley-Milner style algorithm, so annotations are rarely needed. Algebraic data types come in two forms: records for product types and discriminated unions for sum types. Pattern matching over these types is exhaustive-checked. The language also supports object-oriented classes and interfaces for .NET interoperability.

```fsharp
let total prices tax =
    List.sum prices * (1.0 + tax)

type Shape =
    | Circle of radius: float
    | Square of side: float
```

Units of measure annotate numeric types so the compiler checks that, for example, meters are not added to seconds.

## Toolchain and ecosystem

- SDK and runtime: the `dotnet` CLI builds and runs F# projects; `dotnet fsi` starts the F# Interactive read-eval-print loop.
- Packaging and dependencies: packages come from [NuGet](https://www.nuget.org/); [Paket](https://fsprojects.github.io/Paket/) is an alternative dependency manager popular in F# projects.
- Formatting and linting: [Fantomas](https://fsprojects.github.io/fantomas/) formats code, and [FSharpLint](https://fsprojects.github.io/FSharpLint/) reports style and suspicious patterns.

```bash
dotnet new console -lang F# -o app
cd app
dotnet run
```

## Syntax tour

```fsharp
// Values are immutable bindings; indentation defines scope
let name = "world"
printfn "hello, %s" name

// Collections and pipelines
let squares = [ for n in 0..4 -> n * n ]
let lookup = Map [ "a", 1; "b", 2 ]

// Pipe operator threads a value through functions
let sumOfEvens =
    [ 0..9 ]
    |> List.filter (fun n -> n % 2 = 0)
    |> List.sum

// Discriminated union and pattern match
type Animal = Cat | Dog
let sound = function
    | Cat -> "meow"
    | Dog -> "woof"

// Record type
type Point = { X: int; Y: int }
let p = { X = 1; Y = 2 }
```

## Idioms and different approaches

- Compose small functions with the pipe operator `|>` to express data flow left to right.
- Model a domain with records and discriminated unions so illegal states cannot be represented, then branch with exhaustive matches.
- Use `Option` for absence and `Result` for recoverable failure instead of null or exceptions.
- Prefer immutable data and pure functions; use `mutable` and `ref` cells only where genuinely needed.
- Use computation expressions (`async`, `seq`, `task`, and library-defined ones) to sequence effects cleanly.

## Design principles

F# values correctness, conciseness, and interoperability. Type inference and immutability reduce boilerplate and a class of runtime errors, and discriminated unions with exhaustive matching make domain modeling precise. The language keeps a clean functional core while providing full object-oriented support so it fits into the .NET ecosystem rather than standing apart from it.

## Standard library and notable libraries

The F# core library provides immutable `List`, `Array`, `Seq`, `Map`, and `Set` modules, the `Option` and `Result` types, and `async` and `task` computation expressions. The .NET base class library is available directly. Notable libraries include [Giraffe](https://github.com/giraffe-fsharp/Giraffe) and [Saturn](https://saturnframework.org/) for web services, [FSharp.Data](https://fsprojects.github.io/FSharp.Data/) for type providers over data sources, and [Fable](https://fable.io/) for compiling F# to JavaScript.

## Testing and packaging

F# uses the .NET test runners [xUnit](https://xunit.net/) and [NUnit](https://nunit.org/), often with [Expecto](https://github.com/haf/expecto) for an F#-idiomatic style and [FsCheck](https://fscheck.github.io/FsCheck/) for property testing.

```fsharp
module CalculatorTests

open Xunit

[<Fact>]
let ``adds two numbers`` () =
    Assert.Equal(5, 2 + 3)
```

Libraries package as NuGet packages with `dotnet pack`; applications publish with the `dotnet` CLI, including self-contained and single-file builds.

## Performance and concurrency

F# runs on the Common Language Runtime with the same just-in-time and ahead-of-time compilation and garbage collector as C#, so performance is comparable. Immutability can add allocation, which the compiler and structural sharing mitigate, and arrays with `mutable` support tight numeric loops. Concurrency uses:

- The `async` computation expression and the newer `task` expression for asynchronous I/O.
- The .NET Task Parallel Library for CPU-bound parallelism.
- The `MailboxProcessor` agent for message-passing concurrency with isolated state.

## Common pitfalls

- Mixing significant indentation inconsistently (tabs and spaces) breaks the offside rule; use spaces.
- Forgetting that function application is curried can produce a partially applied function instead of a result.
- Non-tail-recursive functions over large inputs overflow the stack; use accumulators or library folds.
- Eagerly evaluating a large `seq` with `List.ofSeq` can exhaust memory; keep it lazy when possible.
- Interop with C# null-returning APIs reintroduces null, which F# otherwise avoids; wrap boundaries in `Option`.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Insecure deserialization: avoid the obsolete `BinaryFormatter` from .NET; use `System.Text.Json` with known types for untrusted data. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized commands or a typed data access library rather than string interpolation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities: disable DTD processing and null the `XmlResolver` on .NET XML readers to avoid [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection: pass arguments through `ProcessStartInfo.ArgumentList` rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin and scan NuGet dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: Roslyn-based .NET security analyzers apply to F# projects in the build, and `dotnet list package --vulnerable` reports known-vulnerable dependencies. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [F# documentation](https://learn.microsoft.com/dotnet/fsharp/) and the [language reference](https://learn.microsoft.com/dotnet/fsharp/language-reference/), the primary sources.
- [F# for Fun and Profit](https://fsharpforfunandprofit.com/) for applied functional design.
- [F# Software Foundation](https://fsharp.org/) for community resources.

## Related pages

- [C#](/languages/csharp.md)
- [Visual Basic .NET](/languages/visual-basic-net.md)
- [Scala](/languages/scala.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
