# Visual Basic .NET

Visual Basic .NET is a statically typed, object-oriented language on the .NET platform, released by Microsoft in 2002 as the successor to classic Visual Basic. It shares the Common Language Runtime and base class library with C# and F#, differing mainly in syntax, which favors English keywords over braces. It is used for business applications, line-of-business desktop tools, and maintenance of existing .NET code.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, with event-driven and some functional features |
| Typing | Static, strong; optional late binding via `Option Strict Off` |
| First appeared | 2002 |
| Memory model | Automatic garbage collection on the managed heap |
| Reference implementation | [.NET runtime and Roslyn compiler](https://github.com/dotnet/roslyn) |
| Typical uses | Business applications, desktop tools, legacy .NET maintenance |
| Governance | Microsoft through the .NET platform |

Related: [C#](/languages/csharp.md), [F#](/languages/fsharp.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Visual Basic .NET replaced the classic Visual Basic 6 line in 2002, moving the language onto the .NET runtime with full object orientation and shared libraries. It compiles, like C#, to the same intermediate language and runs on the Common Language Runtime. Microsoft has stated that the language is stabilized: it is supported on current [.NET](https://dotnet.microsoft.com/) and the Roslyn compiler, but new language features are generally not being added, and the focus is compatibility rather than growth. Microsoft's position is documented in its [.NET language strategy](https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/).

The compiler is part of the open-source [Roslyn](https://github.com/dotnet/roslyn) project under the .NET Foundation. Classic Visual Basic 6 is a separate, older product and is not the same language.

## Paradigm and type system

Visual Basic .NET is statically and nominally typed with generics and the same type system as the rest of .NET. With `Option Strict On` (recommended), implicit narrowing conversions are disallowed and type checks are strict; with `Option Strict Off`, the language permits late binding and implicit conversions, which trades safety for flexibility. Value types and reference types behave as in C#, and the language supports lambdas, LINQ, and nullable value types.

```vbnet
Function Total(prices As IEnumerable(Of Decimal),
               Optional tax As Decimal = 0D) As Decimal
    Return prices.Sum() * (1 + tax)
End Function
```

The syntax uses keyword-delimited blocks (`If ... End If`, `Sub ... End Sub`) rather than braces, and statements are line-terminated.

## Toolchain and ecosystem

- SDK and runtime: the `dotnet` CLI creates, builds, and runs Visual Basic projects (`dotnet new console -lang VB`); the runtime is shared with C#.
- Packaging and dependencies: packages come from [NuGet](https://www.nuget.org/) and are referenced in the project file.
- Tooling: Visual Studio provides the primary editor experience; Roslyn analyzers and `dotnet format` apply to Visual Basic projects.

```bash
dotnet new console -lang VB -o app
cd app
dotnet run
```

## Syntax tour

```vbnet
Option Strict On

Imports System
Imports System.Linq
Imports System.Collections.Generic

Module Tour
    Sub Main()
        ' Variables and string interpolation
        Dim name As String = "world"
        Console.WriteLine($"hello, {name}")

        ' Collections and LINQ
        Dim squares As List(Of Integer) =
            Enumerable.Range(0, 5).Select(Function(n) n * n).ToList()

        Dim lookup As New Dictionary(Of String, Integer) From {
            {"a", 1}, {"b", 2}
        }

        ' Control flow
        For Each sq In squares
            Console.WriteLine(sq)
        Next

        ' Exceptions
        Try
            Dim value As Integer = Integer.Parse("not a number")
        Catch ex As FormatException
            Console.WriteLine("parse failed")
        End Try
    End Sub
End Module

' Class with an auto-implemented property
Public Class Point
    Public Property X As Integer
    Public Property Y As Integer
End Class
```

## Idioms and different approaches

- Set `Option Strict On` and `Option Explicit On` at the top of files or in the project to keep type checking strict.
- Use LINQ query and method syntax for collection transformations, as in C#.
- Prefer auto-implemented properties over manual backing fields.
- Use `Using` blocks to release disposable resources deterministically.
- When interoperating with C# libraries, keep in mind that identifiers are case-insensitive in Visual Basic but case-sensitive across the boundary.

## Design principles

Visual Basic .NET aims to be readable and approachable, using English-like keywords and a forgiving default for rapid application development, while providing the full capability of the .NET type system when strict options are on. Since the platform unification, Microsoft keeps the language stable and compatible rather than adding new syntax, so teams can maintain existing code without churn.

## Standard library and notable frameworks

Visual Basic .NET uses the same .NET base class library as C#: collections, I/O, `System.Net.Http`, and the task-based asynchronous model. It also ships the `Microsoft.VisualBasic` namespace with helpers familiar from classic Visual Basic. For user interfaces it uses [Windows Forms](https://learn.microsoft.com/dotnet/desktop/winforms/) and [WPF](https://learn.microsoft.com/dotnet/desktop/wpf/); for data access it uses [Entity Framework Core](https://learn.microsoft.com/ef/core/) and ADO.NET; ASP.NET Core is usable, though C# is the more common choice for new web work.

## Testing and packaging

Visual Basic projects use the .NET test runners [xUnit](https://xunit.net/), [NUnit](https://nunit.org/), and MSTest, run with `dotnet test`.

```vbnet
Imports Xunit

Public Class CalculatorTests
    <Fact>
    Public Sub AddsTwoNumbers()
        Assert.Equal(5, 2 + 3)
    End Sub
End Class
```

Libraries package as NuGet packages with `dotnet pack`. Applications publish with the `dotnet` CLI, including self-contained builds, the same as other .NET languages.

## Performance and concurrency

Because Visual Basic .NET compiles to the same intermediate language as C# and runs on the Common Language Runtime, its performance characteristics are the same: just-in-time compilation, optional ahead-of-time compilation, and a generational garbage collector. Concurrency uses the task-based asynchronous pattern:

- `Async` and `Await` for I/O-bound work.
- The Task Parallel Library and `Parallel.For` for CPU-bound parallelism.
- Shared mutable state needs `SyncLock` or concurrent collections to avoid races.

## Common pitfalls

- Leaving `Option Strict Off` allows silent narrowing conversions and late binding that fail at run time; turn it on.
- Case-insensitive identifiers can mask two names that differ only in case when interoperating with case-sensitive languages.
- The `On Error` statement from classic Visual Basic still compiles but is inferior to structured `Try`/`Catch`; use the latter.
- Blocking on an async result with `.Result` can deadlock in a synchronization context.
- Default property and optional-argument behavior can hide which overload is called; be explicit.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Insecure deserialization: avoid the obsolete `BinaryFormatter`; use `System.Text.Json` with known types for untrusted data. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized ADO.NET commands or Entity Framework Core, never string concatenation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities: disable DTD processing and null the `XmlResolver` on .NET XML readers to avoid [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection: pass arguments through `ProcessStartInfo.ArgumentList` rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin and scan NuGet dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the built-in .NET Roslyn security analyzers apply to Visual Basic projects, and `dotnet list package --vulnerable` reports vulnerable dependencies. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Visual Basic documentation](https://learn.microsoft.com/dotnet/visual-basic/) and the [language reference](https://learn.microsoft.com/dotnet/visual-basic/language-reference/), the primary sources.
- [.NET documentation](https://learn.microsoft.com/dotnet/) for the shared platform.
- [Visual Basic language specification](https://learn.microsoft.com/dotnet/visual-basic/reference/language-specification/) for formal semantics.

## Related pages

- [C#](/languages/csharp.md)
- [F#](/languages/fsharp.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
