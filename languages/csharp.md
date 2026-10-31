# C#

C# is a statically typed, object-oriented language created by Microsoft and first released in 2000 as part of the .NET platform. Designed by Anders Hejlsberg, it compiles to an intermediate language that runs on the Common Language Runtime. It is used for Windows and cross-platform desktop applications, web back ends with ASP.NET Core, game development with Unity, and cloud services.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, with generics, functional, and asynchronous features |
| Typing | Static, strong, nominal, with local type inference |
| First appeared | 2000 |
| Memory model | Automatic garbage collection on the managed heap |
| Reference implementation | [.NET runtime and Roslyn compiler](https://github.com/dotnet/runtime) |
| Typical uses | Web back ends, desktop apps, game development, cloud services |
| Governance | [ECMA-334](https://ecma-international.org/publications-and-standards/standards/ecma-334/) and Microsoft through .NET |

Related: [F#](/languages/fsharp.md), [Visual Basic .NET](/languages/visual-basic-net.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Microsoft introduced C# in 2000 alongside the .NET Framework, with Anders Hejlsberg as lead architect. The language is standardized as [ECMA-334](https://ecma-international.org/publications-and-standards/standards/ecma-334/) and ISO/IEC 23270. The platform shifted from the Windows-only .NET Framework to the open-source, cross-platform .NET Core, which merged into a unified [.NET](https://dotnet.microsoft.com/) line (.NET 5 and later) that releases yearly, with even-numbered releases designated long-term support.

The compiler, named Roslyn, and the runtime are open source under the [.NET Foundation](https://dotnetfoundation.org/). Language features are designed in the open in the [C# language design repository](https://github.com/dotnet/csharplang).

## Paradigm and type system

C# is statically and nominally typed with generics, type inference for locals (`var`), and nullable reference type annotations that the compiler checks to reduce null dereferences. Value types (`struct`, `enum`) live on the stack or inline, and reference types (`class`, `record`) live on the managed heap. The language has grown functional features: lambdas, pattern matching, records, and immutable `init`-only properties.

```csharp
record Point(int X, int Y);

decimal Total(IEnumerable<decimal> prices, decimal tax = 0m) =>
    prices.Sum() * (1 + tax);
```

Nullable reference types, enabled per project or file, make `string?` distinct from `string` and warn on unchecked dereferences.

## Toolchain and ecosystem

- SDK and runtime: the `dotnet` CLI creates, builds, tests, and runs projects; the Common Language Runtime executes the intermediate language.
- Packaging and dependencies: packages publish to [NuGet](https://www.nuget.org/) and are referenced in the project file or with `dotnet add package`.
- Formatting and linting: `dotnet format` applies style, and Roslyn analyzers (including the built-in .NET analyzers) report defects and style issues during the build.

```bash
dotnet new console -o app
cd app
dotnet run
```

## Syntax tour

```csharp
using System;
using System.Collections.Generic;
using System.Linq;

// Top-level statements (no explicit Main needed)
var name = "world";
Console.WriteLine($"hello, {name}");

// Collections and LINQ
List<int> squares = Enumerable.Range(0, 5).Select(n => n * n).ToList();
var lookup = new Dictionary<string, int> { ["a"] = 1, ["b"] = 2 };

// Pattern matching
string Label(int n) => n switch
{
    0 => "empty",
    < 10 => "short",
    _ => "long"
};

// Exceptions
try
{
    int value = int.Parse("not a number");
}
catch (FormatException)
{
    Console.WriteLine("parse failed");
}

// Record and interface
record Circle(double Radius);

interface IGreeter
{
    string Greet(string who);
}
```

## Idioms and different approaches

- Use LINQ for declarative queries over collections; fall back to loops when logic has side effects or needs early exit.
- Enable nullable reference types and treat warnings as errors to catch null problems at compile time.
- Prefer `async`/`await` for I/O rather than blocking calls or manual thread management.
- Use records for immutable value types and `with` expressions for non-destructive updates.
- Dispose resources with `using` declarations so they release deterministically.

## Design principles

C# aims for a type-safe, component-oriented language that stays approachable for C and Java developers while adopting functional ideas over time. Each release adds features that reduce boilerplate (properties, LINQ, async/await, records, pattern matching) without breaking existing code. The managed runtime provides memory safety, and the language increasingly moves errors from run time to compile time.

## Standard library and notable frameworks

The base class library covers collections, I/O, networking (`System.Net.Http`), text, and the `System.Threading.Tasks` asynchronous model. Notable frameworks include [ASP.NET Core](https://learn.microsoft.com/aspnet/core/) for web applications and APIs, [Entity Framework Core](https://learn.microsoft.com/ef/core/) for object-relational mapping, [Blazor](https://learn.microsoft.com/aspnet/core/blazor/) for web user interfaces in C#, and [Unity](https://unity.com/) for games. [Serilog](https://serilog.net/) and [xUnit](https://xunit.net/) are common supporting libraries.

## Testing and packaging

[xUnit](https://xunit.net/), [NUnit](https://nunit.org/), and the built-in MSTest are common test frameworks, run with `dotnet test`.

```csharp
using Xunit;

public class CalculatorTests
{
    [Fact]
    public void AddsTwoNumbers()
    {
        Assert.Equal(5, 2 + 3);
    }
}
```

Libraries package as NuGet packages (`dotnet pack`) published to [NuGet](https://www.nuget.org/). Applications publish as framework-dependent or self-contained builds, and `PublishSingleFile` and ahead-of-time compilation produce standalone executables.

## Performance and concurrency

The Common Language Runtime compiles intermediate language to native code with a just-in-time compiler and offers ahead-of-time compilation for faster startup. The garbage collector is generational with server and workstation modes. Concurrency is built around the task-based asynchronous pattern:

- `async`/`await` over `Task` and `ValueTask` scales I/O-bound work without blocking threads.
- The Task Parallel Library and `Parallel.For` distribute CPU-bound work across cores.
- `System.Threading.Channels` and concurrent collections support producer-consumer patterns; shared mutable state still needs locks or immutable data.

## Common pitfalls

- `async void` methods cannot be awaited and swallow exceptions; use `async Task` except for event handlers.
- Blocking on a task with `.Result` or `.Wait()` can deadlock in contexts with a synchronization context.
- Reference and value equality differ: `class` compares references by default, `record` and `struct` compare values.
- Disposable objects not released with `using` leak unmanaged resources until finalization.
- Capturing a loop variable in a closure captured the variable, not its value, in older C# versions; current versions changed `foreach` semantics, but the pattern still confuses readers.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Insecure deserialization: `BinaryFormatter` reconstructs arbitrary object graphs and is obsolete and unsafe; it is removed from current .NET. Use `System.Text.Json` with known types for untrusted data. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized commands or Entity Framework Core, never string concatenation into SQL, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- XML external entities: set `XmlResolver` to null and disable DTD processing on `XmlReaderSettings` to avoid [CWE-611](https://cwe.mitre.org/data/definitions/611.html).
- Command injection: pass arguments through `ProcessStartInfo.ArgumentList` rather than a single shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Cross-site scripting in web output: rely on Razor's automatic HTML encoding and avoid `Html.Raw` on untrusted data, addressing [CWE-79](https://cwe.mitre.org/data/definitions/79.html).

Tooling: the built-in Roslyn security analyzers and [Security Code Scan](https://security-code-scan.github.io/) flag insecure patterns, and `dotnet list package --vulnerable` checks dependencies. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

## Learning resources

- [C# documentation](https://learn.microsoft.com/dotnet/csharp/) and the [language reference](https://learn.microsoft.com/dotnet/csharp/language-reference/), the primary sources.
- [.NET documentation](https://learn.microsoft.com/dotnet/) for the platform and runtime.
- [C# language design repository](https://github.com/dotnet/csharplang) for the decision record.

## Related pages

- [F#](/languages/fsharp.md)
- [Visual Basic .NET](/languages/visual-basic-net.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
