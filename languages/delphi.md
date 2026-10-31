# Delphi (Object Pascal)

Delphi is a statically typed, compiled development environment and dialect of Object Pascal, first released by Borland in 1995 and now developed by Embarcadero Technologies. It pairs the Object Pascal language with a visual component framework and a native-code compiler, and it is used mainly to build Windows desktop and business applications, with cross-platform targets added over time. The open-source Free Pascal and its Lazarus IDE provide a largely compatible alternative.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, imperative, event-driven, component-based |
| Typing | Static, strong |
| First appeared | 1995 |
| Memory model | Manual for objects (`Create`/`Free`); reference counting for strings, dynamic arrays, and interfaces |
| Reference compiler | [Embarcadero Delphi](https://www.embarcadero.com/products/delphi); [Free Pascal](https://www.freepascal.org/) with [Lazarus](https://www.lazarus-ide.org/) is a compatible open-source option |
| Typical uses | Windows desktop and business applications, cross-platform apps via FireMonkey |
| Governance/standard | Proprietary, defined by Embarcadero; no ISO standard |

Related: [Pascal](/languages/pascal.md), [Eiffel](/languages/eiffel.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Delphi extended Borland's Turbo Pascal line with a class-based object model and a visual development model: programmers drag components onto forms and attach event handlers. The Visual Component Library (VCL) wraps the Windows API, and later the FireMonkey (FMX) framework added cross-platform user interfaces for macOS, iOS, Android, and Linux. Ownership passed from Borland to CodeGear, then Embarcadero, now part of Idera.

The language, Object Pascal, keeps Pascal's declaration style and strong typing while adding classes, interfaces, exceptions, generics, and anonymous methods. Free Pascal implements a compatible dialect in its `objfpc` and `delphi` modes, and the Lazarus IDE mirrors Delphi's form-based development, so much code ports between them.

## Paradigm and type system

Delphi is statically and strongly typed and class-based. Classes are reference types allocated on the heap; instances are created with a constructor and released with `Free`, usually in a `try`/`finally` block. Interfaces are reference-counted, so objects accessed through an interface are released automatically when the last reference goes away. Strings and dynamic arrays are also reference-counted with copy-on-write semantics.

```pascal
type
  IShape = interface
    function Area: Double;
  end;

  TCircle = class(TInterfacedObject, IShape)
  private
    FRadius: Double;
  public
    constructor Create(ARadius: Double);
    function Area: Double;
  end;
```

Generics (`TList<T>`) and run-time type information support containers and reflection-style programming.

## Toolchain and ecosystem

- Compiler and IDE: the Delphi IDE (RAD Studio) compiles to native code and hosts the form designer; the command-line compiler is `dcc32` or `dcc64`.
- Open-source toolchain: Free Pascal's `fpc` with Lazarus provides a compatible compiler and IDE.
- Packages: [GetIt](https://www.embarcadero.com/products/delphi/features) distributes components for Delphi; the Free Pascal and Lazarus ecosystem uses Online Package Manager (OPM).

```bash
# Free Pascal, Delphi-compatible mode
fpc -Mdelphi project.pas
```

## Syntax tour

```pascal
program Shapes;

{$MODE DELPHI}

uses SysUtils;

type
  TCircle = class
  private
    FRadius: Double;
  public
    constructor Create(ARadius: Double);
    function Area: Double;
  end;

constructor TCircle.Create(ARadius: Double);
begin
  FRadius := ARadius;
end;

function TCircle.Area: Double;
begin
  Result := Pi * FRadius * FRadius;
end;

var
  C: TCircle;
begin
  C := TCircle.Create(2.0);
  try
    WriteLn(Format('area: %.4f', [C.Area]));
  finally
    C.Free;
  end;
end.
```

## Idioms and different approaches

- Pair every object `Create` with a `try`/`finally` that calls `Free`, so resources release even on an exception.
- Use interfaces when you want reference-counted lifetime instead of manual `Free`.
- Separate interface and implementation across units, exposing types in the `interface` section.
- Prefer the generic collections in `System.Generics.Collections` over hand-written structures.
- Use the VCL for Windows-only applications and FireMonkey when you target multiple platforms.

## Design principles

Delphi was designed for productive construction of graphical applications that compile to fast native executables, combining a visual component model with a strongly typed language. The component framework favors composition of ready-made, event-driven pieces, and the single-file executable output suited desktop distribution. Backward compatibility is a priority, so long-lived Delphi codebases continue to build across IDE versions.

## Standard library and notable packages

The run-time library covers strings (`System.SysUtils`), collections (`System.Generics.Collections`), files and streams (`System.Classes`), and formatting. The VCL provides Windows controls and database access; FireMonkey provides cross-platform UI. Third-party components are long-standing in Delphi: database access layers, reporting tools, and UI control suites. Open-source libraries are distributed through GetIt for Delphi and OPM for Lazarus and Free Pascal.

## Testing and packaging

[DUnit](https://dunit.sourceforge.net/) and the newer DUnitX are xUnit-style frameworks for Delphi; Free Pascal's FPCUnit serves the open-source side. Applications are usually distributed as compiled native executables with any required runtime packages; reusable code ships as Delphi packages (`.bpl`) or as source units.

```pascal
procedure TestArea;
begin
  Assert(Abs(TCircle.Create(1.0).Area - Pi) < 1e-9);
end;
```

## Performance and concurrency

Delphi compiles to native machine code, so compute-bound code runs at speeds comparable to other native languages. Concurrency uses operating-system threads through the `TThread` class and the Parallel Programming Library (`System.Threading`) for tasks and parallel loops. Shared mutable state needs explicit synchronization (critical sections, monitors). Because non-interface objects use manual lifetime management, multithreaded code must coordinate ownership carefully to avoid freeing an object another thread still uses.

## Common pitfalls

- Memory leaks and dangling references: forgetting `Free`, or mixing manual `Free` with interface reference counting on the same object, causes leaks or premature release.
- Treating reference-counted and manually managed objects the same way, which breaks lifetime assumptions.
- Dialect and version drift: VCL-only code does not run on non-Windows targets, and IDE versions differ in library APIs.
- Relying on implicit string conversions between `AnsiString`, `UnicodeString`, and `UTF8String`, which can corrupt text.
- Blocking the UI thread with long work instead of moving it to a background thread.

## Secure coding

Delphi compiles native code and, like other systems-oriented languages, leaves memory and input handling to the programmer:

- Buffer and bounds handling: writing past a static array or a `PChar` buffer corrupts memory; keep range checking on and bound external data. This relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free: freeing an object still referenced elsewhere, or double-freeing, is a lifetime defect that maps to [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: enable overflow checking for arithmetic on untrusted values, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Injection in data access: build SQL with parameters rather than concatenating user input, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html); validate all external input, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

Tooling is limited relative to mainstream languages. The compiler's range and overflow checks, hints, and warnings are the first line; commercial static analyzers for Delphi exist but are not widely adopted. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- Embarcadero Delphi documentation, the official language and library reference.
- [Free Pascal and Lazarus wiki](https://wiki.freepascal.org/), for the compatible open-source toolchain.
- Object Pascal language guide, the language reference for the Delphi dialect.

## Related pages

- [Pascal](/languages/pascal.md)
- [Eiffel](/languages/eiffel.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
