# Pascal

Pascal is a statically typed, compiled, procedural language designed by Niklaus Wirth around 1970 to teach structured programming and to support reliable systems work. It emphasizes readable keyword-based syntax, strong typing with user-defined types, and a clear separation of declarations from statements. It was widely used for teaching and for application and systems development through the 1980s and 1990s, and it survives today through implementations such as Free Pascal.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, structured |
| Typing | Static, strong, with user-defined types |
| First appeared | 1970 |
| Memory model | Manual: stack for locals, heap via `new` and `dispose` |
| Reference compiler | No single reference; [Free Pascal](https://www.freepascal.org/) is a common open-source compiler, Turbo Pascal was historically dominant |
| Typical uses | Teaching, application development, systems programming (historically) |
| Governance/standard | [ISO/IEC 7185](https://www.iso.org/standard/13802.html) (Pascal) and ISO/IEC 10206 (Extended Pascal) |

Related: [ALGOL](/languages/algol.md), [Delphi (Object Pascal)](/languages/delphi.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Niklaus Wirth designed Pascal at ETH Zurich as a successor to his earlier work and as a reaction to the size of languages such as ALGOL 68. The language was meant to be small enough to teach and to compile in a single pass, which shaped rules such as declaring every identifier before use. Turbo Pascal, released by Borland in 1983, made Pascal popular on personal computers with a fast compiler and integrated editor, and it added units and other extensions.

Standardization produced ISO/IEC 7185 (ISO Pascal) and ISO/IEC 10206 (Extended Pascal). In practice, most Pascal code uses extended dialects. Free Pascal is a widely available open-source compiler that targets many platforms and supports several dialect modes, including a Turbo Pascal compatibility mode and the Object Pascal dialect used by Delphi.

## Paradigm and type system

Pascal is statically and strongly typed. Programmers define types (enumerations, subranges, records, arrays, sets, and pointers), and the compiler rejects assignments between incompatible types. Subrange types bound a value, so an index can be declared to hold only a defined range. Pointers are typed and allocated with `new`, released with `dispose`; there is no garbage collector in standard Pascal.

```pascal
type
  Suit = (Clubs, Diamonds, Hearts, Spades);
  Hand = set of Suit;
  Day  = 1..31;
```

Procedures and functions can nest, and parameters pass by value or, with `var`, by reference.

## Toolchain and ecosystem

- Compiler: [Free Pascal](https://www.freepascal.org/) (`fpc`) compiles to native code on many platforms; GNU Pascal and historical Turbo Pascal are others.
- IDE: [Lazarus](https://www.lazarus-ide.org/) provides a cross-platform IDE and visual form designer over Free Pascal.
- Build: the compiler handles dependencies through units; `fpmake` and the Lazarus package system manage larger projects.

```bash
fpc hello.pas
./hello
```

## Syntax tour

```pascal
program Primes;

function IsPrime(n: Integer): Boolean;
var
  i: Integer;
begin
  if n < 2 then Exit(False);
  for i := 2 to Trunc(Sqrt(n)) do
    if n mod i = 0 then Exit(False);
  IsPrime := True;
end;

var
  k: Integer;
begin
  for k := 2 to 20 do
    if IsPrime(k) then
      Write(k, ' ');
  WriteLn;
end.
```

## Idioms and different approaches

- Declare precise types and subranges so the compiler and run time reject out-of-range values rather than deferring checks to code.
- Group related declarations and routines into units with an `interface` and `implementation` section.
- Use `set of` types for membership tests instead of chains of boolean conditions.
- Pass large records by `const` or `var` to avoid copying, and by value only when a copy is intended.
- Keep procedures small and nested where a helper is used only locally.

## Design principles

Pascal was designed to teach structured programming and to be implementable as a compact, single-pass compiler. Its rules favor clarity and compile-time checking: declare before use, strong typing, and a syntax that reads as ordered declarations followed by statements. Wirth's later languages (Modula-2, Oberon) continued the theme of small, checkable languages, and the discipline Pascal encourages carried into many teaching curricula.

## Standard library and notable packages

Standard Pascal defines a small built-in set of procedures and functions for input and output (`Read`, `Write`), math, and string handling, with much left to the implementation. Free Pascal ships an extensive runtime library (RTL) and a free component library (FCL) covering collections, files, networking, and data formats; Lazarus adds the LCL (Lazarus Component Library) for graphical applications. There is no large central package registry comparable to those of newer languages; libraries are distributed as source units.

## Testing and packaging

Standard Pascal has no test framework. Free Pascal includes [FPCUnit](https://wiki.freepascal.org/fpcunit), an xUnit-style framework, and Lazarus integrates it. Distribution is typically as source units compiled into the consuming project, or as compiled libraries for a specific platform and compiler version.

```pascal
procedure TestAdd;
begin
  AssertEquals(5, 2 + 3);
end;
```

## Performance and concurrency

Pascal compiles to native code and performs comparably to C for equivalent procedural work. Concurrency is not part of standard Pascal; Free Pascal provides threading through its runtime library (the `TThread` class and lower-level thread routines) and platform calls, with explicit locking for shared state. Because allocation is manual, performance-sensitive code can control exactly when memory is obtained and released.

## Common pitfalls

- Manual memory management: forgetting `dispose` leaks memory, and using a pointer after `dispose` is a dangling-pointer defect.
- Uninitialized variables hold whatever was on the stack or heap; initialize before reading.
- Dialect differences: code written for Turbo Pascal, Delphi's Object Pascal, or ISO Pascal may not compile unchanged elsewhere.
- Range and overflow checks are often compiler options; disabling them for speed removes protection against out-of-range indexing and integer overflow.
- Single-pass declaration rules require careful ordering, and mutual recursion across units needs forward declarations.

## Secure coding

Pascal gives strong compile-time typing but leaves memory and bounds handling to the programmer and to compiler switches:

- Out-of-bounds array access: with range checking disabled, an index outside a declared range reads or writes adjacent memory. Keep range checks on for untrusted input; this relates to [CWE-125](https://cwe.mitre.org/data/definitions/125.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Integer overflow: arithmetic can wrap when overflow checking is off; enable it for arithmetic driven by external data, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Use-after-free and leaks: manual `new` and `dispose` can create dangling pointers, which maps to [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Input validation: parse and bound external data explicitly before placing it into fixed-size structures, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

Tooling is limited compared with mainstream languages. Free Pascal's compiler hints and warnings, with range and overflow checks enabled, catch many issues; third-party static analysis for Pascal is scarce. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Free Pascal documentation](https://www.freepascal.org/docs.html), the language reference and runtime library guide.
- [Lazarus documentation and wiki](https://wiki.freepascal.org/), tutorials for the IDE and component library.
- [Niklaus Wirth, "Pascal User Manual and Report"](https://link.springer.com/book/10.1007/978-1-4612-5983-1), the original description of the language.

## Related pages

- [ALGOL](/languages/algol.md)
- [Delphi (Object Pascal)](/languages/delphi.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
