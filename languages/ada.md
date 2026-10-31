# Ada

Ada is a statically typed, compiled language first designed in the late 1970s under a United States Department of Defense program and named for Ada Lovelace. It emphasizes strong typing, run-time checking, readability, and features for large, long-lived, safety-critical systems. It is used in avionics, rail signaling, spacecraft, defense systems, and other domains where correctness and certification matter. The language is defined by an ISO standard and revised periodically.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, object-oriented, concurrent, with contracts |
| Typing | Static, strong, with user-defined constrained types |
| First appeared | 1980 (standardized 1983; revisions through Ada 2022) |
| Memory model | Manual, with scoped and storage-pool control; optional access checks |
| Reference compiler | No single reference; [GNAT](https://www.adacore.com/community) (part of GCC) is widely used |
| Typical uses | Avionics, rail, spacecraft, defense, safety-critical systems |
| Governance/standard | [ISO/IEC 8652](https://www.iso.org/standard/61507.html), via ISO JTC1/SC22/WG9 |

Related: [C](/languages/c.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Ada was created to replace the many languages then used in Department of Defense systems with one designed for reliability and maintainability. The first standard, Ada 83, was followed by Ada 95 (which added object orientation and protected objects for concurrency), Ada 2005, Ada 2012 (which introduced contract-based programming with preconditions, postconditions, and type invariants), and Ada 2022. A related subset and toolset, SPARK, supports formal verification of Ada programs.

There is no single reference implementation; GNAT, now part of GCC and maintained with support from AdaCore, is the most widely available compiler. The language is governed through ISO working group WG9.

## Paradigm and type system

Ada's type system is a defining feature. Programmers define types with explicit ranges and constraints, and the compiler and run time check them, so a `Day_Of_Month` can be declared to hold only 1 through 31. Strong typing prevents accidental mixing of unrelated numeric types. Ada 2012 added contracts that state preconditions, postconditions, and invariants, which tools can check at run time or prove statically.

```ada
subtype Day_Of_Month is Integer range 1 .. 31;

function Next_Day (D : Day_Of_Month) return Day_Of_Month
  with Pre => D < 31;
```

Packages group declarations into specifications and bodies, separating interface from implementation.

## Toolchain and ecosystem

- Compiler: [GNAT](https://www.adacore.com/community) builds Ada and integrates with GCC; `gnatmake` and `gprbuild` drive builds.
- Build and project files: GPRbuild reads `.gpr` project files.
- Package manager: [Alire](https://alire.ada.dev/) fetches and builds library dependencies.

```bash
alr init --bin app
cd app
alr build
```

## Syntax tour

```ada
with Ada.Text_IO; use Ada.Text_IO;

procedure Shapes is
   type Shape_Kind is (Circle, Rectangle);

   type Shape (Kind : Shape_Kind) is record
      case Kind is
         when Circle    => Radius : Float;
         when Rectangle => Width, Height : Float;
      end case;
   end record;

   function Area (S : Shape) return Float is
   begin
      case S.Kind is
         when Circle    => return 3.14159265 * S.Radius * S.Radius;
         when Rectangle => return S.Width * S.Height;
      end case;
   end Area;

   C : constant Shape := (Kind => Circle, Radius => 2.0);
begin
   Put_Line ("area:" & Float'Image (Area (C)));
end Shapes;
```

## Idioms and different approaches

- Define constrained subtypes so the compiler and run time reject out-of-range values at the boundary.
- Separate a package specification (the interface) from its body (the implementation).
- Use contracts (`Pre`, `Post`, `Type_Invariant`) to state and check obligations.
- Use protected objects and tasks for concurrency rather than raw threads and locks.
- Prefer the language's built-in checks over hand-written validation where a subtype can express the rule.

## Design principles

Ada was designed for programs that must run correctly for decades, so it favors readability over brevity, explicitness over inference, and compile-time and run-time checking over silent assumptions. The language assumes code is read far more often than written, and that catching an error at compile or run time is cheaper than a failure in the field.

## Standard library and notable libraries

The standard library provides text input and output (`Ada.Text_IO`), containers (`Ada.Containers.Vectors`, `Hashed_Maps`), strings (`Ada.Strings`), numerics, and tasking primitives. For high-assurance work, [SPARK](https://www.adacore.com/about-spark) is a subset with a toolset that proves the absence of run-time errors and conformance to contracts. Libraries are distributed through the Alire index.

## Testing and packaging

Ada has no single standard test framework; [AUnit](https://github.com/AdaCore/aunit) is a widely used xUnit-style framework. Projects are built and distributed with GPRbuild project files, and Alire manages library packaging and dependencies.

```ada
with AUnit.Assertions; use AUnit.Assertions;

procedure Test_Add is
   function Add (A, B : Integer) return Integer is (A + B);
begin
   Assert (Add (2, 3) = 5, "add sums two integers");
end Test_Add;
```

## Performance and concurrency

Ada compiles to native code and performs comparably to C for equivalent work; run-time checks can be disabled selectively for hot paths once code is verified. Concurrency is part of the language: tasks are concurrent units, and protected objects provide mutually exclusive access to shared data without explicit locks. The Ravenscar and Jorvik profiles restrict tasking to a subset that is analyzable for real-time and certified systems.

## Common pitfalls

- Suppressing run-time checks globally for performance, which removes the safety the language provides.
- Unchecked deallocation (`Ada.Unchecked_Deallocation`) reintroducing dangling pointers.
- Overly tight numeric subtypes raising `Constraint_Error` on valid edge data.
- Confusing a type with its subtypes, or mixing distinct numeric types that need explicit conversion.
- Task termination and exception propagation across tasks behaving differently than expected.

## Secure coding

Ada's checks eliminate many classes of defect by default, but unsafe features and interfacing remain risks:

- Out-of-bounds access: array and subtype range checks raise `Constraint_Error` rather than corrupting memory; do not suppress these on untrusted input. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Dangling pointers: `Ada.Unchecked_Deallocation` and access types can create use-after-free; confine and audit their use. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: overflow raises `Constraint_Error` when checks are on; keep them enabled for untrusted arithmetic. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Interfacing with C: data crossing to and from C bypasses Ada's checks, so validate at the boundary, which can involve [CWE-78](https://cwe.mitre.org/data/definitions/78.html) when launching processes.

Tooling: use [SPARK](https://www.adacore.com/about-spark) to prove the absence of run-time errors in critical modules, and GNAT warnings and `gnatprove` for static analysis. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Ada Reference Manual](http://www.ada-auth.org/arm.html), the language standard in readable form.
- [learn.adacore.com](https://learn.adacore.com/), tutorials for Ada and SPARK.
- [Ada Programming on Wikibooks](https://en.wikibooks.org/wiki/Ada_Programming), an introductory text.

## Related pages

- [C](/languages/c.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
