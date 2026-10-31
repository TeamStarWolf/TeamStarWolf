# Raku

Raku is a dynamically typed, garbage-collected, multi-paradigm language that began as Perl 6 and was renamed in 2019. Designed under Larry Wall's direction, it keeps Perl's expressive spirit while adding gradual typing, a grammar engine for parsing, lazy evaluation, and built-in concurrency primitives. The main implementation is Rakudo, which runs on the MoarVM virtual machine, and the language is used for text processing, scripting, parsing and language work, and general-purpose programming.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: object-oriented, functional, procedural, concurrent |
| Typing | Gradual: dynamic by default, with optional static type constraints |
| First appeared | 2015 (as Perl 6); renamed Raku in 2019 |
| Memory model | Automatic: tracing garbage collection (MoarVM) |
| Reference implementation | [Rakudo](https://rakudo.org/) on [MoarVM](https://www.moarvm.org/) |
| Typical uses | Text processing, parsing, scripting, general-purpose programming |
| Governance | [Raku Steering Council](https://github.com/Raku/Raku-Steering-Council) with design documents |

Related: [Perl](/languages/perl.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Raku started in 2000 as a redesign of Perl, announced by Larry Wall, and spent many years in specification and implementation. The first stable language release arrived in 2015 under the name Perl 6. Because it is a separate language rather than a new version of Perl 5, the project renamed it Raku in 2019 to reduce confusion; the two languages now evolve independently.

The language is defined by its test suite (called roast) rather than a single prose standard, and Rakudo is the implementation that passes it. Rakudo compiles Raku to bytecode for MoarVM, and historically targeted the JVM as well.

## Paradigm and type system

Raku is gradually typed: variables are dynamic by default, but you can attach type constraints that are checked at run time and inform the compiler. It has a rich built-in type hierarchy, distinguishes value types from reference types, and supports multiple dispatch, where the method chosen depends on the types of all arguments.

```raku
multi greet(Str $who)        { "hi $who" }
multi greet(Int $count)      { "got $count items" }

say greet("world");   # dispatches on Str
say greet(42);        # dispatches on Int
```

Sigils mark variable roles: `$` for scalars, `@` for positional containers, `%` for associative containers, and `&` for callables.

## Toolchain and ecosystem

- Compiler and runtime: `raku` runs programs and an interactive read-eval-print loop.
- Packaging: modules are distributed through the [Raku ecosystem](https://raku.land/) and installed with [zef](https://github.com/ugexe/zef), the module manager.
- Distribution: [Rakudo Star](https://rakudo.org/star) bundles the compiler, zef, and a module set.
- Editing: the `Comma` IDE and editor plugins provide syntax support; the `raku` binary can dump the parse via `--target`.

```bash
zef install Cro
raku -c script.raku   # compile-check without running
```

## Syntax tour

```raku
# Variables and interpolation
my $name = "world";
say "hello, $name";

# Lists, maps, and ranges (lazy where possible)
my @squares = (0 ..^ 5).map(* ** 2);   # (0 1 4 9 16)
my %lookup  = a => 1, b => 2;

# Subroutines with typed, named parameters
sub greet(Str $who, Bool :$excited = False) {
    "hi $who" ~ ($excited ?? "." !! ".")
}

# Classes
class Point {
    has Int $.x;
    has Int $.y;
}

# Grammars parse structured text
grammar Number {
    token TOP { \d+ }
}
say Number.parse("42");   # matches

# Exception handling
my $value = try { "not a number".Int } // 0;
```

## Idioms and different approaches

- Use the `.map`, `.grep`, and `.reduce` methods with the `*` whatever-star for concise transformations: `@nums.grep(* > 0)`.
- Prefer grammars and tokens over hand-rolled regular expressions for anything that resembles a parser.
- Junctions (`any`, `all`, `one`) express set-like conditions: `if $x == any(1, 2, 3)`.
- Lazy lists and the sequence operator `...` let you describe infinite or on-demand sequences.
- Multiple dispatch replaces many manual type checks: write one `multi` per argument shape.

## Design principles

Raku keeps Perl's view that the language should bend to the programmer rather than the reverse, and that there is more than one way to do a thing. It adds consistency that Perl 5 lacked: uniform sigils that do not change with context, a single object model, and gradual typing that lets a program start untyped and gain constraints over time. The design documents, historically called the Synopses and now maintained as specification and roast, record the decisions.

## Standard library and notable modules

The built-in types cover strings, numerics (including rationals and arbitrary-precision integers), containers, and concurrency primitives (`Promise`, `Supply`, `Channel`). Ecosystem modules include [Cro](https://cro.raku.org/) for HTTP services and clients, [DBIish](https://github.com/raku-community-modules/DBIish) for database access, and a range of grammar and data-format libraries distributed through [raku.land](https://raku.land/).

## Testing and packaging

The built-in `Test` module provides assertion routines and emits TAP (Test Anything Protocol) output; `prove6` or `zef test` runs the suite.

```raku
use Test;
plan 1;
is 2 + 3, 5, "addition works";
```

A distribution carries a `META6.json` metadata file; `zef` installs from a local path or the ecosystem, and authors publish through the fez uploader or a Git repository the ecosystem indexes.

## Performance and concurrency

Rakudo compiles to MoarVM bytecode, which includes a just-in-time compiler for hot paths. Startup and some dynamic operations are slower than in compiled languages, so Raku suits tasks where expressiveness matters more than microsecond latency. Concurrency is built into the language:

- `Promise` represents a future value; `await` waits for it.
- `start { ... }` runs a block on the thread pool and returns a `Promise`.
- `Supply` and `Channel` model asynchronous streams and message passing between threads.
- `hyper` and `race` methods parallelize list operations across cores.

## Common pitfalls

- Startup time is noticeable for very short scripts because the compiler and runtime load first; it matters less for long-running programs.
- Containers versus values: `@array` in a scalar context behaves differently than in Perl 5, so read the containerization rules before porting code.
- The language is large, so two authors can solve a problem with different features; agree on a subset for shared code.
- Lazy sequences can hold references longer than expected; force evaluation with `.eager` when you need all elements now.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Code injection: `EVAL` compiles and runs a string as Raku source; never call it on untrusted input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). It is guarded behind the `MONKEY-SEE-NO-EVAL` pragma precisely because it is dangerous.
- Command injection: run external programs with `run(@args)` or `Proc::Async` using an argument list rather than passing a single string through a shell, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Input parsing: prefer grammars with explicit tokens over broad regular expressions on untrusted input to limit catastrophic backtracking.
- SQL injection: use DBIish placeholders and bound parameters rather than interpolating into query text, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html). See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Dependency supply chain: review ecosystem modules and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling is less mature than for older languages, so manual review and the `MONKEY-SEE-NO-EVAL` gate on `EVAL` carry more weight. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Raku documentation](https://docs.raku.org/), the official language and type reference.
- [Raku Guide](https://raku.guide/), an introductory tour.
- [raku.land](https://raku.land/) and [rakudo.org](https://rakudo.org/), the ecosystem index and compiler project.

## Related pages

- [Perl](/languages/perl.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
