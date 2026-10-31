# APL

APL (A Programming Language) is a dynamically typed, array-oriented language created by Kenneth E. Iverson, whose notation was described in his 1962 book and first implemented at IBM in the mid-1960s. It is written in a concise symbolic notation where single glyphs name primitive functions that operate on whole arrays, so many algorithms become short expressions. It is used for financial and actuarial modeling, quantitative analysis, and concise expression of array algorithms.

| Attribute | Value |
|---|---|
| Paradigm | Array-oriented, functional, with imperative control available |
| Typing | Dynamic; values are multidimensional arrays of numbers or characters |
| First appeared | 1966 (notation described 1962) |
| Memory model | Automatic garbage collection |
| Reference implementation | No single one; [Dyalog APL](https://www.dyalog.com/) and GNU APL are common |
| Typical uses | Financial and actuarial modeling, quantitative analysis, array algorithms |
| Governance | ISO 8485 standard; vendors extend it |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [J](/languages/j.md), [languages index](/languages/README.md).

## Overview and history

Iverson devised APL's notation while at Harvard and IBM as a consistent way to describe algorithms and computer systems, and IBM implemented it as an interactive language on mainframes. Its distinguishing feature is a character set of special glyphs (such as `⍴`, `⍳`, `⌿`, and `⍉`) that denote primitive operations on arrays. APL ONE programs read right to left, apply functions to entire arrays at once, and favor composition of primitives over explicit loops.

There is no single reference implementation. The language is standardized by ISO 8485, and current practice centers on [Dyalog APL](https://www.dyalog.com/), a commercial implementation, with GNU APL as a free alternative. Modern dialects add nested arrays, anonymous functions, and namespaces beyond the original flat-array language.

## Paradigm and type system

APL is dynamically typed and array-first: the fundamental value is a possibly multidimensional array, and a scalar is a rank-zero array. Numbers and characters are the element types, and modern APL adds nested arrays whose elements are themselves arrays. Functions are either primitive (a glyph) or user-defined, and they take one argument (monadic) or two (dyadic) depending on context. Operators (higher-order functions such as reduce `/` and each `¨`) take functions as operands and produce derived functions.

```apl
total ← {+/⍵ × 1 + ⍺}     ⍝ dyadic: left arg is tax, right is prices
0.1 total 10 20 30         ⍝ 66
```

The same glyph often has a monadic and a dyadic meaning (`-` negates or subtracts), resolved by whether a left argument is present.

## Toolchain and ecosystem

- Interpreters: [Dyalog APL](https://www.dyalog.com/) (commercial, with a graphical session), GNU APL, and the browser-based [TryAPL](https://tryapl.org/).
- Input: special glyphs are entered through a keyboard layout, a prefix key, or an on-screen language bar.
- Distribution: Dyalog ships a package manager, [Tatin](https://tatin.dev/), for APL libraries, and code is also shared as workspace and script files.
- Interfacing: Dyalog provides .NET and native shared-library interfaces, and APL links to external code through these bridges.

```bash
apl --script <<'EOF'
+/ (⍳4) * 2
EOF
```

## Syntax tour

```apl
⍝ Comments start with the lamp glyph. Expressions run right to left.
name ← 'world'
⎕ ← 'hello, ', name          ⍝ ⎕ assignment prints

⍝ Index generator and whole-array arithmetic
⍳5                            ⍝ 1 2 3 4 5  (origin 1)
squares ← (⍳4) * 2            ⍝ 1 4 9 16

⍝ Reduce (/) sums; shape (⍴) reshapes
+/ 1 2 3 4                    ⍝ 10
3 3 ⍴ ⍳9                      ⍝ a 3-by-3 matrix of 1..9

⍝ Compression selects where a boolean is 1
v ← 5 2 8 1
(v > 3) / v                   ⍝ 5 8

⍝ A dfn is an anonymous function; ⍺ and ⍵ are its arguments
mean ← {(+/⍵) ÷ ≢⍵}
mean 2 4 6                    ⍝ 4

⍝ Error handling (Dyalog)
:Trap 0
    r ← 1 ÷ 0
:Else
    r ← 0
:EndTrap
```

## Idioms and different approaches

- Think in whole arrays: replace loops with reductions (`+/`), scans (`+\`), and the each operator (`¨`), applying functions to entire structures.
- Build selections with boolean masks and compression (`mask / array`) rather than indexing one element at a time.
- Compose primitives: trains and the composition operators let several functions combine into one derived function without naming intermediates.
- Choose dfns (`{ ... }` with `⍺`/`⍵`) for short anonymous functions and traditional (`∇`) definitions for longer ones with local variables and control structures.
- Mind the index origin: `⎕IO` is 1 by default but can be set to 0; code that assumes one or the other breaks if the setting differs.

## Design principles

APL was conceived as a notation first, with the goal that a precise written description of an algorithm could also execute. Its primitives are chosen so that array operations compose cleanly, which lets short expressions capture computations that would be long loops elsewhere. The cost is a steep reading curve and reliance on a special character set. The language rewards thinking about data as arrays transformed as wholes rather than as elements visited in sequence.

## Standard library and notable packages

APL's "standard library" is its set of primitive functions and operators, which already covers arithmetic, array reshaping, selection, sorting (`⍋` grade), set operations, and matrix inverse and solve (`⌹`). System functions (names beginning with `⎕`) provide file access, formatting, regular expressions (`⎕R`/`⎕S` in Dyalog), and environment control. Libraries are distributed through the Tatin package manager and vendor-supplied workspaces rather than a large third-party ecosystem.

## Testing and packaging

Dyalog ships testing support, and community frameworks exist; a simple approach asserts expected results directly.

```apl
add ← {⍺ + ⍵}
assert ← {⍺≡⍵: 'PASS' ⋄ 'FAIL'}
5 assert (2 add 3)            ⍝ PASS
```

Reusable code is packaged as script files (`.aplf`, `.apln`, `.dyalog`) or workspaces, and Tatin packages carry a manifest for dependency resolution.

## Performance and concurrency

Because primitives operate on whole arrays in the interpreter's compiled inner loops, idiomatic array code runs fast without explicit loops; the main performance advice is to express work as array operations rather than scalar iteration. Dyalog APL offers parallel execution through the `⌶` I-beam facilities and futures/isolates for multiprocess work, and it can call out to parallel native libraries. Flat arrays are more memory- and cache-friendly than deeply nested ones, so flattening data where possible helps throughput.

## Common pitfalls

- Index origin: `⎕IO` defaults to 1; code that assumes 0-origin indexing (or vice versa) produces off-by-one errors when the setting changes.
- Right-to-left evaluation with no precedence among functions: `2 × 3 + 4` is 14, not 10, because `+` applies first; parenthesize to be explicit.
- Monadic versus dyadic meaning: the same glyph differs by context, so an accidental or missing left argument changes the operation.
- Scalar extension and shape conformance: operations between arrays of different shapes either extend a scalar or raise a length error; a shape mismatch can be subtle.
- Readability: terse one-liners are hard to maintain; comment intent and decompose long trains.

## Secure coding

APL is used in financial back-office systems, so the main risks are executing untrusted input and shelling out:

- Code injection: the execute primitive `⍎` (monadic) evaluates a character string as APL code; never apply it to untrusted input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Operating-system command injection: `⎕SH` and `⎕CMD` (and `⎕OFF`-adjacent host facilities) run shell commands; never assemble the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Untrusted data and workspaces: loading a saved workspace or component file can restore arbitrary definitions and data; load only from trusted sources and validate imported arrays before use, which relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: when querying a database through a bridge, use parameterized statements rather than building SQL by string catenation, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Dependency provenance: review Tatin packages and shared workspaces before use, and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: Dyalog APL provides a workspace linting facility, [Link](https://dyalog.github.io/link/) plus editor integrations, that checks source during development; review uses of `⍎`, `⎕SH`, and `⎕CMD` specifically.

## Learning resources

- [Dyalog documentation](https://docs.dyalog.com/), the reference for the common commercial implementation.
- [Mastering Dyalog APL](https://www.dyalog.com/mastering-dyalog-apl.htm), a free introductory book.
- APL Wiki, a community reference for glyphs, dialects, and idioms.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [J](/languages/j.md)
- [K and Q](/languages/k-q.md)
- [All languages](/languages/README.md)
