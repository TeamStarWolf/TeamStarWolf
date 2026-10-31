# BASIC

BASIC (Beginner's All-purpose Symbolic Instruction Code) is a family of imperative languages created at Dartmouth College in 1964 by John Kemeny and Thomas Kurtz to make programming approachable for non-specialists. Early dialects used line numbers and an interactive interpreter; later ones added structured constructs and dropped line numbers. BASIC spread widely on 1970s and 1980s microcomputers, and it survives today through dialects such as FreeBASIC and QB64 and, in a different line, in Visual Basic.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural; early dialects were unstructured (line-numbered) |
| Typing | Varies by dialect: often dynamic and weak in early forms, static in later ones |
| First appeared | 1964 |
| Memory model | Interpreter- or runtime-managed; varies by dialect |
| Reference implementation | No single reference; Dartmouth BASIC was the original, modern dialects include [FreeBASIC](https://www.freebasic.net/) and [QB64](https://qb64phoenix.com/) |
| Typical uses | Teaching, early microcomputer software, scripting and hobby programming |
| Governance/standard | ANSI X3.60 (Minimal BASIC) and ECMA-55; no active governing body, dialect-driven |

Related: [Visual Basic (classic)](/languages/visual-basic.md), [Pascal](/languages/pascal.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Dartmouth BASIC ran on a time-sharing system and was meant so that students in any discipline could write programs. Microcomputer makers adopted BASIC as the built-in language of the late 1970s and 1980s: Microsoft's BASIC shipped in ROM on many home computers, and dialects such as Applesoft BASIC, Commodore BASIC, and GW-BASIC defined a generation's first programming experience. Microsoft's QuickBASIC and QBasic later added structured programming (named procedures, block `IF`, no required line numbers).

There is no single reference implementation and no active standard body; the ANSI Minimal BASIC and Full BASIC standards and the ECMA equivalents describe a core that few dialects follow exactly. Modern open-source dialects include FreeBASIC (compiled, with a QuickBASIC-compatible mode) and QB64 (a QuickBASIC-compatible compiler). Visual Basic grew from this family into its own line, covered on its own pages.

## Paradigm and type system

BASIC is imperative and procedural. The type systems differ sharply across dialects. Early BASICs offered a few built-in types (numbers and strings, with a `$` suffix marking strings) and were weakly typed. Later dialects such as QuickBASIC added user-defined record types (`TYPE ... END TYPE`), explicit declarations (`DIM AS`), and stronger checking. Because the model varies, portable statements about typing hold only within a given dialect.

```basic
TYPE Point
    X AS INTEGER
    Y AS INTEGER
END TYPE

DIM origin AS Point
origin.X = 0
origin.Y = 0
```

## Toolchain and ecosystem

- Interpreter or compiler: historical dialects ran in an interpreter; FreeBASIC and QB64 compile to native executables.
- Editor: QBasic and QuickBASIC shipped integrated editors; modern dialects use ordinary text editors or their own IDEs.
- Libraries: capabilities depend on the dialect; FreeBASIC bundles a runtime and bindings to C libraries.

```bash
# FreeBASIC
fbc hello.bas
./hello
```

## Syntax tour

```basic
' Structured dialect (QuickBASIC / FreeBASIC style), no line numbers
DECLARE FUNCTION IsPrime (n AS INTEGER) AS INTEGER

FUNCTION IsPrime (n AS INTEGER) AS INTEGER
    DIM i AS INTEGER
    IF n < 2 THEN
        IsPrime = 0
        EXIT FUNCTION
    END IF
    FOR i = 2 TO INT(SQR(n))
        IF n MOD i = 0 THEN
            IsPrime = 0
            EXIT FUNCTION
        END IF
    NEXT i
    IsPrime = 1
END FUNCTION

DIM k AS INTEGER
FOR k = 2 TO 20
    IF IsPrime(k) THEN PRINT k;
NEXT k
PRINT
```

## Idioms and different approaches

- In modern dialects, use named `SUB` and `FUNCTION` procedures and block `IF`/`FOR`/`DO` rather than `GOTO` and line numbers.
- Declare variables with explicit types (`DIM AS`) and use `OPTION EXPLICIT` where available so typos do not create new variables.
- Keep dialect-specific features isolated so code can be ported between BASICs with less rework.
- Prefer string functions (`MID$`, `INSTR`, `LEN`) for text handling over character-by-character loops.

## Design principles

BASIC was designed for ease of learning and immediate interactive use: short keywords, an interpreter that reports errors as you run, and a small core a beginner could hold in mind. The original Dartmouth goals were access and simplicity over efficiency. Later structured dialects kept the approachability while adopting the procedures and block constructs that structured programming had shown to reduce errors.

## Standard library and notable packages

There is no single standard library; each dialect provides its own built-in functions for math, strings, and input and output, and often for graphics and sound on the target machine. Modern dialects extend this: FreeBASIC includes a runtime library and headers that bind to C libraries for graphics, networking, and more. There is no central package registry comparable to those of newer languages; code is shared as source.

## Testing and packaging

BASIC has no standard test framework. Testing is typically done by writing driver programs that exercise procedures and check results, or by using a dialect-specific community library. Distribution of compiled dialects is as native executables; interpreted dialects distribute source to be loaded by the interpreter.

```basic
' Minimal check-style test
IF IsPrime(7) = 1 THEN PRINT "ok" ELSE PRINT "fail"
```

## Performance and concurrency

Performance depends entirely on the dialect. Interpreted BASICs are slow relative to compiled languages; compiled dialects such as FreeBASIC produce native code with speed comparable to C for similar procedural work. Concurrency is not a core language feature; where it exists, it comes from dialect-specific threading libraries or from calling operating-system and C-library routines. Most BASIC programs are single-threaded.

## Common pitfalls

- Dialect incompatibility: programs written for one BASIC rarely run unchanged on another because keywords, types, and I/O differ.
- Implicit variable creation: without `OPTION EXPLICIT`, a mistyped name silently becomes a new zero-valued variable.
- `GOTO`-heavy control flow in old code is hard to follow and to modify safely.
- Weak typing in early dialects allows surprising coercions between numbers and strings.
- Line-numbered programs mix control flow with layout, making edits error-prone.

## Secure coding

Most classic BASIC ran in single-user settings, so its security history is thin, but modern compiled dialects that call into C and the system carry the usual native-code risks:

- Buffer and bounds handling: fixed-length strings and arrays in dialects that allow direct memory or C interop can overflow; bound external input before copying it. This relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html).
- Input validation: data read with `INPUT` or from files is unchecked until the program checks it; validate type and range, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Command and SQL construction: dialects that run shell commands (`SHELL`) or build database queries from concatenated input are injectable; avoid assembling commands or queries from untrusted strings, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html) and [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Integer overflow in fixed-size numeric types, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).

Dedicated security tooling for BASIC is scarce; rely on compiler warnings where the dialect provides them and on manual review of input handling and any C or shell interop. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [FreeBASIC manual](https://www.freebasic.net/wiki/DocToc), the reference for a modern compiled dialect.
- [QB64 Phoenix Edition wiki](https://qb64phoenix.com/qb64wiki/), documentation for a QuickBASIC-compatible compiler.
- [Kemeny and Kurtz, "Back to BASIC"](https://archive.org/details/backtobasichisto0000keme), the designers' account of the language's origins and goals.

## Related pages

- [Visual Basic (classic)](/languages/visual-basic.md)
- [Pascal](/languages/pascal.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
