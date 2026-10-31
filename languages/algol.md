# ALGOL

ALGOL (Algorithmic Language) is a family of imperative, block-structured languages defined by international committees from 1958 onward. ALGOL 60 established ideas that shaped most later languages: lexical block scope, nested procedures, structured control flow, and a formal grammar expressed in Backus-Naur Form. ALGOL 68 was a larger redesign. The language is largely historical today, used mainly through preservation projects and teaching, but its influence runs through Pascal, C, and their descendants.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, structured, block-structured |
| Typing | Static |
| First appeared | 1958 (ALGOL 58); ALGOL 60 in 1960; ALGOL 68 in 1968 |
| Memory model | Stack-based with block scope; ALGOL 68 added heap allocation and garbage collection |
| Reference implementation | No single reference; the defining Reports stood in for one, [MARST](https://www.gnu.org/software/marst/) translates ALGOL 60 to C and Algol 68 Genie runs ALGOL 68 |
| Typical uses | Historically scientific computing and algorithm publication; today teaching and preservation |
| Governance/standard | Defined by the Revised Report on ALGOL 60 and the Revised Report on ALGOL 68; no active body |

Related: [Pascal](/languages/pascal.md), [PL/I](/languages/pli.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

ALGOL was created by a committee of European and American computer scientists to provide a machine-independent language for describing algorithms, both for running and for publication. ALGOL 58 was a first attempt; ALGOL 60, defined in the 1960 report, was the influential version. Its report introduced Backus-Naur Form (BNF) to define syntax precisely, and it specified block structure, nested procedures with recursion, and call-by-name and call-by-value parameter passing. For years, journals published algorithms in ALGOL as a lingua franca.

ALGOL 68 was a later, larger redesign with a richer type system and new features, described in a report written in a distinctive formal notation; it was divisive and less widely adopted than ALGOL 60. There was no single reference implementation; the Reports served that role. Today the language runs through preservation tools: MARST translates ALGOL 60 to C, and Algol 68 Genie interprets ALGOL 68. Governance ended with the committees; the Reports are the lasting definition.

## Paradigm and type system

ALGOL is statically typed, imperative, and block-structured. A block introduces a scope for declarations, and blocks nest, so an inner procedure sees the variables of enclosing blocks: the origin of lexical scoping. ALGOL 60 offered a few primitive types (`integer`, `real`, `Boolean`) plus arrays, and procedures could be recursive. ALGOL 68 generalized the type system with user-defined modes, references, unions, and structures, and added heap allocation.

```algol
begin
  integer procedure factorial(n);
    value n; integer n;
    factorial := if n <= 1 then 1 else n * factorial(n - 1);
  print(factorial(5))
end
```

ALGOL 60's call-by-name parameter passing, in which an argument expression is re-evaluated each time the parameter is used, is a notable and subtle feature later languages generally dropped.

## Toolchain and ecosystem

- ALGOL 60: [MARST](https://www.gnu.org/software/marst/) translates ALGOL 60 source to C, which is then compiled by a C compiler.
- ALGOL 68: Algol 68 Genie (`a68g`) is an interpreter that runs ALGOL 68 programs on modern systems.
- There is no modern package ecosystem; historical implementations were tied to specific mainframes, and current use is through these preservation tools.

```bash
# ALGOL 60 via MARST, then a C compiler
marst factorial.alg -o factorial.c
cc factorial.c -lalgol -o factorial
./factorial
```

## Syntax tour

```algol
begin
  integer n, sum, i;
  n := 10;
  sum := 0;
  for i := 1 step 1 until n do
    sum := sum + i;
  print(sum)   comment prints 55;
end
```

## Idioms and different approaches

- Use nested blocks and procedures to limit the scope of names to where they are needed.
- Write recursive procedures for problems with a recursive structure, which ALGOL 60 supported from the start.
- In ALGOL 60, prefer call-by-value for ordinary arguments and reserve call-by-name for the rare cases that need re-evaluation, since call-by-name is easy to misuse.
- In ALGOL 68, use the richer modes (structures, unions, references) to model data, closer to later languages.

## Design principles

ALGOL was designed to describe algorithms clearly and independently of any machine, which led to a formal grammar and a clean block structure. The committee valued precise definition: the ALGOL 60 report's use of BNF made the syntax unambiguous and became a standard technique. ALGOL 60 deliberately left input and output out of the language proper, treating them as library concerns, which aided portability of the core but complicated real programs. ALGOL 68 pushed toward generality and orthogonality, at the cost of complexity.

## Standard library and notable packages

ALGOL 60 defined no standard library; even input and output were outside the language and supplied by each implementation, which is one reason programs did not port cleanly between machines. ALGOL 68 specified a standard environment with more built-in facilities, including transput (its term for input and output). There is no package ecosystem in the modern sense; the languages predate it, and current implementations ship only their own runtime support.

## Testing and packaging

ALGOL predates automated testing frameworks, and none is standard. Verification historically meant hand analysis and running programs against known results. There is no packaging system; a program was source compiled for a particular machine, and today it is source run through MARST or Algol 68 Genie. Testing current code means writing driver programs that check outputs.

## Performance and concurrency

On the hardware of its era, ALGOL compilers produced efficient code for numeric work, and the stack-based block model mapped well to machine implementation. Through modern preservation tools, ALGOL 60 performance depends on the generated C, and ALGOL 68 Genie is an interpreter, so it is slower than native code. Concurrency is not part of ALGOL 60. ALGOL 68 included parallel processing features (the `par` clause and semaphores) in its report, though support varied by implementation; in practice, concurrency is not a reason to use ALGOL today.

## Common pitfalls

- Call-by-name surprises: an argument passed by name is re-evaluated on each use, so side effects and index expressions behave in ways that trip up readers expecting call-by-value.
- Missing standard I/O in ALGOL 60: programs depend on implementation-specific input and output, hurting portability.
- Dialect differences: ALGOL 58, 60, and 68 are substantially different languages, and implementations added their own extensions.
- ALGOL 68's complexity: its generality and unusual terminology make programs harder to read than ALGOL 60.
- Relying on machine-specific behavior from historical compilers that modern tools do not reproduce.

## Secure coding

ALGOL is rarely deployed in modern security-relevant settings, but code run through current tools still handles input and arrays, so the general weaknesses apply:

- Out-of-bounds array access: historical implementations varied in whether they checked array bounds; code translated to C through MARST inherits C's lack of checking, so validate indices. This maps to [CWE-125](https://cwe.mitre.org/data/definitions/125.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Integer overflow: fixed-size integer arithmetic can overflow; bound values driven by input, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation: any data read from input is unchecked until the program checks it; validate structure and range, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Interfacing risk: ALGOL 60 run via translation to C crosses into unchecked native code, so treat the boundary with the care C requires.

There is no modern security tooling for ALGOL; where ALGOL 60 is translated to C, apply C-oriented analysis to the generated code. Treat any use of ALGOL for untrusted input as requiring manual review. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Revised Report on the Algorithmic Language ALGOL 60](https://www.masswerk.at/algol60/report.htm), the defining document.
- [MARST documentation](https://www.gnu.org/software/marst/), the GNU ALGOL 60 to C translator.
- [Algol 68 Genie](https://jmvdveer.home.xs4all.nl/en.algol-68-genie.html), an ALGOL 68 interpreter with documentation.

## Related pages

- [Pascal](/languages/pascal.md)
- [PL/I](/languages/pli.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
