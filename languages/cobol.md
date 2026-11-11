# COBOL

COBOL (Common Business-Oriented Language) is a statically typed, compiled language designed in 1959 for business data processing. It favors an English-like syntax, fixed-length record and field declarations through the `PICTURE` clause, and precise fixed-point decimal arithmetic. It remains in heavy use on mainframes for banking, insurance, payroll, and government systems, where large volumes of batch and transaction processing run against established data files.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural; object-oriented features added in COBOL 2002 |
| Typing | Static, with fixed-length fields declared by `PICTURE` clauses |
| First appeared | 1959 |
| Memory model | Static and stack allocation; `WORKING-STORAGE` is fixed at compile time, no garbage collector |
| Reference compiler | No single reference; IBM Enterprise COBOL and Micro Focus are common commercial compilers, [GnuCOBOL](https://gnucobol.sourceforge.io/) is open source |
| Typical uses | Mainframe batch and transaction processing, banking, insurance, payroll, government |
| Governance/standard | ISO/IEC 1989, latest edition ISO/IEC 1989:2023 |

Related: [PL/I](/languages/pli.md), [RPG (IBM)](/languages/rpg.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

COBOL grew out of a 1959 effort by the Conference on Data Systems Languages (CODASYL), with input from Grace Hopper's earlier work on English-like languages. The goal was a portable language for business data processing that managers could read. Standardization followed through ANSI and then ISO: COBOL-68, COBOL-74, COBOL-85 (which added structured programming constructs), COBOL 2002 (object orientation and free-form source), and the 2014 and 2023 editions.

There is no single reference implementation. IBM Enterprise COBOL for z/OS dominates the mainframe market, Micro Focus (now part of OpenText) provides compilers for distributed platforms, and GnuCOBOL translates COBOL to C and builds with a C compiler. A large share of running COBOL predates current standards, so dialect differences and compiler-specific extensions are a practical concern.

## Paradigm and type system

COBOL is procedural and statically typed. A program is organized into four divisions: `IDENTIFICATION`, `ENVIRONMENT`, `DATA`, and `PROCEDURE`. Data items are declared with a level number and a `PICTURE` clause that fixes the type, length, and layout: `PIC 9(5)` is a five-digit number, `PIC X(20)` is a twenty-character field, and `PIC S9(7)V99 COMP-3` is a signed packed-decimal value with two implied decimal places. Because field sizes are fixed at compile time, assignments that do not fit are truncated or padded according to defined rules rather than reallocating.

```cobol
       01  WS-CUSTOMER.
           05  WS-ID        PIC 9(6).
           05  WS-NAME      PIC X(30).
           05  WS-BALANCE   PIC S9(9)V99 COMP-3.
```

Object-oriented features (classes, methods, inheritance) exist in COBOL 2002 and later, but most production code is procedural.

## Toolchain and ecosystem

- Compiler: `cobc` from GnuCOBOL compiles and links; commercial compilers ship with mainframe or cross-platform toolchains.
- Build and job control: mainframe builds are driven by JCL (Job Control Language); distributed builds use makefiles or vendor tooling.
- Data: COBOL programs commonly read and write VSAM and sequential data sets, and embed SQL for Db2 access through a precompiler.

```bash
cobc -x -free payroll.cbl -o payroll
./payroll
```

Package management in the modern sense does not apply; shared code is distributed as copybooks (`COPY` members) that are textually included at compile time.

## Syntax tour

```cobol
       IDENTIFICATION DIVISION.
       PROGRAM-ID. PAYROLL.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-HOURS    PIC 9(3)V99 VALUE 40.00.
       01  WS-RATE     PIC 9(3)V99 VALUE 25.50.
       01  WS-GROSS    PIC 9(6)V99 VALUE 0.
       PROCEDURE DIVISION.
       MAIN-PARA.
           COMPUTE WS-GROSS = WS-HOURS * WS-RATE
           DISPLAY "Gross pay: " WS-GROSS
           IF WS-GROSS > 1000.00
               DISPLAY "Above threshold"
           END-IF
           STOP RUN.
```

## Idioms and different approaches

- Use the `PICTURE` clause to state the exact shape of each field rather than validating lengths later in code.
- Prefer `COMP-3` (packed decimal) for monetary values to keep exact decimal arithmetic.
- Factor repeated record layouts into copybooks and `COPY` them, so one definition serves many programs.
- Use scope terminators (`END-IF`, `END-PERFORM`) and structured `PERFORM` paragraphs in new code rather than `GO TO`.
- Keep edited (display) fields separate from computational fields, converting with `MOVE`.

## Design principles

COBOL was designed so that data definitions and business rules are explicit and readable by people who are not programmers, and so that programs are portable across the machines of the era. The fixed-length, position-based data model matches the record-oriented files and reports of business computing. Stability is a stated priority: standards preserve older behavior so that programs written decades ago still compile and produce identical numeric results.

## Standard library and notable packages

COBOL has no package ecosystem in the modern sense. Capabilities come from the language's verbs (`READ`, `WRITE`, `COMPUTE`, `STRING`, `INSPECT`, `SORT`) and from the surrounding platform: transaction monitors such as CICS and IMS, the Db2 database through embedded SQL, and VSAM for keyed file access. Reusable definitions are shared as copybooks. GnuCOBOL adds library routines and C interoperability for distributed environments.

## Testing and packaging

COBOL has no built-in test framework. Open-source unit-test frameworks such as [cobol-unit-test](https://github.com/neopragma/cobol-unit-test) exist, and commercial tools provide coverage and unit testing on the mainframe. Deployment is typically compilation into load modules managed by a change-control system rather than packaging a distributable artifact.

## Performance and concurrency

Compiled COBOL runs efficiently for its intended record and batch processing, and its fixed-point decimal arithmetic avoids the rounding issues of binary floating point for money. The traditional execution model is single-threaded batch. Concurrency is provided by the surrounding platform: transaction monitors such as CICS and IMS run many program instances in parallel regions, and some compilers add thread support. Language-level threading is not part of the traditional model, so shared-state concurrency as found in modern languages generally does not apply.

## Common pitfalls

- Field truncation: moving a value into a shorter `PICTURE` silently drops digits or characters, so size mismatches corrupt data without an error.
- Numeric overflow: arithmetic whose result exceeds the receiving field's declared digits is truncated unless `ON SIZE ERROR` is handled.
- Implicit decimal alignment: the `V` in a picture is an assumed decimal point, and mismatched scales between fields produce wrong results.
- Uninitialized `WORKING-STORAGE` carrying stale values when `VALUE` clauses are omitted.
- Dialect drift: compiler extensions that do not port between IBM, Micro Focus, and GnuCOBOL.

## Security relevance

COBOL reaches security practitioners almost entirely on the defensive side, as the language of mainframe systems that process money and personal records and that defenders have to audit. Offensive tooling written in COBOL is rare. The defensive patterns that counter each weakness below are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Mainframe business systems. COBOL runs core banking, insurance, payroll, and government batch and transaction processing on z/OS under CICS and IMS, against VSAM files and Db2. These systems hold regulated financial and personal data, so an assessor reads COBOL to see how that data is validated, moved, and stored.
- Embedded SQL and external interfaces. Many programs reach data through embedded SQL compiled by the Db2 precompiler and call C or system services, which is where external input meets fixed-length fields. See the [Database Security Reference](/DATABASE_SECURITY_REFERENCE.md).
- Little offensive presence. COBOL is not a tool-building language for red teams, so the security interest is reading and auditing existing code, and safely wrapping or migrating it.

### Dominant weakness classes

COBOL has no garbage collector and a fixed-length, position-based data model, so field-handling mistakes corrupt data even though classic pointer-style corruption is less common than in C. The weaknesses that matter are about field handling, numeric limits, and untrusted input:

- Fixed-length field handling. Moving external data into a shorter `PICTURE` field with `MOVE`, `STRING`, or reference modification truncates or mis-aligns it, and unchecked lengths in calls to C or system services can overflow buffers. These are [CWE-120](https://cwe.mitre.org/data/definitions/120.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Numeric overflow and truncation. Arithmetic whose result exceeds a field's declared digits is silently truncated unless `ON SIZE ERROR` is handled, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- SQL injection. Embedded SQL that concatenates untrusted input into a dynamic statement is injectable; this is [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Improper input validation. Data read from files, terminals, or messages is unchecked until the program checks its structure, sign, and range, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).

### Why it matters

Reading COBOL lets an analyst follow how a mainframe system validates, moves, and stores regulated data, and audit the embedded-SQL and external-call boundaries where untrusted input enters fixed fields. Tooling is scarce: COBOL support in SonarQube and commercial mainframe analyzers cover some of these patterns, and GnuCOBOL compiler warnings catch others, so manual review of data handling remains the main control, as the Secure coding section details.

## Secure coding

COBOL's fixed-length data model is the source of most of its security-relevant defects, especially where it meets untrusted input:

- Fixed-length buffer handling: copying external data into fixed fields with `MOVE`, `STRING`, or reference modification can truncate or mis-align data, and unchecked lengths in programs that call C or system services can overflow buffers. This relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Numeric overflow and conversion: arithmetic that exceeds a field's digits, or `MOVE` between fields of different scale, yields wrong values; handle `ON SIZE ERROR` and validate ranges. This maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation: data read from files, terminals, or messages is unchecked until the program checks it; validate structure, sign, and range at the boundary, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- SQL injection: embedded SQL that concatenates untrusted input into a dynamic statement is injectable; use host variables and parameters, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

Tooling is comparatively scarce. Commercial static analyzers (Micro Focus, and COBOL support in SonarQube) cover some of these patterns; GnuCOBOL compiler warnings catch others. Treat manual review of data handling as the primary control. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [GnuCOBOL documentation](https://gnucobol.sourceforge.io/), including the programmer's guide for an open-source compiler.
- IBM Enterprise COBOL documentation, the language and compiler reference for z/OS.
- [Mainframe and COBOL material on IBM Z education](https://www.ibm.com/z), for the surrounding platform.

## Related pages

- [PL/I](/languages/pli.md)
- [RPG (IBM)](/languages/rpg.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
