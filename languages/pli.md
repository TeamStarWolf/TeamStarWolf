# PL/I

PL/I (Programming Language One) is a statically typed, compiled language designed by IBM in the mid-1960s to serve both scientific and business computing in one language. It combines block structure, extensive data types, string handling, and a condition-handling mechanism for run-time events. It was used heavily on IBM mainframes and in the Multics operating system, and it remains in use on IBM Z for long-lived mainframe applications.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, structured |
| Typing | Static, with extensive implicit conversions between types |
| First appeared | 1964 |
| Memory model | Static, automatic (stack), controlled, and based (heap) storage classes |
| Reference compiler | No single reference; IBM Enterprise PL/I for z/OS is the dominant compiler, [Iron Spring PL/I](http://www.iron-spring.com/) targets personal platforms |
| Typical uses | Mainframe scientific and business applications, systems programming (historically Multics) |
| Governance/standard | [ANSI X3.53-1976](https://www.iso.org/standard/11169.html) and ISO 6160 (PL/I) |

Related: [COBOL](/languages/cobol.md), [ALGOL](/languages/algol.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

IBM designed PL/I (originally called NPL) to replace the separate scientific (FORTRAN) and business (COBOL) languages with a single language for both communities, drawing ideas from FORTRAN, COBOL, and ALGOL. It offered a large feature set: many numeric and string data types, arrays and structures, pointer-based data, a preprocessor, multitasking, and an ON-condition mechanism that lets a program respond to run-time events such as overflow or end-of-file. The Multics operating system was written largely in a PL/I subset.

Standardization produced ANSI X3.53-1976 and the corresponding ISO standard, along with a defined general-purpose subset. There is no single reference implementation: IBM Enterprise PL/I for z/OS is the dominant compiler on the mainframe, and Iron Spring PL/I provides a compiler for OS/2 and Linux. Most running PL/I is mainframe business and scientific code maintained over decades.

## Paradigm and type system

PL/I is statically typed, procedural, and block-structured. It provides a broad set of data types: fixed and floating-point numbers in binary and decimal, fixed and varying character and bit strings, pictured data for formatted values, arrays, and structures. Variables have a storage class (`STATIC`, `AUTOMATIC`, `CONTROLLED`, or `BASED`) that controls lifetime and allocation. A defining trait is extensive implicit conversion: the language will convert between many types automatically, which is convenient but a frequent source of surprising results.

```pli
declare 1 Customer,
          2 Id        fixed binary(31),
          2 Name      character(30) varying,
          2 Balance   fixed decimal(11,2);
```

The ON-condition mechanism registers handlers for conditions such as `OVERFLOW`, `ZERODIVIDE`, `ENDFILE`, and `CONVERSION`, giving structured response to run-time events.

## Toolchain and ecosystem

- Compiler: IBM Enterprise PL/I for z/OS compiles on the mainframe; Iron Spring PL/I compiles on Linux and OS/2.
- Build: mainframe builds are driven by JCL; the compiler integrates with the platform's linkage editor and debuggers.
- Data and transactions: PL/I programs use the surrounding platform (VSAM files, Db2 through embedded SQL, CICS for transactions).

There is no modern package manager; reusable declarations are shared through `%INCLUDE` members, analogous to COBOL copybooks.

## Syntax tour

```pli
Payroll: procedure options(main);
   declare Hours   fixed decimal(5,2) initial(40.00);
   declare Rate    fixed decimal(5,2) initial(25.50);
   declare Gross   fixed decimal(9,2);

   Gross = Hours * Rate;
   put skip list('Gross pay:', Gross);

   if Gross > 1000 then
      put skip list('Above threshold');
end Payroll;
```

## Idioms and different approaches

- Declare precise numeric types (`fixed decimal` for money, `fixed binary` for counts) rather than relying on default conversions.
- Use ON-units to handle conditions such as `ENDFILE` and `OVERFLOW` where they occur, instead of checking after the fact.
- Choose the storage class deliberately: `BASED` with pointers for dynamic structures, `CONTROLLED` for explicit allocation, `AUTOMATIC` for locals.
- Share record and constant declarations through `%INCLUDE` members so one definition serves many programs.
- Prefer `VARYING` strings when length changes, and fixed strings when the layout is a record field.

## Design principles

PL/I was designed for generality: one language that could do the numeric work of FORTRAN and the data processing of COBOL, with a feature for most needs of the time. This produced a large language with many defaults and automatic conversions intended to make programming easier. The same generality makes the language harder to learn fully and makes some defaults surprising, a trade-off criticized then and since. The ON-condition system was an early, structured approach to run-time error handling.

## Standard library and notable packages

PL/I's capabilities are largely built in rather than drawn from a library ecosystem: the language includes string handling, mathematical built-in functions, formatted and stream I/O, record I/O, and storage management. On the mainframe, programs reach databases and transaction monitors (Db2, CICS, IMS) through the platform rather than language packages. There is no central package registry; shared code is distributed as source members included at compile time.

## Testing and packaging

PL/I has no standard unit-test framework. Testing is typically done with driver programs and platform test tooling, and commercial mainframe test and coverage tools support it. Deployment is compilation into load modules managed by a change-control system, not packaging of a distributable artifact.

## Performance and concurrency

PL/I compiles to efficient native code and its decimal arithmetic suits exact monetary calculation, so it performs well for its mainframe workloads. The language includes multitasking features (`TASK`, `EVENT`, `WAIT`) for concurrent execution, though in practice concurrency on the mainframe is often provided by the transaction monitor (CICS, IMS) running many program instances rather than by in-language tasking. Shared state in concurrent code must be coordinated explicitly.

## Common pitfalls

- Implicit conversions: automatic type conversion between numeric and string types can produce unexpected values or truncation; declare and convert deliberately.
- Precision and overflow in `FIXED DECIMAL` arithmetic, where intermediate results can exceed declared precision.
- String handling: mixing `VARYING` and fixed strings, or copying into a short fixed string, truncates data.
- Pointer and `BASED` storage errors producing dangling references or corruption.
- Relying on language defaults (default attributes of undeclared variables) rather than explicit declarations.

## Secure coding

PL/I handles strings, pointers, and numeric conversions directly, so its security-relevant risks resemble those of other systems languages, especially where it meets untrusted input:

- Buffer and string handling: copying external data into fixed-length strings or buffers without a length check truncates or overflows them; bound input and use `VARYING` strings where appropriate. This relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html) and [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Numeric overflow and conversion: `FIXED DECIMAL` and `FIXED BINARY` arithmetic can overflow or lose precision, and implicit conversions can produce wrong values; enable and handle the `OVERFLOW`, `SIZE`, and `CONVERSION` conditions and validate ranges. This maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation: data read from files, terminals, or messages is unchecked until validated; check structure, sign, and range at the boundary, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- SQL injection: embedded SQL built by concatenating untrusted input is injectable; use host variables, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

Dedicated security tooling is scarce. Commercial mainframe static analyzers cover some patterns, and compiler diagnostics catch others; manual review of string handling, conversions, and data access is the primary control. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- IBM Enterprise PL/I for z/OS documentation, the language reference and programming guide.
- [Iron Spring PL/I documentation](http://www.iron-spring.com/), for a compiler on personal platforms.
- [PL/I language reference material on IBM Z](https://www.ibm.com/z), for the surrounding mainframe platform.

## Related pages

- [COBOL](/languages/cobol.md)
- [ALGOL](/languages/algol.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
