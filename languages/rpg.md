# RPG (IBM)

RPG (Report Program Generator) is a statically typed, compiled language from IBM, first released in 1959 for generating business reports and now a general-purpose language on the IBM i platform (formerly AS/400 and iSeries). Early RPG used a fixed-column format and a built-in program cycle that read records and produced output automatically; modern RPG (ILE RPG, also called RPG IV) adds free-format syntax, procedures, and direct database access. It is used for business applications on IBM i, closely tied to the integrated Db2 database.

| Attribute | Value |
|---|---|
| Paradigm | Originally cyclic and fixed-format; modern RPG is procedural and free-format |
| Typing | Static |
| First appeared | 1959 (RPG IV / ILE RPG in 1994; free-format added in 2013) |
| Memory model | Static, managed by the runtime; ILE activation groups scope resources |
| Reference compiler | IBM ILE RPG compiler on IBM i |
| Typical uses | Business applications on IBM i: transaction processing, reporting, Db2 data access |
| Governance/standard | Proprietary, IBM; no open standard |

Related: [COBOL](/languages/cobol.md), [PL/I](/languages/pli.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

RPG began as a tool for generating reports from punched-card data, with a fixed-column source format and an implicit program cycle: the runtime read an input record, performed calculations, and wrote output, looping automatically until the input was exhausted. Through RPG II and RPG III it grew into a general business language on IBM midrange systems. RPG IV, introduced in 1994 as part of the Integrated Language Environment (ILE), added subprocedures, a wider set of data types, and modular binding. A free-format calculation syntax arrived in 2001, and fully free-format RPG, which drops the column dependence entirely, became available in 2013.

RPG runs on IBM i, the operating system for IBM Power servers descended from the AS/400. It is proprietary to IBM, with no open standard, and its development is tightly integrated with the Db2 for i database, so data access is often a first-class part of the language rather than a separate library.

## Paradigm and type system

RPG is statically typed. Modern ILE RPG declares variables and data structures with explicit types (character, packed and zoned decimal, integer, date, time) and supports subprocedures with typed parameters and return values. The historical program cycle still exists but is usually bypassed in modern code in favor of explicit read loops and procedures. Fixed-format RPG placed each part of a statement in specific columns; free-format RPG uses ordinary free-form statements.

```rpg
**free
dcl-s hours packed(5:2) inz(40.00);
dcl-s rate  packed(5:2) inz(25.50);
dcl-s gross packed(9:2);

gross = hours * rate;
dsply ('Gross pay: ' + %char(gross));
```

## Toolchain and ecosystem

- Compiler: the ILE RPG compiler on IBM i produces modules bound into programs and service programs.
- IDE: development uses Rational Developer for i (an Eclipse-based IDE) or the older green-screen SEU editor; VS Code extensions exist for IBM i.
- Database: Db2 for i is integrated, accessed through native record-level I/O or embedded SQL.

There is no package manager in the modern sense; reusable code is built into service programs and shared through binding directories, and open-source tooling for IBM i is distributed through the platform's open-source package system.

## Syntax tour

```rpg
**free
// Read a customer file and total balances
dcl-f customers disk;
dcl-s total packed(11:2) inz(0);

dow not %eof(customers);
  read customers;
  if not %eof(customers);
    total += balance;
  endif;
enddo;

dsply ('Total balance: ' + %char(total));
*inlr = *on;
```

## Idioms and different approaches

- Write new code in fully free-format RPG with explicit read loops rather than relying on the implicit program cycle.
- Factor logic into subprocedures in service programs and bind them, rather than large monolithic programs.
- Use built-in functions (`%char`, `%dec`, `%trim`, `%eof`) for conversions and checks instead of older operation codes.
- Use embedded SQL with host variables for set-based database work, and native record I/O for simple keyed access.
- Declare precise `packed` or `zoned` decimal types for monetary values to keep exact arithmetic.

## Design principles

RPG was designed to produce business reports and process records with minimal code, originally by having the runtime drive a fixed cycle so the programmer specified mostly the data and the calculations. Its close coupling to the IBM database and operating system makes data access direct and efficient on that platform. Modern RPG keeps backward compatibility, so decades-old fixed-format programs still compile, while free-format syntax and ILE modularity bring it closer to contemporary procedural languages.

## Standard library and notable packages

RPG's capabilities come from the language's operation codes and built-in functions and from the IBM i operating system: integrated Db2 database access, the system's APIs for files and jobs, and service programs that package reusable procedures. There is no cross-platform package registry; shared code lives in service programs and binding directories. IBM i also hosts an open-source environment (through which tools such as Git and interpreters are installed) that RPG programs can call.

## Testing and packaging

RPG has no single standard test framework, but RPGUnit, an xUnit-style framework for ILE RPG, is in common use for unit testing procedures. Code is packaged as compiled programs and service programs on IBM i, grouped into libraries and bound through binding directories; deployment moves these objects between environments under change control.

```rpg
**free
// An RPGUnit-style test procedure checks a result
dcl-proc test_gross export;
  dcl-s result packed(9:2);
  result = calcGross(40.00: 25.50);
  aEqual(1020.00: result);
end-proc;
```

## Performance and concurrency

RPG compiles to native code on IBM i and runs efficiently for record and transaction processing, with the integrated database reducing the cost of data access. Concurrency is handled largely by the operating system: IBM i runs many jobs and activation groups in parallel, and the database manages locking and commitment control for concurrent access. RPG programs are typically single-threaded; thread support exists but is used cautiously, so shared-state concurrency within a program is uncommon compared with relying on the platform's job and transaction model.

## Common pitfalls

- Mixing the implicit program cycle with explicit logic, which makes control flow hard to follow in older code.
- Fixed-format column errors: in legacy source, a field in the wrong column changes meaning silently.
- Field truncation: moving a value into a shorter character or decimal field drops data without an error.
- Numeric overflow in packed or zoned decimal arithmetic when results exceed declared digits.
- Resource scoping across ILE activation groups, where files or storage outlive or die with the wrong group.

## Secure coding

RPG's data model and its tight database coupling put most of its security-relevant risks in fixed-length field handling and in SQL:

- SQL injection: dynamic SQL built by concatenating untrusted input into a statement is injectable; use parameter markers and host variables with prepared statements. This maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Fixed-length field handling: moving external data into fixed character or decimal fields truncates or mis-aligns it, and unchecked lengths cause data corruption; validate and bound input lengths. This relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html).
- Numeric overflow: packed and zoned arithmetic can overflow declared digits; check ranges on untrusted values, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Input validation: data from display files, data queues, and messages is unchecked until validated; check structure and range at the boundary, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Command injection: passing untrusted input to system command APIs (`QCMDEXC` and similar) is injectable; do not build commands from external data, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Dedicated static-analysis tooling for RPG is scarce. IBM i object authority and adopted-authority settings are an important platform control, and compiler diagnostics plus manual review of SQL and input handling are the main code-level controls. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- IBM i ILE RPG documentation, the language reference and programmer's guide.
- IBM i development material, for the surrounding operating system and database.
- [RPGUnit project](https://rpgunit.sourceforge.io/), an open-source unit-testing framework for ILE RPG.

## Related pages

- [COBOL](/languages/cobol.md)
- [PL/I](/languages/pli.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
