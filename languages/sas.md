# SAS

SAS (Statistical Analysis System) is a proprietary language and software system for data management and statistical analysis, developed at North Carolina State University from 1966 and released commercially by SAS Institute in 1976. Its programs combine a data-manipulation stage (the DATA step) with a set of procedures (PROC steps) that run analyses, and a macro language that generates code. It is used for clinical trial reporting, pharmaceutical and regulatory submissions, banking and insurance analytics, and large-scale statistical processing.

| Attribute | Value |
|---|---|
| Paradigm | Imperative data-step processing, declarative procedures, macro metaprogramming |
| Typing | Two base types only: numeric (floating point) and character |
| First appeared | 1976 (commercial) |
| Memory model | Managed by the system; row-at-a-time data-step processing |
| Reference implementation | [SAS](https://www.sas.com/) (SAS Institute, proprietary) |
| Typical uses | Clinical trials, regulatory submissions, banking and insurance analytics |
| Governance | [SAS Institute](https://www.sas.com/), proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [R](/languages/r.md), [languages index](/languages/README.md).

## Overview and history

SAS grew from a project to analyze agricultural data at North Carolina State University, where Anthony Barr, James Goodnight, and colleagues built a statistical package on mainframes. SAS Institute was founded in 1976 to develop and sell it. The system became entrenched in regulated industries, especially pharmaceutical research, where the US Food and Drug Administration has long accepted SAS transport files and SAS-based analysis for submissions.

SAS is proprietary, defined by SAS Institute rather than a public standard. The classic product is Base SAS with add-on modules; newer platforms include SAS Viya for cloud and in-memory processing. A SAS program is typically a sequence of DATA steps that build and transform datasets and PROC steps that summarize, model, or report them.

## Paradigm and type system

SAS has an unusually small type system: a variable is either numeric (stored as a floating-point number, which also represents dates as day counts) or character (a fixed-length string). The language's model is the DATA step, which reads a dataset observation by observation into a program data vector, applies statements, and writes observations out, implicitly looping over the input. PROC steps are declarative: you name a procedure and options, and it performs a fixed analysis. The macro language is a separate text-substitution layer that generates SAS code before it runs.

```sas
data sales;
  input item $ price;
  taxed = price * 1.1;        /* computed column */
  datalines;
widget 10
gadget 20
;
run;
```

## Toolchain and ecosystem

- Environments: SAS runs through the classic Display Manager, [SAS Studio](https://www.sas.com/en_us/software/studio.html) (browser-based), and SAS Enterprise Guide; SAS Viya adds cloud and in-memory engines.
- Procedures: analysis is delivered as PROC steps (`PROC MEANS`, `PROC FREQ`, `PROC SQL`, `PROC REG`, and many more) rather than a general function library.
- SQL: `PROC SQL` runs ANSI-style SQL against SAS datasets and external databases.
- Interoperability: SAS/ACCESS connects to external databases, and transport (`.xpt`) files move datasets between systems and to regulators.

```sas
proc means data=sales mean sum;
  var price;
run;
```

## Syntax tour

```sas
/* DATA step: read, compute, filter */
data report;
  set sales;                   /* read an existing dataset */
  length category $ 10;
  if price >= 15 then category = "high";
  else category = "low";
  total = price * quantity;
run;

/* Conditional and loop inside the implicit observation loop */
data squares;
  do n = 1 to 4;
     sq = n**2;
     output;                   /* write one observation per iteration */
  end;
run;

/* PROC SQL: set-based query */
proc sql;
  select category, mean(price) as avg_price
  from report
  group by category;
quit;

/* Macro variables and macros generate code */
%let cutoff = 15;
%macro flag(ds);
  data &ds._flagged;
    set &ds;
    expensive = (price >= &cutoff);
  run;
%mend flag;
%flag(sales)
```

## Idioms and different approaches

- Choose between the DATA step and `PROC SQL` by task: the DATA step suits row-by-row logic and lookups, while `PROC SQL` suits joins and set-based summaries.
- Use the macro language to generate repetitive code and parameterize programs, but keep macro logic thin; heavy macro code is hard to read and debug.
- Prefer `PROC FORMAT` and informats/formats to recode and display values rather than hard-coding conversions.
- Use `BY`-group processing (with sorted input) instead of manual grouping loops.
- Keep DATA step statements aware of the implicit loop: `retain`, `output`, and automatic variables such as `_N_` and `first.`/`last.` control behavior across observations.

## Design principles

SAS was built so analysts could read raw data, reshape it, and run established statistical procedures without programming infrastructure. The DATA step's implicit observation loop makes common per-row transformations concise, and PROC steps package validated statistical methods behind simple option syntax, which matters in regulated settings where method provenance is audited. The two-type data model and stable procedure interfaces favor long-lived, reproducible production programs over language flexibility.

## Standard library and notable packages

SAS capability is delivered as modules and procedures rather than packages. Base SAS provides the DATA step, `PROC SQL`, and reporting procedures (`PROC PRINT`, `PROC REPORT`, `PROC TABULATE`). SAS/STAT adds statistical modeling procedures (`PROC REG`, `PROC GLM`, `PROC MIXED`, `PROC LOGISTIC`), SAS/GRAPH and ODS Graphics produce charts, and SAS/ACCESS connects to external databases. SAS Viya adds the in-memory CAS engine and its analytic action sets.

## Testing and packaging

SAS has no single standard test framework in Base SAS; the community [SASUnit](https://sourceforge.net/projects/sasunit/) framework and the [SASjs](https://cli.sasjs.io/) toolchain provide unit testing and project structure.

```sas
%macro assert_equal(actual, expected);
  %if &actual = &expected %then %put PASS;
  %else %put FAIL: &actual ne &expected;
%mend;
%assert_equal(%eval(2+3), 5)
```

Reusable code is typically distributed as `.sas` program files and autocall macro libraries pointed to by the `SASAUTOS` option, rather than as a packaged artifact.

## Performance and concurrency

SAS processes a DATA step one observation at a time, streaming from disk, so large datasets are handled without loading everything into memory. Performance tuning focuses on reducing passes over the data, indexing datasets, using `WHERE` to subset at read time, and pushing joins into the database through SAS/ACCESS. For parallelism, SAS offers multithreaded procedures, the SPD (Scalable Performance Data) engine, MP CONNECT for multiprocessing, and, in SAS Viya, the CAS engine that distributes in-memory work across nodes.

## Common pitfalls

- Variable length is fixed on first assignment: a character variable truncates later values to its initial length unless you declare `length` first.
- Numeric precision: dates and large integers are stored as floating point, so exact comparisons and very large integers can lose precision.
- Missing values sort as the smallest numeric value and propagate through arithmetic; account for them in comparisons and sums.
- Macro versus DATA step timing: the macro language substitutes text before the step runs, so macro and data-step logic execute at different phases, a frequent source of confusion.
- Automatic conversion between character and numeric raises notes rather than errors and can hide data problems; convert explicitly with `input` and `put`.

## Secure coding

SAS programs in production often read external files, call the host operating system, and query databases, which creates the main risks:

- Operating-system command injection: the `X` command, `CALL SYSTEM`, the `SYSTASK` statement, and the `%SYSEXEC` macro run host commands; the `XCMD` system option controls whether this is allowed. Disable `NOXCMD` where shell access is not needed, and never build a command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- SQL injection: `PROC SQL` and pass-through SQL built by concatenating macro-variable values are injectable; validate and quote inputs, and prefer parameterized pass-through where the database supports it. This maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Code injection through macros: resolving untrusted text as macro code runs generated SAS; never pass unvalidated input into macro variables that build code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Untrusted data files: validate the structure and values of imported files (`PROC IMPORT`, `INFILE`) before processing, and treat externally supplied programs as untrusted.
- Credentials: do not embed database passwords in plain text in programs; use SAS authentication domains or encoded passwords (`PROC PWENCODE`), which relates to [CWE-798](https://cwe.mitre.org/data/definitions/798.html).

Tooling: SAS logs flag notes, warnings, and errors that often reveal unsafe conversions; code-review tooling and the SASjs linter check program style and some risk patterns during static analysis.

## Learning resources

- [SAS Documentation](https://documentation.sas.com/), the official product and language reference.
- [SAS Programming 1](https://support.sas.com/edu/schedules.html?ctry=us&crs=PROG1), SAS Institute's introductory course.
- SAS Support Communities, the user forums and samples.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [SQL](/languages/sql.md)
- [R](/languages/r.md)
- [All languages](/languages/README.md)
