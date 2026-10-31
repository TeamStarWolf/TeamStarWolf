# K and Q

K and Q are dynamically typed, array-oriented languages created by Arthur Whitney at Kx Systems, with K first appearing in 1993 and Q layered on top of it in 2003. K is a terse APL-descended language, and Q is a more readable layer whose words expand to K primitives; both are the query and programming languages of the kdb+ database, which stores and queries large time-series datasets in memory and on disk. They are used for financial market data, high-volume time-series analytics, and real-time and historical trade analysis.

| Attribute | Value |
|---|---|
| Paradigm | Array-oriented, functional, with a built-in query sublanguage (qSQL) |
| Typing | Dynamic; values are typed vectors and tables |
| First appeared | K in 1993; Q in 2003 |
| Memory model | Automatic: reference counting |
| Reference implementation | [kdb+ / q](https://kx.com/) (KX, proprietary) |
| Typical uses | Financial market data, time-series analytics, real-time trade analysis |
| Governance | [KX (formerly Kx Systems)](https://kx.com/), proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [APL](/languages/apl.md), [languages index](/languages/README.md).

## Overview and history

Arthur Whitney designed K as a small, fast array language in the APL tradition, implemented in a compact C core. Kx Systems built the kdb+ database on K, and introduced Q as a layer of readable words (`select`, `update`, `where`, `avg`) that compile to K, so that analysts could write queries without the densest notation. Q became the primary language users write, while K remains underneath. The combination is widely deployed in banks and trading firms for storing and querying tick data.

The system is proprietary, developed by KX. A q session is both a programming environment and a database: tables are first-class values, and a query sublanguage called qSQL resembles SQL while operating on in-memory and on-disk column stores.

## Paradigm and type system

Q is dynamically typed and array-oriented. Atoms have types (boolean, int, long, real, float, char, symbol, timestamp, and more), and the common values are typed vectors (homogeneous lists), dictionaries (mappings from a key list to a value list), and tables (dictionaries of column vectors). Functions are first-class, written with `{ ... }` and the implicit parameters `x`, `y`, and `z` or named arguments. Evaluation, as in APL and J, is right to left with no function precedence.

```q
total:{[tax;prices] sum prices * 1 + tax}
total[0.1; 10 20 30]        / 66
```

A table is a list of named column vectors, which is why column-wise operations and qSQL queries are natural and fast.

## Toolchain and ecosystem

- Interpreter and database: the `q` executable runs an interactive session and serves kdb+; the same process stores data, answers queries, and runs user code.
- Interprocess communication: q processes talk over a simple IPC protocol, which underlies tick-capture architectures (feed handlers, tickerplants, real-time and historical databases).
- Distribution: scripts are `.q` files; community code is shared through repositories such as the [KX code repositories](https://github.com/KxSystems) rather than a central package manager.
- Interfacing: C and other languages connect through the kdb+ C API and language bindings.

```bash
q -c "sum (til 4) xexp 2"   # command-line evaluation
```

## Syntax tour

```q
/ Comments start with a slash. Expressions run right to left.
name:`world                  / a symbol
"hello, ", string name

/ til generates indices (origin 0); xexp is power
til 5                        / 0 1 2 3 4
squares: (til 4) xexp 2      / 0 1 4 9

/ sum, avg, and other aggregates work on vectors
sum 1 2 3 4                  / 10

/ Dictionaries map keys to values
d:`a`b!1 2
d[`a]                        / 1

/ Tables are lists of named columns
t:([] sym:`AAPL`MSFT`AAPL; px:187.0 410.0 188.0)

/ qSQL queries tables
select avg px by sym from t

/ Functions with implicit args x and y
add:{x+y}
add[2;3]                     / 5

/ Error trapping with the protected-evaluation form
@[{1%0}; ::; {[e] 0}]        / returns 0 on error
```

## Idioms and different approaches

- Keep data in columnar tables and express analytics as qSQL (`select ... by ... from ...`) rather than row loops; the column store makes aggregations fast.
- Use vector operations and the adverbs (`/` over, `\` scan, `'` each, `/:` and `\:` each-right and each-left) instead of explicit iteration.
- Prefer Q words for code others will read, and drop to K primitives only where terseness or speed justifies the loss of clarity.
- Use symbols (`` `sym ``) for interned, repeated string values such as identifiers; they compare and group faster than character strings.
- Partition large historical tables on disk by date and store them as splayed columns so queries read only the needed columns.

## Design principles

The design goal is speed on large columnar and time-series data from a tiny core. K's compact implementation keeps the interpreter and its working set small enough to stay in cache, and the array model means aggregations run as tight vector operations. Q adds readable vocabulary on top without changing the semantics, so analysts write clearer code that still compiles to the fast K primitives. Tables as first-class values unify the programming language and the database, so analytics and storage share one model.

## Standard library and notable packages

Q's built-in words cover arithmetic and aggregation, list and dictionary manipulation, string and symbol handling, date and time types suited to market data, and the qSQL query verbs (`select`, `exec`, `update`, `delete`). The kdb+ system adds IPC, on-disk partitioned tables, and the tick-capture reference architecture. There is no large third-party package registry in the usual sense; organizations maintain internal libraries and share utilities through KX community repositories.

## Testing and packaging

Testing uses community frameworks or simple assertion helpers; a direct approach compares results.

```q
add:{x+y}
assert:{[e;a] if[not e~a; '"FAIL"]; `PASS}
assert[5; add[2;3]]         / `PASS
```

Reusable code is distributed as `.q` script files loaded with `\l`, and organizations structure larger systems as sets of scripts and namespaces rather than packaged artifacts.

## Performance and concurrency

kdb+ is built for throughput on large datasets: columnar storage, operations that run as vector loops, and a small interpreter that stays cache-resident. Keeping values in typed vectors and symbols, querying with qSQL, and partitioning historical data on disk are the main tuning levers. A q process is single-threaded for its main loop; parallelism comes from the peach (parallel each) primitive across secondary threads, from multiple q processes communicating over IPC, and from map-reduce patterns across a cluster of historical-database processes.

## Common pitfalls

- Right-to-left evaluation with no operator precedence: `2*3+4` is 14; parenthesize when you mean otherwise.
- Index origin 0 and terse spellings make K especially hard to read; prefer Q words and comment intent.
- Type discipline in vectors: a list with mixed types is a general list, not a typed vector, which changes performance and some operations; keep columns homogeneous.
- Symbols versus strings: interned symbols and character strings behave differently in comparison and grouping; pick the right one for the data.
- Memory: holding references to large intermediate results keeps them alive under reference counting; let them go out of scope to reclaim memory.

## Secure coding

kdb+ systems frequently expose a q process to network clients, which makes access control and injection the central concerns:

- Remote code execution over IPC: a q process accepts messages that can evaluate arbitrary q unless restricted; set the message handlers (`.z.pg`, `.z.ps`) to validate and constrain incoming requests, and run with reduced privileges. Unrestricted evaluation of client input maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Code injection: the `value` and `eval` verbs execute a string or parse tree as q; never apply them to untrusted input, which also maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection: the `system` command (and the `\` system escape) runs host commands; never build the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- qSQL injection: building a qSQL query by concatenating untrusted text into a string passed to `value` is injectable; use functional-form queries with parameters rather than string catenation, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Authentication and transport: enable kdb+ user access control and run IPC over TLS so credentials and data are not exposed in transit; weak or absent authentication relates to [CWE-306](https://cwe.mitre.org/data/definitions/306.html). Review dependency provenance in the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: KX documents access-control and TLS configuration for kdb+; there is no widely adopted dedicated security linter, so review the IPC message handlers and every use of `value`, `eval`, and `system` by hand.

## Learning resources

- [KX documentation](https://code.kx.com/q/), the official q and kdb+ reference.
- [Q for Mortals](https://code.kx.com/q4m3/), a free introductory book by Jeffry Borror.
- [KX Academy](https://kx.com/academy/), vendor training materials.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [APL](/languages/apl.md)
- [J](/languages/j.md)
- [SQL](/languages/sql.md)
- [All languages](/languages/README.md)
