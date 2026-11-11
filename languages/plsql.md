# PL/SQL

PL/SQL (Procedural Language/SQL) is Oracle's statically typed, block-structured procedural extension to SQL, introduced with Oracle Database version 6 in 1991. It adds variables, control flow, procedures, functions, packages, and exception handling to SQL, and it runs inside the Oracle Database engine so that procedural logic executes close to the data. It is used for stored procedures, triggers, package-based application logic, and batch processing in Oracle-based systems.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, block-structured, with embedded SQL |
| Typing | Static, strong, with SQL and PL/SQL-specific types |
| First appeared | 1991 (Oracle Database 6) |
| Memory model | Managed by the database engine |
| Reference implementation | [Oracle Database](https://www.oracle.com/database/) (Oracle, proprietary) |
| Typical uses | Stored procedures, triggers, package logic, batch processing |
| Governance | Oracle Corporation, proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [SQL](/languages/sql.md), [languages index](/languages/README.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain PL/SQL code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,489 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing PL/SQL code (typical uses: stored procedures, triggers, package logic, batch processing), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [SQL](/languages/sql.md), [T-SQL](/languages/tsql.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Oracle introduced PL/SQL to let developers write procedural logic that runs inside the database, reducing round trips between an application and the data and allowing complex operations to be packaged as callable units. Its syntax and structure draw on Ada, with `BEGIN`/`END` blocks, strong typing, and packages that separate a specification from a body. The language has grown features such as bulk binding, autonomous transactions, object types, and native compilation across Oracle releases.

PL/SQL is proprietary to Oracle and runs only in the Oracle Database and compatible engines. It embeds SQL directly, so a procedure can mix procedural statements with queries and data modification, and the engine compiles the unit and stores it in the database.

## Paradigm and type system

PL/SQL is imperative and statically typed. A program is a block with an optional declaration section, an executable section, and an exception section. Types include the SQL column types plus PL/SQL types such as `BOOLEAN`, records, nested tables, varrays, and associative arrays (index-by tables). The anchored types `%TYPE` and `%ROWTYPE` declare a variable to match a column or a whole row, so code stays consistent with the schema.

```sql
CREATE OR REPLACE FUNCTION total(p_tax NUMBER, p_sum NUMBER)
    RETURN NUMBER IS
BEGIN
    RETURN p_sum * (1 + p_tax);
END;
/
```

Cursors iterate over query results, and the language integrates SQL so tightly that a `SELECT ... INTO` reads a row directly into variables.

## Toolchain and ecosystem

- Database: PL/SQL runs inside [Oracle Database](https://www.oracle.com/database/); the free [Oracle Database Express Edition](https://www.oracle.com/database/technologies/appdev/xe.html) is available for development.
- Development tools: [SQL Developer](https://www.oracle.com/database/sqldeveloper/) and SQL*Plus edit, compile, and run PL/SQL; third-party IDEs such as Toad are also common.
- Packaging: code is organized into packages (a specification and a body) stored in the database and invoked by name.
- Analysis: Oracle's `PL/Scope` and `DBMS_HPROF` profiler assist review and tuning; third-party tools add static analysis.

```sql
BEGIN
    DBMS_OUTPUT.PUT_LINE(total(0.1, 60));
END;
/
```

## Syntax tour

```sql
DECLARE
    v_name    VARCHAR2(50) := 'world';
    v_total   NUMBER := 0;
    CURSOR c_products IS SELECT price FROM products WHERE price > 0;
BEGIN
    DBMS_OUTPUT.PUT_LINE('hello, ' || v_name);

    -- Loop over a cursor
    FOR rec IN c_products LOOP
        v_total := v_total + rec.price;
    END LOOP;

    -- Conditionals
    IF v_total > 100 THEN
        DBMS_OUTPUT.PUT_LINE('large');
    ELSE
        DBMS_OUTPUT.PUT_LINE('small');
    END IF;

    -- Read a single row into variables
    SELECT COUNT(*) INTO v_total FROM products;

EXCEPTION
    WHEN NO_DATA_FOUND THEN
        v_total := 0;
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('error: ' || SQLERRM);
END;
/
```

## Idioms and different approaches

- Anchor variable types to the schema with `%TYPE` and `%ROWTYPE` so column changes propagate automatically.
- Use bulk operations (`BULK COLLECT` and `FORALL`) to process many rows in one context switch rather than row-by-row loops, which cuts the overhead between the PL/SQL and SQL engines.
- Group related procedures and functions into packages; the package specification is the stable interface and the body holds the implementation.
- Handle named exceptions explicitly and reserve `WHEN OTHERS` for logging and re-raising, not for silently swallowing errors.
- Prefer cursor `FOR` loops for simple iteration and explicit cursors with bulk fetch for large result sets.

## Design principles

PL/SQL exists to run procedural logic inside the database, so that data-intensive work avoids network round trips and executes where the data lives. Its Ada-derived structure (declarative blocks, strong typing, packages, exceptions) favors large, maintainable bodies of server-side logic. Tight SQL integration means queries and procedural code share types and flow together, and features such as bulk binding exist specifically to reduce the cost of moving between the procedural and set-based engines.

## Standard library and notable packages

PL/SQL ships a large set of Oracle-supplied packages. Common ones include `DBMS_OUTPUT` for debug output, `DBMS_SQL` and `EXECUTE IMMEDIATE` for dynamic SQL, `DBMS_SCHEDULER` for jobs, `UTL_FILE` for file I/O, `UTL_HTTP` for web requests, `DBMS_LOB` for large objects, `DBMS_CRYPTO` for cryptography, and `DBMS_ASSERT` for validating identifiers in dynamic SQL. These packages are the practical standard library for server-side logic.

## Testing and packaging

[utPLSQL](https://www.utplsql.org/) is the common unit-testing framework for PL/SQL.

```sql
-- utPLSQL expectation inside a test procedure
BEGIN
    ut.expect(total(0.1, 60)).to_equal(66);
END;
/
```

Code is packaged as database objects: packages, standalone procedures and functions, and triggers, versioned through migration scripts and deployed into the database.

## Performance and concurrency

The main performance concern is the context switch between the PL/SQL engine and the SQL engine: processing rows one at a time forces a switch per row, so bulk binding (`BULK COLLECT`, `FORALL`) is the primary optimization. Beyond that, native compilation speeds procedural code, and well-chosen SQL and indexes matter as much as in plain SQL. Concurrency is managed by the database through transactions, locking, and isolation levels; autonomous transactions let a subprogram commit independently of its caller, which is useful for logging but easy to misuse.

## Common pitfalls

- `WHEN OTHERS` without re-raising silently hides errors; always log and re-raise unless you are deliberately handling a specific condition.
- Row-by-row processing (the "slow-by-slow" pattern) is far slower than bulk operations; use `BULK COLLECT` and `FORALL` for volume.
- `SELECT ... INTO` raises `NO_DATA_FOUND` when no row matches and `TOO_MANY_ROWS` when more than one does; handle both.
- Committing inside a loop or relying on autonomous transactions can break transactional consistency; commit at well-defined boundaries.
- Implicit data-type conversion between `VARCHAR2`, `NUMBER`, and `DATE` can mask bugs and defeat indexes; convert explicitly.

## Security relevance

PL/SQL reaches security practitioners mainly as server-side database logic that defenders and auditors assess, since it runs inside the Oracle Database with access to data and, through supplied packages, to the host and network. The defensive patterns that counter each weakness below are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Database back ends. Stored procedures, triggers, and packages hold business logic inside Oracle Database for finance, government, and ERP systems, so an assessment of an Oracle estate often means reading PL/SQL. See the [Database Security Reference](/DATABASE_SECURITY_REFERENCE.md).
- Dynamic SQL and reporting. Code that builds statements at run time with `EXECUTE IMMEDIATE` or `DBMS_SQL` is where injection concentrates, the same class a web tester chases from the front end. See the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Host and network reach. Supplied packages such as `UTL_FILE`, `UTL_HTTP`, and `DBMS_SCHEDULER` external jobs let database code touch the file system, make outbound requests, and run operating-system work, which widens the attack surface well beyond the data.

### Dominant weakness classes

PL/SQL runs inside the database engine, which manages its memory, so the memory-corruption classes that dominate C and C++ do not apply. The weaknesses that matter are about injection and privilege:

- SQL injection in dynamic SQL. Concatenating untrusted input into `EXECUTE IMMEDIATE` or `DBMS_SQL` lets an attacker change a statement's meaning. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Privilege handling. Procedures run with definer rights by default, so an injectable or careless procedure can lend its owner's privileges to its caller. This is improper privilege management, [CWE-269](https://cwe.mitre.org/data/definitions/269.html).
- Operating-system and network injection. Arguments to `UTL_FILE`, `UTL_HTTP`, and scheduler external jobs built from untrusted input reach the host, mapping to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Information exposure. Returning raw `SQLERRM` text to end users reveals schema and query structure, which is [CWE-200](https://cwe.mitre.org/data/definitions/200.html).

### Why it matters

Reading PL/SQL lets an auditor find statements assembled by concatenation, definer-rights procedures that grant more than they should, and supplied-package calls that reach the operating system or network. Dedicated static analysis is thin: Oracle's `PL/Scope` supports identifier and call analysis and some third-party analyzers flag concatenated dynamic SQL, so manual review of every dynamic statement and privilege grant remains the main control.

## Secure coding

PL/SQL runs inside the database with significant privileges, so injection and privilege handling are the central concerns:

- SQL injection in dynamic SQL: building a statement by concatenating untrusted input into `EXECUTE IMMEDIATE` or `DBMS_SQL` lets an attacker change its meaning. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html). Use bind variables (`USING` clause) for values, and validate any dynamic identifier with `DBMS_ASSERT` (for example `DBMS_ASSERT.SIMPLE_SQL_NAME`) rather than interpolating it. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

```sql
-- Unsafe: input concatenated into dynamic SQL
-- EXECUTE IMMEDIATE 'SELECT ... WHERE name = ''' || p_name || '''';

-- Safe: a bind variable carries the value
EXECUTE IMMEDIATE 'SELECT id FROM users WHERE name = :1'
    INTO v_id USING p_name;
```

- Definer versus invoker rights: a procedure runs by default with its definer's privileges; grant the minimum needed and consider `AUTHID CURRENT_USER` (invoker rights) so a procedure does not lend elevated privileges, which relates to [CWE-269](https://cwe.mitre.org/data/definitions/269.html).
- Operating-system and network access: packages such as `UTL_FILE`, `DBMS_SCHEDULER` external jobs, and `UTL_HTTP` reach outside the database; restrict access control lists and never build their arguments from untrusted input, which relates to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Error handling: do not expose `SQLERRM` text to end users, since it reveals schema and query structure, which relates to [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Dependency and object provenance: review third-party packages and installed objects before granting them execution rights; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: Oracle's `PL/Scope` aids identifier and call analysis, and third-party static analyzers for PL/SQL flag dynamic SQL built from concatenation and other risk patterns.

## Learning resources

- [Oracle Database PL/SQL Language Reference](https://docs.oracle.com/en/database/oracle/oracle-database/19/lnpls/index.html), the official specification.
- Oracle Live SQL, a free in-browser environment with tutorials.
- [Oracle PL/SQL documentation](https://docs.oracle.com/en/database/), the product documentation set.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [SQL](/languages/sql.md)
- [T-SQL](/languages/tsql.md)
- [All languages](/languages/README.md)
