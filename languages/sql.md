# SQL

SQL (Structured Query Language) is a declarative language for defining, querying, and modifying data in relational databases, developed at IBM in the early 1970s and first standardized by ANSI and ISO in 1986. A program states what data it wants, and the database's query planner decides how to retrieve it. SQL is used for transactional applications, reporting and analytics, data warehousing, and as the interface to most relational data stores, including the data stores behind security tooling.

| Attribute | Value |
|---|---|
| Paradigm | Declarative, set-based, relational |
| Typing | Static per column, with a defined set of SQL data types |
| First appeared | 1974 (as SEQUEL); first standard 1986 |
| Memory model | Managed by the database engine |
| Reference implementation | No single one; [PostgreSQL](https://www.postgresql.org/), [SQLite](https://www.sqlite.org/), and MySQL are common |
| Typical uses | Transactional applications, reporting, analytics, data warehousing |
| Governance | ISO/IEC 9075, ISO/IEC JTC 1/SC 32 |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [PL/SQL](/languages/plsql.md), [languages index](/languages/README.md).

## Overview and history

SQL began as SEQUEL, designed by Donald Chamberlin and Raymond Boyce at IBM to query the experimental System R database, itself based on Edgar F. Codd's relational model. It was renamed SQL and became an ANSI standard in 1986 and an ISO standard in 1987. The standard has been revised repeatedly, adding outer joins and integrity constraints (SQL-92), recursive queries and window functions (SQL:1999 and SQL:2003), and JSON support (SQL:2016), among much else.

There is no single reference implementation. The standard is ISO/IEC 9075, and each database (PostgreSQL, Oracle Database, Microsoft SQL Server, MySQL, SQLite, and others) implements a core of it plus vendor extensions. Portable SQL sticks to standard features; most real applications use some dialect-specific syntax.

## Paradigm and type system

SQL is declarative and set-based: a query describes a result set in terms of relations (tables), and the engine's optimizer chooses an execution plan. Each column has a static type drawn from the standard's families: exact and approximate numerics (`INTEGER`, `DECIMAL`, `DOUBLE PRECISION`), character and binary strings, booleans, date and time types, and, in recent standards, JSON and XML. The special value `NULL` represents the absence of a value and uses three-valued logic, so a comparison with `NULL` yields unknown rather than true or false.

```sql
SELECT category, AVG(price) AS avg_price
FROM products
WHERE price > 0
GROUP BY category
HAVING COUNT(*) >= 3;
```

Constraints (`NOT NULL`, `UNIQUE`, `CHECK`, `PRIMARY KEY`, `FOREIGN KEY`) are part of the schema and let the engine enforce data integrity.

## Toolchain and ecosystem

- Engines: [PostgreSQL](https://www.postgresql.org/), MySQL, [SQLite](https://www.sqlite.org/), [Oracle Database](https://www.oracle.com/database/), and [Microsoft SQL Server](https://www.microsoft.com/sql-server), among others.
- Clients: each engine ships a command-line client (`psql`, `sqlite3`, `mysql`); graphical tools such as [DBeaver](https://dbeaver.io/) connect to many engines.
- Access from code: applications connect through standard interfaces such as ODBC and JDBC, or language drivers that expose prepared statements.
- Migrations and linting: tools such as [Flyway](https://flywaydb.org/) and [Liquibase](https://www.liquibase.org/) version schema changes, and [sqlfluff](https://sqlfluff.com/) lints and formats SQL.

```bash
sqlite3 :memory: "SELECT 2 + 3;"
```

## Syntax tour

```sql
-- Data definition
CREATE TABLE products (
    id       INTEGER PRIMARY KEY,
    name     VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    price    DECIMAL(10, 2) CHECK (price >= 0)
);

-- Data modification
INSERT INTO products (id, name, category, price)
VALUES (1, 'widget', 'tools', 9.99);

UPDATE products SET price = price * 1.1 WHERE category = 'tools';

-- Queries: joins, grouping, ordering
SELECT p.name, p.price
FROM products AS p
JOIN categories AS c ON c.name = p.category
WHERE p.price BETWEEN 5 AND 50
ORDER BY p.price DESC;

-- Window functions rank within groups
SELECT name, category,
       RANK() OVER (PARTITION BY category ORDER BY price DESC) AS rnk
FROM products;

-- Common table expression, including recursion
WITH RECURSIVE counter(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM counter WHERE n < 5
)
SELECT n FROM counter;
```

## Idioms and different approaches

- Think in sets, not rows: express work as joins, grouping, and filtering rather than iterating row by row, and let the optimizer plan it.
- Use explicit `JOIN ... ON` syntax rather than comma joins with conditions in `WHERE`; it separates join logic from filtering and avoids accidental cross joins.
- Prefer window functions over self-joins or correlated subqueries for ranking and running totals.
- Handle `NULL` deliberately: use `IS NULL`, `COALESCE`, and `IS DISTINCT FROM` rather than `=`, which never matches `NULL`.
- Let the schema enforce invariants with constraints rather than checking them only in application code.

## Design principles

SQL separates what from how: the programmer declares the desired result, and a cost-based optimizer picks indexes, join orders, and algorithms. This lets the same query stay correct as data volume and physical layout change. The relational model gives a small set of composable operations (selection, projection, join, aggregation) that combine into arbitrarily complex queries, and declarative integrity constraints keep data valid regardless of which application writes it. Transactions with ACID guarantees make concurrent modification safe.

## Standard library and notable packages

SQL's "standard library" is its built-in functions and operators: aggregates (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`), string and numeric functions, date and time arithmetic, `CASE` expressions, and window functions. Beyond the core language, each engine adds extensions: PostgreSQL has a rich extension system (for example [PostGIS](https://postgis.net/) for geospatial data), and engines provide full-text search, JSON functions, and procedural languages. Portable code limits itself to standard functions; dialect functions trade portability for capability.

## Testing and packaging

Database logic is tested with framework support such as [pgTAP](https://pgtap.org/) for PostgreSQL, or application-level tests that run queries against a disposable database.

```sql
-- pgTAP example
SELECT plan(1);
SELECT is( (SELECT 2 + 3), 5, 'addition works' );
SELECT finish();
```

Schema and query code are versioned as migration scripts managed by Flyway or Liquibase, which apply ordered changes and track which have run.

## Performance and concurrency

Query performance depends on the plan the optimizer chooses, which in turn depends on indexes and up-to-date statistics. Reading the plan with `EXPLAIN` (or `EXPLAIN ANALYZE`) is the primary tuning step: it shows whether the engine uses an index or scans a table, and how it orders joins. Create indexes for the columns used in filters and joins, keep statistics current, and avoid patterns that defeat indexes (functions on indexed columns, leading wildcards in `LIKE`). Concurrency is handled by the engine through transactions and isolation levels, which trade consistency against the amount of locking or versioning; choose the level that matches the application's tolerance for anomalies.

## Common pitfalls

- Three-valued logic: `WHERE x = NULL` matches nothing; use `IS NULL`. Aggregates and `NOT IN` with `NULL`s produce results that surprise newcomers.
- Implicit cross joins: listing tables in `FROM` without a join condition produces every combination of rows.
- `SELECT *` in application code couples the query to column order and hides which columns are used; list columns explicitly.
- Floating-point types for money lose cents to rounding; use `DECIMAL`/`NUMERIC` for currency.
- Dialect drift: syntax and functions that work in one engine may not exist in another; confirm against the target engine.

## Secure coding

SQL's central security risk is injection, because queries are often built from application input:

- SQL injection: concatenating untrusted input into a query string lets an attacker change the query's meaning, read or modify unauthorized data, and sometimes run commands. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html) and remains among the most damaging web weaknesses. The primary defense is parameterized queries (prepared statements with bound parameters), which send the query structure and the data separately so input can never become code. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

```sql
-- Unsafe: input concatenated into the query
-- "SELECT * FROM users WHERE name = '" + userInput + "'"

-- Safe: a parameter placeholder bound at execution
SELECT * FROM users WHERE name = ?;
```

- Least privilege: connect the application with an account that has only the rights it needs, so a successful injection or bug cannot drop tables or read unrelated data. Over-broad privileges relate to [CWE-269](https://cwe.mitre.org/data/definitions/269.html).
- Dynamic SQL and identifiers: parameters bind values, not table or column names; when an identifier must be dynamic, validate it against an allowlist rather than interpolating input.
- Sensitive data exposure: encrypt data at rest and in transit, and avoid returning more columns than needed; broad exposure relates to [CWE-200](https://cwe.mitre.org/data/definitions/200.html).
- Error handling: do not return raw database error text to end users, since it reveals schema details, which relates to [CWE-209](https://cwe.mitre.org/data/definitions/209.html).

Tooling: [sqlfluff](https://sqlfluff.com/) lints SQL style and some risk patterns, and application static analyzers (such as language-specific SAST tools) flag query strings built by concatenation.

## Learning resources

- ISO/IEC 9075, the SQL standard (the engine manuals below are the practical references).
- [PostgreSQL documentation](https://www.postgresql.org/docs/), a thorough and widely cited SQL reference.
- [SQLite SQL syntax](https://www.sqlite.org/lang.html), a concise reference for a small, embeddable engine.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [PL/SQL](/languages/plsql.md)
- [T-SQL](/languages/tsql.md)
- [All languages](/languages/README.md)
