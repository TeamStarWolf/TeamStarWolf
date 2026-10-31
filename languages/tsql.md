# T-SQL

T-SQL (Transact-SQL) is the statically typed, procedural extension to SQL used by Microsoft SQL Server and Azure SQL, originally developed by Sybase and adopted by Microsoft in the late 1980s. It adds variables, control flow, stored procedures, functions, triggers, and error handling to standard SQL, and it runs inside the database engine. It is used for stored procedures, triggers, reporting queries, and server-side logic in SQL Server and Azure SQL deployments.

| Attribute | Value |
|---|---|
| Paradigm | Declarative SQL with imperative, procedural extensions |
| Typing | Static, strong, with SQL Server data types |
| First appeared | Late 1980s (Sybase SQL Server) |
| Memory model | Managed by the database engine |
| Reference implementation | [Microsoft SQL Server](https://www.microsoft.com/sql-server) and [Azure SQL](https://azure.microsoft.com/products/azure-sql/) (proprietary) |
| Typical uses | Stored procedures, triggers, reporting, server-side logic |
| Governance | [Microsoft](https://www.microsoft.com/), proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [SQL](/languages/sql.md), [languages index](/languages/README.md).

## Overview and history

Transact-SQL originated at Sybase for its SQL Server product, which Microsoft licensed and developed into Microsoft SQL Server; the two product lines later diverged but share the T-SQL heritage. Microsoft has extended the dialect over many releases with features such as common table expressions and window functions, the `TRY ... CATCH` error model, the `MERGE` statement, sequences, and `OFFSET`/`FETCH` paging. The same language runs in on-premises SQL Server and in the cloud-hosted Azure SQL Database and Azure SQL Managed Instance.

T-SQL is proprietary to Microsoft and runs in SQL Server and Azure SQL. It implements a core of the ISO SQL standard plus Microsoft-specific syntax, so queries that use T-SQL-only features (such as `TOP`, `OUTPUT`, or the `+` string concatenation operator) do not port directly to other engines.

## Paradigm and type system

T-SQL combines declarative SQL queries with imperative control flow. It is statically typed over SQL Server's type set: exact numerics (`INT`, `BIGINT`, `DECIMAL`, `MONEY`), approximate numerics (`FLOAT`, `REAL`), character and Unicode strings (`VARCHAR`, `NVARCHAR`), binary types, date and time types (`DATE`, `DATETIME2`, `DATETIMEOFFSET`), and others including `UNIQUEIDENTIFIER` and `XML`. Variables are declared with `DECLARE` and an `@` prefix. As in all SQL, `NULL` uses three-valued logic.

```sql
CREATE FUNCTION dbo.total(@tax DECIMAL(5,2), @sum DECIMAL(10,2))
RETURNS DECIMAL(12,2)
AS
BEGIN
    RETURN @sum * (1 + @tax);
END;
```

Batches are separated by the client-side `GO` directive, and statements within a procedure share a scope and transaction context.

## Toolchain and ecosystem

- Database: [SQL Server](https://www.microsoft.com/sql-server) (including the free Developer and Express editions) and [Azure SQL](https://azure.microsoft.com/products/azure-sql/).
- Tools: [SQL Server Management Studio](https://learn.microsoft.com/sql/ssms/) and [Azure Data Studio](https://learn.microsoft.com/azure-data-studio/) edit and run T-SQL; the `sqlcmd` command-line client runs scripts.
- Project model: [SQL Server Data Tools](https://learn.microsoft.com/sql/ssdt/) builds database projects and `.dacpac` packages for deployment.
- Analysis: T-SQL code analysis rules in the project tools and third-party linters flag style and risk patterns.

```bash
sqlcmd -S localhost -Q "SELECT 2 + 3;"
```

## Syntax tour

```sql
-- Variables and control flow
DECLARE @name NVARCHAR(50) = N'world';
DECLARE @total DECIMAL(12, 2) = 0;
PRINT CONCAT(N'hello, ', @name);

-- A cursor-free set-based update
UPDATE products SET price = price * 1.1 WHERE category = 'tools';

-- Aggregate into a variable
SELECT @total = SUM(price) FROM products;

IF @total > 100
    PRINT 'large';
ELSE
    PRINT 'small';

-- Common table expression and window function
WITH ranked AS (
    SELECT name, category,
           RANK() OVER (PARTITION BY category ORDER BY price DESC) AS rnk
    FROM products
)
SELECT * FROM ranked WHERE rnk = 1;

-- TOP and OFFSET/FETCH are T-SQL paging
SELECT TOP (10) name FROM products ORDER BY price DESC;

-- Structured error handling
BEGIN TRY
    INSERT INTO products (id, name) VALUES (1, N'widget');
END TRY
BEGIN CATCH
    PRINT ERROR_MESSAGE();
END CATCH;
```

## Idioms and different approaches

- Prefer set-based statements over cursors: a single `UPDATE` or `MERGE` usually outperforms a row-by-row cursor loop and is clearer.
- Use `TRY ... CATCH` with `THROW` (or `RAISERROR`) for error handling, and wrap multi-statement changes in explicit transactions with `SET XACT_ABORT ON`.
- Parameterize queries and stored procedures; parameterized calls also let the engine reuse cached execution plans.
- Use `NVARCHAR` and the `N'...'` literal prefix for Unicode text so non-ASCII data is not silently lost.
- Schema-qualify object names (`dbo.table`) so name resolution is unambiguous and plans are reused.

## Design principles

T-SQL extends SQL so that server-side logic runs in the engine, next to the data, with the set-based query model at its core and procedural constructs layered around it. Microsoft's additions target practical application needs: structured error handling, paging, upserts, and output of affected rows. The same language spanning on-premises SQL Server and Azure SQL lets logic move to the cloud without rewriting, at the cost of portability to non-Microsoft engines.

## Standard library and notable packages

T-SQL's built-in functions are its standard library: aggregates and window functions, string functions (`CONCAT`, `STRING_AGG`, `REPLACE`), date and time functions (`DATEADD`, `DATEDIFF`, `SYSDATETIME`), conversion (`CAST`, `CONVERT`, `TRY_CONVERT`), JSON functions (`OPENJSON`, `FOR JSON`), and system stored procedures such as `sp_executesql` for parameterized dynamic SQL. SQL Server itself adds engine features (Query Store, In-Memory OLTP, columnstore indexes) that T-SQL controls through its syntax rather than through third-party packages.

## Testing and packaging

[tSQLt](https://tsqlt.org/) is the common unit-testing framework for T-SQL, running tests inside the database.

```sql
-- tSQLt assertion inside a test procedure
EXEC tSQLt.AssertEquals @Expected = 66, @Actual = dbo.total(0.1, 60);
```

Database objects are packaged with SQL Server Data Tools into a `.dacpac` that can be compared against and deployed to a target database, or versioned as ordered migration scripts.

## Performance and concurrency

Query performance depends on the execution plan, inspected with `SET SHOWPLAN` or the graphical plan in Management Studio. Indexes, current statistics, and set-based logic are the main levers, and parameterized queries let the plan cache reuse plans rather than recompiling per value (while watching for parameter-sniffing skew). Concurrency is managed through transactions and isolation levels; snapshot and read-committed-snapshot isolation use row versioning to reduce blocking. Keep transactions short to limit lock contention, and set `XACT_ABORT ON` so errors roll back cleanly.

## Common pitfalls

- Row-by-row cursors where a set-based statement would do are a frequent performance problem; rewrite as a single query where possible.
- `NVARCHAR` versus `VARCHAR`: forgetting the `N` prefix on Unicode literals or mixing the types causes implicit conversions that lose data or defeat indexes.
- Three-valued logic: `NOT IN (subquery)` returns no rows when the subquery yields a `NULL`; use `NOT EXISTS` instead.
- Error handling without `SET XACT_ABORT ON` can leave a transaction partly applied after some errors; set it and use explicit transactions.
- Implicit conversions in join and filter predicates can silently prevent index use; match types explicitly.

## Secure coding

T-SQL runs inside the database engine, so injection and privilege handling are the central concerns:

- SQL injection: concatenating untrusted input into a query, especially into dynamic SQL run with `EXEC(@sql)`, lets an attacker change the query's meaning. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html). Use `sp_executesql` with typed parameters rather than building a string, and when an identifier must be dynamic, validate it or wrap it with `QUOTENAME`. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

```sql
-- Unsafe: input concatenated and executed
-- EXEC('SELECT * FROM users WHERE name = ''' + @name + '''');

-- Safe: parameterized dynamic SQL
EXEC sp_executesql
    N'SELECT id FROM users WHERE name = @name',
    N'@name NVARCHAR(50)',
    @name = @name;
```

- Least privilege: run application connections under accounts with only the needed rights, and grant `EXECUTE` on specific procedures rather than broad table access; over-broad rights relate to [CWE-269](https://cwe.mitre.org/data/definitions/269.html).
- Ownership chaining and `EXECUTE AS`: understand which identity a procedure runs under so it does not lend elevated privileges to its callers.
- Dangerous surface: `xp_cmdshell` runs operating-system commands and should stay disabled unless strictly required; enabling it and passing it untrusted input maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Error handling: do not return raw `ERROR_MESSAGE()` text to end users, since it reveals schema and query structure, which relates to [CWE-209](https://cwe.mitre.org/data/definitions/209.html). Protect data with Transparent Data Encryption and Always Encrypted as appropriate, and review dependencies in the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the SQL code analysis rules in SQL Server Data Tools and third-party analyzers flag dynamic SQL built from concatenation and other risk patterns during static analysis.

## Learning resources

- [Transact-SQL reference](https://learn.microsoft.com/sql/t-sql/language-reference), the official Microsoft documentation.
- [SQL Server tutorials](https://learn.microsoft.com/sql/sql-server/tutorials-for-sql-server), Microsoft's getting-started material.
- [Azure SQL documentation](https://learn.microsoft.com/azure/azure-sql/), for the cloud-hosted engines.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [SQL](/languages/sql.md)
- [PL/SQL](/languages/plsql.md)
- [All languages](/languages/README.md)
