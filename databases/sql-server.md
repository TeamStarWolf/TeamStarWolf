# Microsoft SQL Server

Microsoft SQL Server is a relational database management system from Microsoft. It runs on Windows and Linux, and in containers. It serves transactional and analytical workloads with the T-SQL dialect. Editions range from the free Express and Developer tiers to Standard and Enterprise.

## What it is and where it is used

SQL Server stores data in relational tables with enforced schemas, constraints, and foreign keys. It is common in enterprise line-of-business systems, finance, healthcare, and Windows-centric stacks. It integrates with .NET, Active Directory, and the wider Microsoft data platform. Azure SQL Database and Azure SQL Managed Instance are the managed cloud variants.

The engine handles concurrency with locking and row versioning. It supports stored procedures, triggers, views, and functions. SQL Server Agent runs scheduled jobs for maintenance and batch work.

## Data model and architecture

A SQL Server instance hosts multiple databases. Each database contains schemas, and each schema groups tables, views, and procedures. The default schema is `dbo`. Object names resolve as `database.schema.object`, for example `Sales.dbo.Orders`.

Each database stores data in one or more data files (`.mdf`, `.ndf`) and a transaction log file (`.ldf`). The log records every change and underpins recovery, point-in-time restore, and replication. The recovery model (`FULL`, `BULK_LOGGED`, or `SIMPLE`) controls how the log is retained.

System databases include `master`, `model`, `msdb`, and `tempdb`. `master` records instance-wide configuration and logins. `tempdb` holds temporary objects and is recreated on each restart.

## Query language and interface

SQL Server uses Transact-SQL (T-SQL), an extension of standard SQL. T-SQL adds procedural control flow, variables, error handling with `TRY...CATCH`, and functions such as `TOP` and window functions.

Client interfaces include the `sqlcmd` command-line tool, SQL Server Management Studio (SSMS), and Azure Data Studio. Applications connect through ODBC, JDBC, OLE DB, or the native .NET `Microsoft.Data.SqlClient` driver. The default TCP port is `1433`.

```sql
SELECT TOP (10) name, database_id, create_date
FROM sys.databases
ORDER BY create_date DESC;
```

## Administration and operations

Connect with `sqlcmd` using either Windows or SQL authentication.

```bash
# SQL authentication
sqlcmd -S localhost -U sa -P '<StrongPassword>' -d master

# Windows integrated authentication
sqlcmd -S localhost -E -d master
```

SQL Server separates server-level logins from database-level users. A login authenticates to the instance. A user maps a login into a specific database and receives permissions there.

```sql
-- Server-level login
CREATE LOGIN app_login WITH PASSWORD = '<StrongPassword>';

-- Database-level user mapped to that login
USE SalesDB;
CREATE USER app_user FOR LOGIN app_login;
```

Permissions flow through roles. Server roles include `sysadmin` and `securityadmin`. Fixed database roles include `db_datareader`, `db_datawriter`, and `db_owner`. Grant the least role that fits the task.

```sql
-- Grant read-only access, not db_owner
ALTER ROLE db_datareader ADD MEMBER app_user;
GRANT SELECT ON SCHEMA::Sales TO app_user;
```

Back up and restore databases with native commands.

```sql
BACKUP DATABASE SalesDB
TO DISK = 'C:\backups\SalesDB_full.bak'
WITH INIT, CHECKSUM;

RESTORE DATABASE SalesDB
FROM DISK = 'C:\backups\SalesDB_full.bak'
WITH RECOVERY;
```

SQL Server Agent schedules recurring work such as backups, index rebuilds, and integrity checks. Define a job, add steps, and attach a schedule. Keep Agent job owners on low-privilege accounts.

Configure instance settings with `sp_configure`. Many options are hidden behind `show advanced options`.

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
```

## A worked example

Create a database, add a table, insert a row, and read it back.

```sql
CREATE DATABASE InventoryDB;
GO
USE InventoryDB;
GO

CREATE TABLE dbo.Products (
    ProductId   INT IDENTITY(1,1) PRIMARY KEY,
    Name        NVARCHAR(100) NOT NULL,
    UnitPrice   DECIMAL(10,2) NOT NULL,
    CreatedAt   DATETIME2 DEFAULT SYSUTCDATETIME()
);
GO

INSERT INTO dbo.Products (Name, UnitPrice)
VALUES (N'Widget', 9.99);
GO

SELECT ProductId, Name, UnitPrice, CreatedAt
FROM dbo.Products
WHERE UnitPrice < 20.00;
GO
```

## Security and hardening

Choose Windows authentication where possible. Mixed Mode enables both Windows and SQL logins. SQL logins with weak passwords are a frequent entry point, so missing or weak authentication maps to CWE-306. Disable or rename the `sa` account and set a strong password.

Apply least privilege. Map each application to a dedicated login and user with only the grants it needs. Avoid `db_owner` and `sysadmin` for application accounts. Use schemas to scope permissions.

Build queries with parameters, never with string concatenation. Concatenating user input into dynamic T-SQL creates SQL injection, which is CWE-89. Prefer `sp_executesql` with typed parameters over `EXEC(@sql)`.

```sql
-- Safe parameterized dynamic SQL
EXEC sp_executesql
    N'SELECT * FROM dbo.Products WHERE Name = @name',
    N'@name NVARCHAR(100)',
    @name = @userInput;
```

Keep `xp_cmdshell` disabled. It runs operating-system commands from inside the database and turns SQL injection into OS command injection, which is CWE-78. Leave it off unless a hardened, audited need exists.

```sql
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

Encrypt data at rest with Transparent Data Encryption (TDE). TDE encrypts the data and log files and protects against stolen file or backup theft. Protect sensitive columns in the application and database with Always Encrypted, which keeps plaintext keys away from the engine. Storing sensitive data without encryption maps to CWE-312. Require TLS for connections so credentials and data in transit are protected.

Enable SQL Server Audit to record logins, permission changes, and sensitive data access. Write audit targets to a secured location. Do not expose port `1433` to the public internet, and restrict access with host firewalls and network segmentation. For input validation, output encoding, and credential handling across layers, see /SECURE_CODING_REFERENCE.md.

## Performance and scaling

Index design drives read performance. Each table has one clustered index that orders the data, plus nonclustered indexes for lookups. Review execution plans to find scans, missing indexes, and poor estimates. Keep statistics current so the optimizer estimates row counts well.

Partition large tables to manage big datasets and speed maintenance. Use columnstore indexes for analytical scans over large fact tables. Set `tempdb` on fast storage with multiple data files to reduce contention.

Scale reads with Availability Groups and readable secondaries. Scale write-heavy systems by tuning indexes, batching work, and sizing memory so the buffer pool keeps the working set resident.

## Resources

- Microsoft SQL Server documentation on Microsoft Learn (the official product documentation).
- SQL Server Books Online reference for T-SQL syntax and system views.

## Related pages

- /languages/tsql.md
- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/postgresql.md
- /databases/mysql.md
- /databases/oracle.md
