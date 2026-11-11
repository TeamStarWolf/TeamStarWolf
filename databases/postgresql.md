# PostgreSQL

PostgreSQL is an open-source relational database management system that follows the SQL standard closely and adds an extensible type system. It stores data in tables organized by schemas and databases, and it uses Multiversion Concurrency Control (MVCC) so readers and writers rarely block each other. It is used for transactional applications, analytics, geospatial workloads through PostGIS, and as a general backend store. The project has a long release history and strong ACID guarantees.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Database administrators, developers and security engineers who run, query or assess PostgreSQL

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,109 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are modeling data or writing queries for PostgreSQL, you are administering or hardening a deployment, or you want a worked example to start from

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Data model and architecture](#data-model-and-architecture), [Security and hardening](#security-and-hardening), [A worked example](#a-worked-example)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[SQL](/languages/sql.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [MySQL and MariaDB](/databases/mysql.md), [Oracle Database](/databases/oracle.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

PostgreSQL began at UC Berkeley and is now maintained by a global development group. It runs on Linux, BSD, macOS, and Windows, and backs web applications, financial systems, and data warehouses. Managed versions exist on most cloud providers, including Amazon RDS and Aurora, Azure Database, and Google Cloud SQL. Developers choose it for JSON support, strong constraints, and its extension model.

## Data model and architecture

The core model is relational: data lives in tables made of typed columns and rows, grouped into schemas inside databases. Each row version carries transaction identifiers so MVCC can show a consistent snapshot without read locks. The background `autovacuum` process reclaims space from dead row versions and updates planner statistics.

Physical storage is organized into tablespaces, which map logical objects to directories on disk. A cluster holds one or more databases and shares a single set of background processes and a write-ahead log (WAL). The WAL records every change before it reaches the data files, which supports crash recovery and replication.

Extensions add types, functions, and index methods without patching the server. Common ones include `postgis` for geospatial data, `pg_stat_statements` for query telemetry, and `pgcrypto` for cryptographic functions. Install one with a single statement:

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

## Query language and interface

PostgreSQL speaks SQL with its own dialect additions, including rich JSON and `jsonb` operators, window functions, common table expressions, and `RETURNING` clauses on writes. Server-side functions can be written in PL/pgSQL, PL/Python, and other procedural languages. The primary terminal client is `psql`, and most languages connect through the libpq-based driver or a native implementation.

```sql
SELECT id, name FROM customers WHERE created_at > now() - interval '7 days';
```

## Administration and operations

Connect with `psql`, naming the database, user, and host:

```bash
psql -h db.internal -U app_owner -d sales
```

Create roles and grant least privilege rather than using the superuser for applications:

```sql
CREATE ROLE app_rw LOGIN PASSWORD 'set-in-secret-manager';
GRANT CONNECT ON DATABASE sales TO app_rw;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_rw;
```

Client authentication is driven by `pg_hba.conf`, which maps connection type, database, user, and source address to a method. Prefer `scram-sha-256` over `trust` or `password`:

```
# TYPE  DATABASE  USER    ADDRESS         METHOD
hostssl sales     app_rw  10.0.0.0/24     scram-sha-256
```

Back up a single database with `pg_dump` and restore with `pg_restore` from the custom format:

```bash
pg_dump -Fc -h db.internal -U app_owner sales > sales.dump
pg_restore -h db.internal -U app_owner -d sales_restore sales.dump
```

Server settings live in `postgresql.conf`. Reload most of them without downtime:

```sql
ALTER SYSTEM SET log_min_duration_statement = '500ms';
SELECT pg_reload_conf();
```

## A worked example

Connect, create a small table, insert a row, and read it back:

```sql
CREATE TABLE orders (
    id         bigserial PRIMARY KEY,
    customer   text NOT NULL,
    total_cents integer NOT NULL CHECK (total_cents >= 0),
    placed_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO orders (customer, total_cents)
VALUES ('acme-co', 4999)
RETURNING id, placed_at;

SELECT customer, total_cents
FROM orders
WHERE placed_at > now() - interval '1 day'
ORDER BY total_cents DESC;
```

## Security relevance

This section is the threat-facing view of PostgreSQL: how it is reached and abused, and which weakness classes matter. The configuration steps that defend against them are in the "Security and hardening" section that follows.

### Where it appears

- The data tier behind web applications, financial systems, and warehouses, which makes it a primary objective once an attacker finds SQL injection in the application or reaches the internal network.
- On the offensive side, `sqlmap` and similar tools fingerprint the engine and automate extraction. A SQL foothold with enough privilege can be escalated to file read and write through large objects and `COPY ... TO/FROM`, and to command execution through `COPY ... PROGRAM` or an untrusted procedural language such as PL/Python.
- Managed offerings (Amazon RDS and Aurora, Azure Database, Google Cloud SQL) remove host access but keep the full SQL surface, so application-level and privilege flaws still apply.
- Exposure cases: a cluster bound to `0.0.0.0` with a `trust` line in `pg_hba.conf`, or a connection string with credentials leaked into source control or logs.

### Dominant weakness classes

PostgreSQL itself is a mature C server that is hardened against memory corruption in normal use, so the practical risks are access control, injection that reaches the engine, and server features used with more privilege than they need.

- SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)), the application-layer flaw whose impact is realized inside the database.
- Missing or weak authentication ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)) from `trust` methods or an over-broad `listen_addresses`.
- Improper privilege management ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)): a login role that holds superuser or `pg_execute_server_program` can turn a query into host command execution.
- Cleartext storage of secrets ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) in columns, since the server does not encrypt table data itself.

### Why it matters

Understanding how a foothold in PostgreSQL converts into file access or command execution tells a defender exactly what to constrain: keep applications off the superuser, limit or disable untrusted procedural languages and `COPY ... PROGRAM`, bind `listen_addresses` to known interfaces, and require `scram-sha-256` over `hostssl`. The `pgaudit` extension and statement logging give the detection trail. See [the database security reference](/DATABASE_SECURITY_REFERENCE.md) for the engine-agnostic hardening checklist.

## Security and hardening

Use `scram-sha-256` for password authentication, which stores a salted verifier rather than a recoverable password. Set the method in `pg_hba.conf` and the matching `password_encryption` in `postgresql.conf`. For service-to-service access, consider certificate authentication over `hostssl`.

Grant privileges to roles by least privilege, and give each application its own login role. Row-level security confines a role to the rows it may see, which supports multitenant isolation:

```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders
    USING (customer = current_setting('app.tenant'));
```

Require TLS for connections in transit by setting `ssl = on` and distributing the server certificate, then force it per client with `hostssl`. For data at rest, use filesystem or volume encryption, since the server does not encrypt table files itself; storing secrets or tokens unencrypted in columns risks cleartext exposure (CWE-312).

SQL injection (CWE-89) is the main application-level risk. Use parameterized statements through the driver, never string concatenation:

```python
cur.execute("SELECT * FROM orders WHERE customer = %s", (name,))
```

A misconfigured `pg_hba.conf`, a `trust` line, or a server listening on `0.0.0.0` with no firewall can expose the cluster with no real authentication (CWE-306). Bind `listen_addresses` to known interfaces, restrict source ranges, and avoid default or sample roles with weak passwords. Enable statement logging and the `pgaudit` extension for an audit trail. See /SECURE_CODING_REFERENCE.md for the injection and secrets-handling patterns.

## Performance and scaling

B-tree indexes serve equality and range lookups; GIN and GiST indexes serve `jsonb`, full-text, and geospatial queries. Use `EXPLAIN (ANALYZE, BUFFERS)` to read the planner's choices and confirm an index is used. Keep statistics fresh so the planner estimates row counts well.

Streaming replication ships WAL to one or more replicas for read scaling and failover. Logical replication copies selected tables and supports version upgrades and selective fan-out. Declarative partitioning splits a large table by range, list, or hash, which prunes scans and speeds bulk deletes. For write scaling beyond one node, sharding middleware such as Citus distributes tables across a cluster.

## Resources

- PostgreSQL documentation (the official manual from the PostgreSQL Global Development Group)
- *PostgreSQL: Up and Running* by Regina Obe and Leo Hsu

## Related pages

- [SQL](/languages/sql.md)
- [Databases](/databases/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [MySQL and MariaDB](/databases/mysql.md)
- [Oracle Database](/databases/oracle.md)
- [SQLite](/databases/sqlite.md)
- [ClickHouse](/databases/clickhouse.md)
