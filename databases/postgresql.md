# PostgreSQL

PostgreSQL is an open-source relational database management system that follows the SQL standard closely and adds an extensible type system. It stores data in tables organized by schemas and databases, and it uses Multiversion Concurrency Control (MVCC) so readers and writers rarely block each other. It is used for transactional applications, analytics, geospatial workloads through PostGIS, and as a general backend store. The project has a long release history and strong ACID guarantees.

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

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/mysql.md
- /databases/oracle.md
- /databases/sqlite.md
- /databases/clickhouse.md
