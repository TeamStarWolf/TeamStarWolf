# ClickHouse

ClickHouse is a columnar database built for online analytical processing (OLAP). It stores data by column and reads only the columns a query needs, which makes aggregations over billions of rows fast. It uses a SQL dialect and scales from a single node to large distributed clusters. It fits analytics, observability, and reporting rather than high-rate single-row updates.

## What it is and where it is used

ClickHouse answers analytical queries over large datasets: counts, sums, and group-by aggregations across wide tables. It powers dashboards, log and metrics stores, clickstream analysis, and time-series workloads. Reads scan many rows and few columns, which the column layout serves well.

It is not a transactional store. There are no classic row-level `UPDATE` and `DELETE` with the semantics of an OLTP engine, and inserts favor large batches over single rows. Treat it as an append-and-aggregate system.

## Data model and architecture

ClickHouse stores each column in its own files, compressed independently. Column compression plus reading only referenced columns cuts disk reads sharply. Data is organized into parts that background merges combine over time.

The table engine defines storage and behavior. The MergeTree family is the main engine group. A MergeTree table has an `ORDER BY` key that sorts data within each part and acts as a sparse primary index. `PARTITION BY` splits data into partitions, often by month, for pruning and maintenance.

```sql
CREATE TABLE events (
    event_time DateTime,
    user_id    UInt64,
    event_type LowCardinality(String),
    value      Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_type, event_time);
```

Variants add behavior. `ReplacingMergeTree` collapses duplicate keys on merge. `SummingMergeTree` and `AggregatingMergeTree` pre-aggregate. `ReplicatedMergeTree` replicates parts across nodes using Keeper or ZooKeeper for coordination.

Materialized views compute results at insert time. A materialized view reads new rows as they land and writes aggregates into a target table, so dashboards read a small summary instead of scanning raw data.

```sql
CREATE MATERIALIZED VIEW events_daily
ENGINE = SummingMergeTree
ORDER BY (event_type, day)
AS SELECT
    event_type,
    toDate(event_time) AS day,
    sum(value) AS total
FROM events
GROUP BY event_type, day;
```

## Query language and interface

ClickHouse uses an SQL dialect with analytical extensions. It adds many aggregate and array functions, combinators such as `-If` and `-Merge`, and data types such as `LowCardinality`, `Nullable`, and nested structures. Joins, subqueries, and window functions are supported.

The `clickhouse-client` command-line tool connects over the native TCP protocol on port `9000`. The HTTP interface listens on port `8123` and accepts queries over HTTP. Many language drivers wrap one of these.

```bash
clickhouse-client --host localhost --port 9000 --user analyst --password
```

```sql
SELECT event_type, count() AS n, avg(value) AS mean
FROM events
WHERE event_time >= now() - INTERVAL 1 DAY
GROUP BY event_type
ORDER BY n DESC;
```

## Administration and operations

Manage users and roles either in XML configuration files or with SQL. The file path is typically `users.xml`, or drop-in files under `users.d`. SQL-driven access control is the modern approach and stores definitions in the server.

```sql
CREATE USER analyst IDENTIFIED WITH sha256_password BY '<StrongPassword>';

CREATE ROLE readonly;
GRANT SELECT ON analytics.* TO readonly;
GRANT readonly TO analyst;
```

Quotas and settings profiles cap resource use per user. A quota limits queries, rows read, and execution time over an interval. A settings profile fixes limits such as `max_memory_usage`.

```sql
CREATE QUOTA q_analyst
FOR INTERVAL 1 HOUR MAX queries = 1000, read_rows = 1000000000
TO analyst;
```

Back up data with the built-in `BACKUP` and `RESTORE` commands, which write to a disk or object-store destination. The `clickhouse-backup` tool and filesystem snapshots of the parts directory are alternatives for part-level backups.

```sql
BACKUP TABLE analytics.events TO Disk('backups', 'events.zip');
RESTORE TABLE analytics.events FROM Disk('backups', 'events.zip');
```

Inspect running work and storage with system tables. `system.query_log` records queries, `system.parts` shows storage parts, and `system.processes` lists active queries.

```sql
SELECT query, read_rows, memory_usage
FROM system.query_log
WHERE type = 'QueryFinish'
ORDER BY event_time DESC
LIMIT 10;
```

## A worked example

Connect, create a table, insert a batch, and aggregate.

```bash
clickhouse-client --host localhost --port 9000 --user analyst --password
```

```sql
CREATE TABLE sales (
    sale_time DateTime,
    product   LowCardinality(String),
    amount    Decimal(10, 2)
)
ENGINE = MergeTree
ORDER BY (product, sale_time);

INSERT INTO sales VALUES
    ('2026-10-31 09:00:00', 'Widget', 9.99),
    ('2026-10-31 09:05:00', 'Gadget', 24.50),
    ('2026-10-31 09:10:00', 'Widget', 9.99);

SELECT product, count() AS orders, sum(amount) AS revenue
FROM sales
GROUP BY product
ORDER BY revenue DESC;
```

## Security and hardening

Use role-based access control. Create one role per access level, grant table and column privileges to roles, and assign roles to users. Give each user only the grants the work needs, since broad grants widen the blast radius of a stolen credential.

Set strong password hashing. Define users with `IDENTIFIED WITH sha256_password` rather than plaintext, and avoid the `default` user with no password. A server that answers on an open port with no required credential maps to CWE-306.

Network exposure is the main risk. The native port `9000` and the HTTP port `8123` must not face the public internet. Bind to internal interfaces, put the server behind a firewall, and enable TLS so both the HTTP (`8443`) and native (`9440`) secure ports carry encrypted traffic. Configure `<listen_host>` so the server does not listen on `0.0.0.0` by accident.

```xml
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
    <tcp_port_secure>9440</tcp_port_secure>
    <https_port>8443</https_port>
</clickhouse>
```

Injection applies to any query built from untrusted input. Concatenating user input into ClickHouse SQL is CWE-89. Use parameterized queries with the driver's bound parameters or server-side query parameters.

```sql
-- Server-side parameter, substituted safely by the server
SELECT * FROM sales WHERE product = {p:String};
```

Encrypt data at rest with disk encryption or an encrypting storage layer, since parts on disk are otherwise readable to anyone with file access. Enable query and access logging through `system.query_log` and the session log, and ship those logs to a secured store for audit. For parameterization, credential handling, and transport security across services, see /SECURE_CODING_REFERENCE.md.

## Performance and scaling

Choose the `ORDER BY` key to match the columns queries filter and sort on. The key drives the sparse primary index and the physical order, so a good key lets ClickHouse skip most parts. Partition by a coarse time unit so old data prunes and drops cleanly.

Keep inserts in large batches. Many tiny inserts create many small parts and heavy merge pressure, so buffer rows and insert thousands at a time. Use `LowCardinality` for repetitive string columns to shrink storage and speed group-by.

Scale out with sharding and replication. A `Distributed` table spreads queries across shards, and `ReplicatedMergeTree` keeps copies on multiple nodes for availability. Materialized views move aggregation to insert time so read queries stay cheap. Watch `max_memory_usage` and spill settings so large aggregations do not exhaust memory.

## Resources

- The ClickHouse documentation (the official reference at the project site, covering engines, SQL functions, and operations).

## Related pages

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/postgresql.md
- /databases/snowflake.md
- /databases/databricks.md
