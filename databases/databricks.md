# Databricks and Spark SQL

Databricks is a lakehouse platform built on Apache Spark and Delta Lake. It combines the open storage of a data lake with table semantics closer to a warehouse: ACID transactions, schema enforcement, and time travel over files in cloud object storage. Work happens in notebooks and SQL against clusters, and Unity Catalog governs access across workspaces. The query interface is Spark SQL plus the DataFrame APIs.

## What it is and where it is used

The lakehouse model stores data once, in open file formats on cloud storage, and serves both analytics and machine learning from it. Teams avoid copying data between a lake and a separate warehouse.

Databricks runs as a managed service on AWS, Azure, and Google Cloud. Data engineers build pipelines, analysts run SQL, and data scientists train models, all against the same tables. Jobs schedule production workloads; notebooks support interactive work.

Delta Lake is the storage layer that makes files behave like tables. Unity Catalog is the governance layer that controls who can read and write them.

## Data model and architecture

A Delta Lake table is a directory of Parquet data files plus a transaction log (`_delta_log`). The log records every commit, which gives atomic writes, concurrent reads, and the ability to read an earlier version.

```sql
CREATE TABLE sales.orders (
    order_id   BIGINT,
    customer   STRING,
    amount     DECIMAL(12,2),
    ordered_at TIMESTAMP
) USING DELTA;
```

Unity Catalog organizes objects in three levels: catalog, schema, and table. A name is fully qualified as `catalog.schema.table`.

```sql
CREATE CATALOG prod;
CREATE SCHEMA prod.sales;
```

Compute is a cluster of Spark workers. Jobs run on job clusters that start and stop with the workload; interactive analysis runs on all-purpose clusters or SQL warehouses. Storage and compute are decoupled, so clusters are disposable.

Time travel reads a prior table version.

```sql
SELECT * FROM prod.sales.orders VERSION AS OF 12;
SELECT * FROM prod.sales.orders TIMESTAMP AS OF '2026-10-30';
```

## Query language and interface

Spark SQL is ANSI-style SQL over Delta tables. The DataFrame API offers the same operations in Python, Scala, and R, and the two interoperate in one notebook.

```sql
SELECT customer, SUM(amount) AS total
FROM prod.sales.orders
WHERE ordered_at >= current_date() - INTERVAL 30 DAYS
GROUP BY customer
ORDER BY total DESC;
```

```python
df = spark.table("prod.sales.orders")
(df.filter("amount > 100")
   .groupBy("customer")
   .sum("amount")
   .show())
```

Notebooks mix SQL, Python, and Markdown cells. SQL warehouses serve business intelligence tools over JDBC and ODBC.

## Administration and operations

A workspace is the unit of collaboration; accounts hold workspaces and share a Unity Catalog metastore. Clusters, jobs, catalogs, and secrets are managed from the workspace or the account console.

Unity Catalog privileges are granted with SQL.

```sql
GRANT USAGE ON CATALOG prod TO `data-analysts`;
GRANT USAGE ON SCHEMA prod.sales TO `data-analysts`;
GRANT SELECT ON TABLE prod.sales.orders TO `data-analysts`;
```

Secret scopes hold credentials so notebooks and jobs read them at runtime instead of embedding them. The CLI manages scopes and secrets.

```bash
databricks secrets create-scope sales-etl
databricks secrets put-secret sales-etl jdbc_password
```

```python
pwd = dbutils.secrets.get(scope="sales-etl", key="jdbc_password")
```

Jobs define a task graph, a schedule, and a cluster spec. Cluster policies constrain the instance types and sizes users may launch.

## A worked example

Merge a batch of changed orders into a Delta table so new rows insert and existing rows update in one atomic commit.

```sql
MERGE INTO prod.sales.orders AS t
USING staging.orders_changes AS s
ON t.order_id = s.order_id
WHEN MATCHED THEN UPDATE SET
    t.amount = s.amount,
    t.ordered_at = s.ordered_at
WHEN NOT MATCHED THEN INSERT
    (order_id, customer, amount, ordered_at)
    VALUES (s.order_id, s.customer, s.amount, s.ordered_at);
```

The whole `MERGE` is one transaction in the Delta log. Readers see either the old state or the new state, never a partial write.

## Security and hardening

Unity Catalog is the authorization boundary. Privileges attach to catalogs, schemas, and tables and inherit down the hierarchy. Grant each group the narrowest set of objects it needs, and review inherited grants: a `USAGE` or `SELECT` at the catalog level reaches every schema below it (CWE-862, missing authorization from over-broad grants). Unity Catalog also records column and table lineage, which helps audit how data moved.

Never hardcode credentials in notebooks or job definitions. Read them from secret scopes at runtime (CWE-798, use of hardcoded credentials). Keep secrets out of notebook output and source control (CWE-522, insufficiently protected credentials).

```python
# wrong: hardcoded credential
# token = "dapiXXXXXXXXXXXXXXXX"
# right: fetch from a secret scope
token = dbutils.secrets.get(scope="sales-etl", key="api_token")
```

Isolate workspaces and clusters on private networking so data planes are not exposed to the public internet; use customer-managed VPCs or VNets and private endpoints where available. Databricks encrypts data at rest and in transit, and supports customer-managed keys (CWE-312, cleartext storage of sensitive information). Enable audit logs so reads, grants, and job runs are recorded for review. See /SECURE_CODING_REFERENCE.md for the credential-handling and authorization patterns referenced here.

## Performance and scaling

Clusters autoscale within bounds, adding workers under load and releasing them when idle. Size job clusters to the pipeline and prefer job clusters over long-lived interactive ones for production.

Delta Lake performance comes from file layout. `OPTIMIZE` compacts small files; `ZORDER` colocates related data so selective filters read fewer files; `VACUUM` removes files no longer referenced.

```sql
OPTIMIZE prod.sales.orders ZORDER BY (customer);
VACUUM prod.sales.orders RETAIN 168 HOURS;
```

Partition large tables on a low-cardinality column that matches common filters. Photon, the vectorized query engine, speeds up SQL and DataFrame workloads. Caching keeps hot data on cluster-local storage for repeated reads.

## Resources

- Databricks Documentation (docs.databricks.com), the official platform, Delta Lake, and Unity Catalog reference.
- Apache Spark documentation (spark.apache.org), the reference for Spark SQL and the DataFrame APIs.

## Related pages

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/snowflake.md
- /databases/clickhouse.md
- /databases/cassandra.md
