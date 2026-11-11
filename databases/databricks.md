# Databricks and Spark SQL

Databricks is a lakehouse platform built on Apache Spark and Delta Lake. It combines the open storage of a data lake with table semantics closer to a warehouse: ACID transactions, schema enforcement, and time travel over files in cloud object storage. Work happens in notebooks and SQL against clusters, and Unity Catalog governs access across workspaces. The query interface is Spark SQL plus the DataFrame APIs.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Database administrators, developers and security engineers who run, query or assess Databricks and Spark SQL

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,130 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are modeling data or writing queries for Databricks and Spark SQL, you are administering or hardening a deployment, or you want a worked example to start from

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Data model and architecture](#data-model-and-architecture), [Security and hardening](#security-and-hardening), [A worked example](#a-worked-example)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[SQL](/languages/sql.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Snowflake](/databases/snowflake.md), [ClickHouse](/databases/clickhouse.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Security relevance

This section is the threat-facing view of Databricks: how a managed lakehouse looks to an attacker or auditor, and which weakness classes dominate its record. The controls that defend against them are in the "Security and hardening" section that follows.

### Where it appears

- A managed cloud service on AWS, Azure, and Google Cloud, so the attack surface is the control plane (the workspace and account console, notebooks, and jobs) and the cloud object storage that holds the Delta files behind the tables.
- Recognized by workspace hostnames such as `*.cloud.databricks.com` and `*.azuredatabricks.net`, and by personal access tokens that begin with `dapi`. Spark SQL and the DataFrame APIs are the query interfaces.
- Targeted less by network exploits than by credential discovery: leaked `dapi` tokens in source control, notebooks, or CI, and over-broad cloud roles that reach the storage bucket directly and bypass table access control. General cloud-exploitation tooling such as Pacu applies to the underlying accounts.
- Audited through Unity Catalog lineage and grants, the platform audit logs, and the cloud provider's IAM analyzers. The supply-chain surface is notebook library installs from PyPI and Maven and cluster init scripts.

### Dominant weakness classes

Databricks is a managed cloud platform, so the practical risks are identity and access-management misconfiguration and credential exposure rather than memory corruption in the engine.

- Use of hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)) when access tokens or service keys are embedded in notebooks, job definitions, or repositories instead of read from secret scopes.
- Missing authorization ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)) from over-broad Unity Catalog grants, or from a cloud role that reaches the storage bucket beneath the table and bypasses the catalog entirely.
- Information exposure through logs ([CWE-532](https://cwe.mitre.org/data/definitions/532.html)) when secrets or sensitive rows land in notebook output or job logs.
- SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) when Spark SQL is assembled from untrusted input inside a job or notebook.

### Why it matters

Recognizing a workspace URL and a `dapi` token tells a practitioner the pivot to test: a leaked token grants workspace access, and a mis-scoped cloud role can reach the data files directly. Each maps to a control the defender owns: keep secrets in scopes, scope Unity Catalog and cloud roles to least privilege, isolate the data plane on private networking, and enable audit logs. See [the cloud security reference](/CLOUD_SECURITY_REFERENCE.md) alongside [the database security reference](/DATABASE_SECURITY_REFERENCE.md).

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

- [SQL](/languages/sql.md)
- [Databases](/databases/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Snowflake](/databases/snowflake.md)
- [ClickHouse](/databases/clickhouse.md)
- [Apache Cassandra](/databases/cassandra.md)
