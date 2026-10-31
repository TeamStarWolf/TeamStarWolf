# Snowflake

Snowflake is a cloud data warehouse that separates storage from compute. Data sits in cloud object storage as compressed micro-partitions, and independent compute clusters called virtual warehouses run queries against it. You can resize or pause compute without moving data. The interface is SQL, reached through a web console, the `snowsql` client, and drivers.

## What it is and where it is used

Snowflake runs as a managed service on AWS, Azure, and Google Cloud. There is no infrastructure to patch; the account is provisioned and billed by usage.

Teams use it as a central analytics store: loading data from operational systems, transforming it with SQL, and serving it to business intelligence tools and data applications. Separated compute lets a loading job, a dashboard, and an ad hoc analyst each use their own warehouse without contending for the same cluster.

Data sharing lets one account grant live, read-only access to another account's objects without copying the data.

## Data model and architecture

Objects live in a hierarchy: an account holds databases, a database holds schemas, and a schema holds tables, views, and other objects.

```sql
CREATE DATABASE analytics;
CREATE SCHEMA analytics.sales;
CREATE TABLE analytics.sales.orders (
    order_id   NUMBER,
    customer   STRING,
    amount     NUMBER(12,2),
    ordered_at TIMESTAMP_NTZ
);
```

Table data is stored as micro-partitions: small, columnar, compressed files that Snowflake creates and manages automatically. Each micro-partition carries metadata (min, max, distinct counts) so the engine can prune partitions a query cannot match. There are no manual indexes.

Compute is a virtual warehouse: a cluster sized from X-Small upward. Storage and compute scale independently, and several warehouses can read the same data at once.

Time Travel keeps prior versions of data for a retention window, so you can query or restore a table as it was at an earlier point.

```sql
SELECT * FROM orders AT (OFFSET => -3600);   -- one hour ago
UNDROP TABLE orders;
```

## Query language and interface

Snowflake speaks ANSI SQL with extensions for semi-structured data (`VARIANT`, `FLATTEN`), streams, and tasks.

```sql
SELECT customer, SUM(amount) AS total
FROM analytics.sales.orders
WHERE ordered_at >= DATEADD(day, -30, CURRENT_TIMESTAMP())
GROUP BY customer
ORDER BY total DESC
LIMIT 10;
```

`snowsql` is the command-line client. It authenticates, selects a warehouse and schema, and runs scripts.

```bash
snowsql -a myorg-myaccount -u analyst -w REPORTING_WH -d ANALYTICS -s SALES
```

The web console, Python, JDBC, ODBC, and Go drivers all target the same SQL. Query history and result caching are visible in the console.

## Administration and operations

Administration is itself SQL. Roles, warehouses, and monitors are created and granted with statements.

```sql
CREATE WAREHOUSE reporting_wh
    WAREHOUSE_SIZE = 'SMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE;

CREATE ROLE analyst;
GRANT USAGE ON WAREHOUSE reporting_wh TO ROLE analyst;
GRANT USAGE ON DATABASE analytics TO ROLE analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics.sales TO ROLE analyst;
```

A resource monitor caps credit spend and can suspend warehouses that exceed a quota.

```sql
CREATE RESOURCE MONITOR monthly_cap
    WITH CREDIT_QUOTA = 500
    TRIGGERS ON 90 PERCENT DO NOTIFY
             ON 100 PERCENT DO SUSPEND;
ALTER WAREHOUSE reporting_wh SET RESOURCE_MONITOR = monthly_cap;
```

`AUTO_SUSPEND` stops idle compute so it stops billing; `AUTO_RESUME` restarts it on the next query.

## A worked example

Grant a reporting role least-privilege read access, then run a windowed query that an analyst using that role would run.

```sql
USE ROLE securityadmin;
CREATE ROLE sales_reader;
GRANT USAGE ON WAREHOUSE reporting_wh TO ROLE sales_reader;
GRANT USAGE ON DATABASE analytics TO ROLE sales_reader;
GRANT USAGE ON SCHEMA analytics.sales TO ROLE sales_reader;
GRANT SELECT ON TABLE analytics.sales.orders TO ROLE sales_reader;

USE ROLE sales_reader;
SELECT customer, amount,
       RANK() OVER (PARTITION BY customer ORDER BY amount DESC) AS rnk
FROM analytics.sales.orders
QUALIFY rnk = 1;
```

The reader role can select from one table and nothing more. `QUALIFY` filters on the window function result without a subquery.

## Security and hardening

Access is governed by role-based access control. Privileges attach to roles, roles form a hierarchy, and users activate roles. Grant each role only the objects it needs, and avoid handing broad roles such as `ACCOUNTADMIN` to analysts (CWE-862, missing authorization). Build narrow roles and compose them.

Network policies restrict which IP ranges can connect. Require multi-factor authentication for interactive users and use key-pair authentication for service accounts so no password travels with a job.

```sql
CREATE NETWORK POLICY corp_only ALLOWED_IP_LIST = ('203.0.113.0/24');
ALTER ACCOUNT SET NETWORK_POLICY = corp_only;
ALTER USER service_etl SET RSA_PUBLIC_KEY = 'MIIBIj...';
```

Dynamic data masking and row access policies limit what a role sees inside a table, so sensitive columns return masked values to roles that lack clearance.

```sql
CREATE MASKING POLICY mask_email AS (val STRING) RETURNS STRING ->
  CASE WHEN CURRENT_ROLE() IN ('PII_READER') THEN val ELSE '***MASKED***' END;
ALTER TABLE customers MODIFY COLUMN email SET MASKING POLICY mask_email;
```

Snowflake encrypts data at rest and in transit by default, so cleartext storage is not a concern when keys are managed correctly (CWE-312, cleartext storage of sensitive information). Keep credentials and key material out of source control and scripts (CWE-522, insufficiently protected credentials); use key-pair auth or a secrets manager instead. Secure data sharing exposes read-only views to other accounts without duplicating data. See /SECURE_CODING_REFERENCE.md for the authorization and credential-handling patterns.

## Performance and scaling

Size compute to the workload. Scale up (a larger warehouse) for heavy single queries; scale out (a multi-cluster warehouse) for many concurrent users. Pause warehouses when idle to control cost.

Micro-partition pruning does the work of indexes. Load and cluster data so that filters line up with partition metadata; define a clustering key on very large tables whose natural load order does not match query filters.

```sql
ALTER TABLE orders CLUSTER BY (ordered_at);
```

Result caching returns identical queries without recompute. Materialized views and the search optimization service help point-lookup and selective-filter patterns on large tables.

## Resources

- Snowflake Documentation (docs.snowflake.com), the official product and SQL reference.

## Related pages

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/databricks.md
- /databases/clickhouse.md
- /databases/postgresql.md
