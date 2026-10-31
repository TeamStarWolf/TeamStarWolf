# Databases

Reference pages for the database engines that applications store their data in: relational databases, analytical warehouses and lakehouses, the NoSQL families (document, key-value, wide-column), search and graph engines, and time-series stores. Each page covers the data model and architecture, the query language and interface, the real administration commands, a worked example, and the security and hardening that matter, from authentication and role-based access to encryption, injection, and the network-exposure and default-configuration mistakes that put databases in breach reports.

For the query languages themselves see [SQL](/languages/sql.md), [PL/SQL](/languages/plsql.md), [T-SQL](/languages/tsql.md), and [kdb+ and q](/languages/k-q.md); for building queries safely see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

Related: [All languages](/languages/README.md), [Command reference](/commands/README.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Reference Index](/INDEX.md).

---

## Relational

| Database | Summary |
|---|---|
| [PostgreSQL](/databases/postgresql.md) | Open-source relational database with MVCC, extensions, and row-level security |
| [MySQL and MariaDB](/databases/mysql.md) | The widely deployed open-source relational database and its fork |
| [Oracle Database](/databases/oracle.md) | Enterprise relational database with multitenant containers and PL/SQL |
| [Microsoft SQL Server](/databases/sql-server.md) | Microsoft's relational engine with T-SQL, TDE, and Always Encrypted |
| [SQLite](/databases/sqlite.md) | Embedded, serverless, single-file relational database |

## Analytical, warehouse, and lakehouse

| Database | Summary |
|---|---|
| [ClickHouse](/databases/clickhouse.md) | Columnar online-analytical database for fast aggregate queries |
| [Snowflake](/databases/snowflake.md) | Cloud data warehouse with separated storage and compute and role-based access |
| [Databricks and Spark SQL](/databases/databricks.md) | Lakehouse platform on Apache Spark and Delta Lake with Unity Catalog governance |

## Document, key-value, and wide-column

| Database | Summary |
|---|---|
| [MongoDB](/databases/mongodb.md) | Document database with a flexible schema and an aggregation pipeline |
| [Amazon DynamoDB](/databases/dynamodb.md) | Managed serverless key-value and document database with IAM-based access |
| [Redis](/databases/redis.md) | In-memory key-value and data-structure store with optional persistence |
| [Apache Cassandra](/databases/cassandra.md) | Wide-column distributed database with tunable consistency |

## Search and graph

| Database | Summary |
|---|---|
| [Elasticsearch](/databases/elasticsearch.md) | Distributed search and analytics engine on Lucene |
| [Neo4j](/databases/neo4j.md) | Property-graph database with the Cypher query language |

## Time-series

| Database | Summary |
|---|---|
| [kdb+ and q](/databases/kdb.md) | High-performance columnar time-series database used in finance |

## Databases and security

A database holds the data an attacker wants, so its defenses are a recurring theme across this library. The constant risks are injection when queries are built from untrusted input (CWE-89 for SQL, CWE-943 for NoSQL), missing or default authentication and binding to all interfaces, which has exposed countless Redis, MongoDB, and Elasticsearch instances (CWE-306), over-broad roles and grants (CWE-862), and unencrypted data at rest and in transit (CWE-312). Each page's security section gives the engine-specific controls, tied to the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
