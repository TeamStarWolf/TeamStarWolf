# Apache Cassandra

Apache Cassandra is a distributed wide-column database built for high write throughput and no single point of failure. Data spreads across a ring of peer nodes, each able to take reads and writes. It is used for time-series data, event logging, messaging, and other write-heavy workloads that must stay available across data centers.

## What it is and where it is used

Cassandra has no primary node. Every node is equal and holds a share of the data plus replicas of other nodes' data. A client can connect to any node, which acts as the coordinator for that request. This design keeps the cluster serving even when nodes or whole data centers go down.

It fits workloads with heavy, continuous writes and known access patterns: sensor and metrics streams, user activity logs, order and payment events, and inboxes. It is a poor fit for ad hoc analytical queries and heavy joins, which it does not support.

You design tables around the queries you will run, not around normalized entities. The query comes first, then the table that answers it.

## Data model and architecture

Data lives in a ring. Each row has a partition key, and Cassandra hashes that key with a partitioner to place the row on the ring. The token that results decides which nodes store the row and its replicas. Rows with the same partition key sit together on the same nodes.

A keyspace is the top-level container and sets the replication strategy. A table holds rows defined by a primary key. The primary key has two parts: the partition key, which locates the data, and optional clustering columns, which order rows within a partition.

Wide-column means a partition can hold many rows, each with its own set of columns. Writes go first to a commit log and an in-memory memtable, then flush to immutable SSTable files on disk. Compaction merges SSTables over time and discards tombstones, the markers that represent deletes.

## Query language and interface

The query language is CQL, the Cassandra Query Language. Its syntax resembles SQL, but it only supports operations the data model can serve efficiently. Every query should target a partition key, and joins and arbitrary `WHERE` clauses are not allowed.

```sql
CREATE KEYSPACE shop
  WITH replication = { 'class': 'NetworkTopologyStrategy', 'dc1': 3 };

CREATE TABLE shop.orders_by_customer (
  customer_id uuid,
  order_time  timestamp,
  order_id    uuid,
  amount      decimal,
  PRIMARY KEY (customer_id, order_time)
) WITH CLUSTERING ORDER BY (order_time DESC);
```

The interactive shell is `cqlsh`, a Python client that connects over the native protocol on port 9042. Official drivers exist for Java, Python, Node.js, Go, and C#. Prepared statements bind parameters and are the preferred way to build queries.

```sql
SELECT order_id, amount FROM shop.orders_by_customer
  WHERE customer_id = 7f3b... AND order_time > '2026-01-01';
```

## Administration and operations

Connect with the shell.

```bash
cqlsh 127.0.0.1 9042 -u cassandra -p cassandra
```

Create roles and grant permissions. Roles can log in, hold passwords, and own grants on keyspaces and tables.

```sql
CREATE ROLE appuser WITH PASSWORD = 'a-long-secret' AND LOGIN = true;
GRANT SELECT, MODIFY ON KEYSPACE shop TO appuser;
REVOKE MODIFY ON KEYSPACE shop FROM appuser;
```

Operate the cluster with `nodetool`, the admin command for a node.

```bash
nodetool status
nodetool repair shop
nodetool tpstats
```

Take a snapshot, which hard-links the current SSTables into a backup directory.

```bash
nodetool snapshot shop
nodetool clearsnapshot shop
```

The main config file is `cassandra.yaml`. It sets the cluster name, the seed nodes, the listen and RPC addresses, the authenticator, and the authorizer.

## A worked example

Create a keyspace and a query-first table, write rows, and read a partition.

```sql
cqlsh

CREATE KEYSPACE sensors
  WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': 3 };

USE sensors;

CREATE TABLE readings (
  device_id text,
  ts        timestamp,
  celsius   float,
  PRIMARY KEY (device_id, ts)
) WITH CLUSTERING ORDER BY (ts DESC);

INSERT INTO readings (device_id, ts, celsius)
  VALUES ('dev-1', '2026-10-31 09:00:00', 21.4);

INSERT INTO readings (device_id, ts, celsius)
  VALUES ('dev-1', '2026-10-31 09:05:00', 21.9);

SELECT * FROM readings
  WHERE device_id = 'dev-1'
  LIMIT 10;
```

Each query hits one partition (`device_id`) and reads rows already ordered by `ts`. That is why the table was shaped around this exact read.

## Security and hardening

Historically Cassandra shipped with authentication and authorization turned off. The default `AllowAllAuthenticator` let any client that reached port 9042 run any query. An exposed cluster had no access control at all, a missing authentication weakness (CWE-306).

Turn on authentication by setting `authenticator: PasswordAuthenticator` and `authorizer: CassandraAuthorizer` in `cassandra.yaml`, then restart and rotate the default `cassandra` superuser. Grant each role only the keyspaces and operations it needs, following least privilege.

```yaml
# cassandra.yaml
authenticator: PasswordAuthenticator
authorizer: CassandraAuthorizer
```

Encrypt traffic with TLS. Cassandra separates `server_encryption_options` for node-to-node traffic from `client_encryption_options` for client connections. Enable both so gossip and queries do not cross the network in cleartext. Avoid storing sensitive values unencrypted at rest, which is cleartext storage, CWE-312.

CQL injection is real when a query is built by concatenating untrusted input into the statement string. An attacker can inject clauses or extra statements the same way SQL injection works, the CWE-89 family applied to CQL. Use prepared statements with bound parameters, and never interpolate user input into CQL text. See /SECURE_CODING_REFERENCE.md.

## Performance and scaling

Replication is set per keyspace by a strategy and a replication factor. `NetworkTopologyStrategy` places replicas across racks and data centers. A factor of 3 keeps three copies of every row, so the cluster survives node loss without data loss.

Scaling is horizontal. Add nodes and the ring rebalances token ranges to spread data and traffic. There is no central coordinator to bottleneck, so throughput grows roughly with node count for well-partitioned data.

Consistency is tunable per request. A query sets a consistency level such as `ONE`, `QUORUM`, or `ALL`, which decides how many replicas must respond. When read consistency plus write consistency exceed the replication factor, reads see the latest write. Lower levels give lower latency and higher availability at the cost of possibly stale reads.

## Resources

- Apache Cassandra documentation (official documentation)

## Related pages

- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/mongodb.md
- /databases/redis.md
- /databases/dynamodb.md
- /databases/clickhouse.md
