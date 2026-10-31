# MySQL and MariaDB

MySQL is an open-source relational database widely used behind web applications and content systems. MariaDB is a community fork started by the original MySQL authors after the Oracle acquisition, and it stays largely wire-compatible and SQL-compatible. Both store data in tables managed by pluggable storage engines, with InnoDB as the transactional default. This page covers both, noting where they diverge.

## What it is and where it is used

MySQL powers the classic LAMP stack and backs platforms such as WordPress, Drupal, and many commerce systems. It runs on Linux, Windows, and macOS, and has managed forms on Amazon RDS and Aurora, Azure, and Google Cloud SQL. MariaDB ships as the default in several Linux distributions and offers its own clustering and storage engine options. Applications often target the shared subset so they can run on either.

## Data model and architecture

The model is relational: typed columns and rows in tables, grouped into databases (also called schemas). A storage engine decides how rows are stored, indexed, and locked. InnoDB is the transactional, crash-safe default, with row-level locking, foreign keys, and MVCC; MyISAM is an older table-level-locking engine kept for legacy data.

InnoDB keeps a clustered primary-key index, so rows are stored in primary-key order and secondary indexes point back to it. A redo log and a buffer pool support durability and caching. MariaDB adds engines such as Aria and ColumnStore, and both servers support the binary log that records changes for replication and point-in-time recovery.

## Query language and interface

Both speak SQL with vendor extensions, including `LIMIT`, `INSERT ... ON DUPLICATE KEY UPDATE`, and JSON functions. Window functions and common table expressions are available in MySQL 8.0 and current MariaDB. The command-line client is `mysql` (shipped as `mariadb` on MariaDB), and applications connect through connectors for most languages.

```sql
SELECT id, name FROM customers ORDER BY created_at DESC LIMIT 10;
```

## Administration and operations

Connect with the client, naming host, user, and database:

```bash
mysql -h db.internal -u app_rw -p sales
```

Create a user scoped to a host pattern and grant least privilege:

```sql
CREATE USER 'app_rw'@'10.0.0.%' IDENTIFIED BY 'set-in-secret-manager';
GRANT SELECT, INSERT, UPDATE ON sales.* TO 'app_rw'@'10.0.0.%';
FLUSH PRIVILEGES;
```

Back up logically with `mysqldump` and restore by replaying the SQL:

```bash
mysqldump -h db.internal -u admin -p --single-transaction sales > sales.sql
mysql -h db.internal -u admin -p sales_restore < sales.sql
```

Server settings live in `my.cnf` (or `my.ini` on Windows) under sections such as `[mysqld]`. Inspect a running value:

```sql
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
```

## A worked example

Connect, create a table, insert a row, and read it back:

```sql
CREATE TABLE orders (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    customer    VARCHAR(100) NOT NULL,
    total_cents INT NOT NULL,
    placed_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT INTO orders (customer, total_cents)
VALUES ('acme-co', 4999);

SELECT customer, total_cents
FROM orders
WHERE placed_at > NOW() - INTERVAL 1 DAY
ORDER BY total_cents DESC;
```

## Security and hardening

Enforce password strength with the `validate_password` component in MySQL (or the equivalent plugin in MariaDB), which rejects short or common passwords at creation time. Grant privileges by least privilege and scope each account to the hosts it should connect from, rather than `'user'@'%'`.

Run `mysql_secure_installation` on a new server. It removes anonymous accounts, blocks remote root login, drops the test database, and can set a root password:

```bash
mysql_secure_installation
```

Require TLS for connections in transit. Configure the server with certificate files and force encryption per account:

```sql
ALTER USER 'app_rw'@'10.0.0.%' REQUIRE SSL;
```

For data at rest, InnoDB supports tablespace encryption with a keyring; otherwise use volume encryption. Avoid storing secrets as plaintext columns, which risks cleartext exposure (CWE-312).

SQL injection (CWE-89) is the main application risk. Use prepared statements and bound parameters:

```python
cur.execute("SELECT * FROM orders WHERE customer = %s", (name,))
```

The `LOCAL INFILE` feature lets a client load a local file into a table, and a malicious or compromised server can request arbitrary client files, an information exposure risk (CWE-200). Disable it unless needed by setting `local_infile = 0`. A server listening on all interfaces with default or anonymous accounts can allow access with no real authentication (CWE-306); bind `bind-address` to known interfaces and firewall the port. Enable the audit log plugin for a trail of connections and statements. See /SECURE_CODING_REFERENCE.md for injection and secrets guidance.

## Performance and scaling

InnoDB uses B-tree indexes; a well-chosen primary key and covering secondary indexes avoid extra lookups. Use `EXPLAIN` to confirm the optimizer picks an index and reads few rows. Size `innodb_buffer_pool_size` to hold the working set in memory.

Asynchronous replication streams the binary log from a primary to replicas for read scaling and failover; semisynchronous and group replication reduce data loss on failover. MariaDB offers Galera Cluster for synchronous multi-primary replication. Partitioning splits one table by range, list, hash, or key for large datasets. For write scaling beyond one node, application-level or proxy-based sharding (for example Vitess) distributes data across shards.

## Resources

- MySQL Reference Manual (the official manual from Oracle)
- MariaDB Knowledge Base (the official MariaDB documentation)
- *High Performance MySQL* by Silvia Botros and Jeremy Tinley

## Related pages

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/postgresql.md
- /databases/oracle.md
- /databases/sqlite.md
