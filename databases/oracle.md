# Oracle Database

Oracle Database is a commercial relational database used in large enterprises for transactional and mixed workloads. It stores data in tables within schemas and tablespaces, and it is known for strong concurrency, high availability through Real Application Clusters, and a deep feature set. Procedural logic is written in PL/SQL, Oracle's server-side language. It runs on Linux, Unix, and Windows, and in Oracle Cloud Infrastructure as an Autonomous Database.

## What it is and where it is used

Oracle backs banking cores, telecom billing, ERP systems such as Oracle E-Business Suite, and other systems with heavy transaction and reporting demands. It is licensed per processor or per named user, with editions from Express up to Enterprise. Organizations choose it for mature partitioning, advanced security options, and long-term support. Managed forms include Autonomous Transaction Processing and Autonomous Data Warehouse.

## Data model and architecture

The model is relational: typed columns and rows in tables, grouped into schemas owned by users. Since 12c, the architecture is multitenant: a container database (CDB) holds the root and one or more pluggable databases (PDBs). A PDB is a self-contained set of schemas that can be plugged into or unplugged from a CDB, which eases consolidation and cloning.

Storage is organized into tablespaces, which group data files on disk and map segments such as tables and indexes. An instance is the set of memory structures (the System Global Area) and background processes that serve a database. Redo logs record changes for recovery, and undo segments provide read consistency and rollback.

## Query language and interface

Oracle speaks SQL with its own extensions, including analytic functions, hierarchical `CONNECT BY` queries, and the `MERGE` statement. Server-side procedures, functions, packages, and triggers are written in PL/SQL. The traditional command-line client is `sqlplus`; `SQLcl` is the modern Java-based client, and SQL Developer is the graphical tool.

```sql
SELECT customer_id, SUM(total) FROM orders GROUP BY customer_id;
```

## Administration and operations

Connect with `sqlplus`, naming the user and a connect identifier:

```bash
sqlplus app_owner@//db.internal:1521/SALESPDB
```

Create users and grant roles and privileges by least privilege; profiles enforce password and resource rules:

```sql
CREATE USER app_rw IDENTIFIED BY "set-in-secret-manager"
    DEFAULT TABLESPACE users QUOTA 100M ON users;
GRANT CREATE SESSION TO app_rw;
GRANT SELECT, INSERT, UPDATE ON sales.orders TO app_rw;
```

Back up with Recovery Manager (RMAN), which handles incremental backups and point-in-time recovery:

```bash
rman target /
RMAN> BACKUP DATABASE PLUS ARCHIVELOG;
```

Move schemas and data with Data Pump (`expdp` and `impdp`):

```bash
expdp app_owner DIRECTORY=dp_dir DUMPFILE=sales.dmp SCHEMAS=sales
impdp app_owner DIRECTORY=dp_dir DUMPFILE=sales.dmp REMAP_SCHEMA=sales:sales_qa
```

## A worked example

Connect, create a table, insert a row, and read it back:

```sql
CREATE TABLE orders (
    id          NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer    VARCHAR2(100) NOT NULL,
    total_cents NUMBER(12) NOT NULL,
    placed_at   TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL
);

INSERT INTO orders (customer, total_cents) VALUES ('acme-co', 4999);
COMMIT;

SELECT customer, total_cents
FROM orders
WHERE placed_at > SYSTIMESTAMP - INTERVAL '1' DAY
ORDER BY total_cents DESC;
```

## Security and hardening

Transparent Data Encryption (TDE) encrypts tablespaces and columns at rest with keys held in a wallet or keystore, which protects data files and backups without application changes. Combined with volume encryption, it addresses cleartext storage of sensitive data (CWE-312). Require TLS (Oracle Native Network Encryption or TCPS) for connections in transit.

Grant object and system privileges through roles and keep each application account at least privilege. Profiles limit password lifetime, reuse, and failed-login lockout. Unified Auditing records policy-driven audit events into a single secured trail:

```sql
CREATE AUDIT POLICY ord_access ACTIONS SELECT, UPDATE ON sales.orders;
AUDIT POLICY ord_access;
```

SQL injection (CWE-89) is the main application risk, and it is acute in dynamic PL/SQL. Avoid building statements by concatenation; use bind variables with `EXECUTE IMMEDIATE ... USING` or static SQL:

```sql
EXECUTE IMMEDIATE
    'SELECT total_cents FROM orders WHERE customer = :1'
    INTO v_total USING p_customer;
```

Oracle ships sample schemas (`HR`, `SCOTT`) and default accounts; lock or drop any you do not need, since known default credentials allow access with no real barrier (CWE-306). Restrict the listener to known interfaces, firewall port 1521, and set `SEC_CASE_SENSITIVE_LOGON` and strong password verifiers. See /SECURE_CODING_REFERENCE.md for injection and secrets handling.

## Performance and scaling

B-tree indexes serve most lookups; bitmap indexes suit low-cardinality columns in data warehouses. Use the cost-based optimizer with fresh statistics and read plans with `EXPLAIN PLAN` or `DBMS_XPLAN`. Partitioning splits large tables by range, list, hash, or composite keys, which prunes scans and eases maintenance.

Real Application Clusters (RAC) runs one database across several nodes for availability and scaling. Data Guard maintains standby databases for disaster recovery and read offload. Sharding distributes a table across independent databases by a sharding key for linear scale on very large datasets.

## Resources

- Oracle Database documentation (the official library from Oracle)

## Related pages

- /languages/plsql.md
- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/postgresql.md
- /databases/mysql.md
- /databases/sql-server.md
