# SQLite

SQLite is an embedded, serverless relational database engine. The whole database lives in a single file on disk, and the engine is a library linked into the host program. There is no separate process to install, configure, or run. It is one of the most widely deployed database engines, shipping in browsers, phones, and desktop applications.

## What it is and where it is used

SQLite runs in-process. The application calls library functions, and the library reads and writes the database file directly. This design fits local storage, caches, application file formats, and testing. It is not built for many concurrent writers over a network.

You find SQLite in Android and iOS apps, web browsers, Python's standard library, and countless desktop tools. It stores settings, offline data, and structured documents. When a single process or a handful of local readers own the data, it is a strong fit.

## Data model and architecture

A SQLite database is one file holding tables, indexes, views, and triggers. The schema is relational with `CREATE TABLE`, primary keys, foreign keys, and constraints. Foreign key enforcement is off by default and is enabled per connection with `PRAGMA foreign_keys = ON`.

SQLite uses dynamic typing with type affinity. A column has a declared affinity (`TEXT`, `NUMERIC`, `INTEGER`, `REAL`, or `BLOB`), but a value keeps its own storage class. A column declared `INTEGER` can hold text unless a `CHECK` constraint or `STRICT` table forbids it. `STRICT` tables, available in recent versions, enforce declared types.

The engine supports transactions with `BEGIN`, `COMMIT`, and `ROLLBACK`. Write-Ahead Logging (WAL) mode lets readers and one writer proceed at the same time, which improves concurrency over the default rollback journal.

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
```

## Query language and interface

SQLite implements most of standard SQL, including joins, subqueries, common table expressions, and window functions. It omits some features such as full `ALTER TABLE` column changes and `RIGHT`/`FULL OUTER JOIN` in older versions.

The `sqlite3` command-line shell opens a database file and runs SQL and dot-commands. Dot-commands such as `.tables`, `.schema`, and `.import` control the shell itself.

```bash
sqlite3 app.db
```

```
sqlite> .tables
sqlite> .schema products
sqlite> .mode column
sqlite> .headers on
sqlite> SELECT * FROM products LIMIT 5;
sqlite> .quit
```

Language bindings exist for C, Python, Go, Rust, Java, and most others. Python's `sqlite3` module ships in the standard library.

## Administration and operations

There is no server, no daemon, and no user accounts to manage. Administration is mostly file management plus a few pragmas. Create a database by opening a path that does not yet exist.

Back up a database by copying the file when no process is writing. For a live database, use the `.backup` dot-command or the online backup API, which produces a consistent copy while connections are open.

```bash
# Safe online backup of a live database
sqlite3 app.db ".backup 'backup/app_$(date +%F).db'"

# Dump schema and data as SQL text
sqlite3 app.db ".dump" > app_dump.sql
```

Reclaim space and defragment with `VACUUM`. Check integrity before trusting a recovered file.

```sql
VACUUM;
PRAGMA integrity_check;
PRAGMA optimize;
```

Tune behavior with pragmas rather than config files. `PRAGMA busy_timeout` sets how long a blocked connection waits for a lock. `PRAGMA synchronous` trades durability for speed.

```sql
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
```

## A worked example

Create a table, insert rows, and query them from the shell.

```bash
sqlite3 inventory.db
```

```sql
CREATE TABLE products (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    unit_price REAL NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

INSERT INTO products (name, unit_price) VALUES ('Widget', 9.99);
INSERT INTO products (name, unit_price) VALUES ('Gadget', 24.50);

SELECT id, name, unit_price
FROM products
WHERE unit_price < 20.0
ORDER BY unit_price;
```

## Security and hardening

SQLite has no built-in user authentication, roles, or network access control. Anyone who can read the file can read every row, and anyone who can write it can change any row. The database file is the trust boundary. Protection comes from the operating system.

Set restrictive file permissions. The database and its WAL and journal files should be readable and writable only by the owning account. Loose permissions on a sensitive database map to CWE-732. Store the file outside web-served directories so it cannot be downloaded over HTTP.

SQLite does not encrypt the file by default, so sensitive data sits in plaintext on disk. Storing sensitive data unencrypted maps to CWE-312. Use an encryption extension such as SQLCipher or the SQLite Encryption Extension (SEE) when the file holds secrets, or encrypt the surrounding volume.

SQL injection still applies in full. Dynamic SQL built from untrusted input is CWE-89. Use parameter binding, never string concatenation.

```python
import sqlite3
conn = sqlite3.connect("inventory.db")
cur = conn.cursor()

# Safe: bound parameter
cur.execute("SELECT * FROM products WHERE name = ?", (user_input,))

# Unsafe: string formatting invites injection
# cur.execute(f"SELECT * FROM products WHERE name = '{user_input}'")
```

Treat loadable extensions and untrusted database files with care. Opening a crafted database file can trigger bugs, so validate the source. Disable `load_extension` for untrusted input. For parameterization, least privilege at the OS layer, and secret handling, see /SECURE_CODING_REFERENCE.md.

## Performance and scaling

SQLite is fast for local reads and moderate write volumes. Add indexes on columns used in `WHERE`, `JOIN`, and `ORDER BY`. Use `EXPLAIN QUERY PLAN` to confirm an index is used.

```sql
EXPLAIN QUERY PLAN
SELECT * FROM products WHERE name = 'Widget';
```

Enable WAL mode for better read-write concurrency. Wrap bulk inserts in a single transaction, since each unwrapped statement commits on its own and pays a full durability cost. Keep write transactions short so other connections are not blocked.

SQLite does not scale to many concurrent writers or to clustered deployments. A single writer holds a lock during a write transaction. When an application outgrows one machine and needs concurrent remote writers, a client-server database such as PostgreSQL or MySQL is the right move.

## Resources

- The SQLite documentation (the official reference at the project site, including the SQL syntax and pragma references).

## Related pages

- /languages/sql.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/postgresql.md
- /databases/mysql.md
- /databases/sql-server.md
