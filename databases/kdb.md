# kdb+ and q

kdb+ is a columnar database built for time-series data at high volume. It pairs an in-memory store with an on-disk column store and is queried through the `q` language. Finance teams use it for tick data: order books, trades, and quotes recorded at microsecond resolution. A kdb+ system usually runs as several cooperating processes connected over IPC.

## What it is and where it is used

kdb+ comes from KX Systems. The database and the `q` language ship as one small binary. The same binary serves as an in-memory engine, an on-disk store, and an IPC server.

The typical deployment is capital markets. A feed handler publishes ticks to a tickerplant, which logs them and forwards them to subscribers. A real-time database (RDB) holds the current day in memory. A historical database (HDB) holds prior days on disk, partitioned by date. Analysts query both through the same `q` syntax.

The design favors fast ingestion and fast aggregation over many rows. Columns are stored contiguously, so reading one column of a billion-row table touches only that column.

## Data model and architecture

The core types are atoms, lists, dictionaries, and tables. A table is a list of named columns. Each column is a typed vector held contiguously in memory or mapped from disk.

A keyed table marks one or more columns as a primary key. Lookups against the key behave like a dictionary from key rows to value rows.

```q
trade:([] time:`time$(); sym:`symbol$(); price:`float$(); size:`long$())
quote:([] time:`time$(); sym:`symbol$(); bid:`float$(); ask:`float$())
master:([sym:`symbol$()] name:(); sector:())
```

An HDB stores each day in its own directory. Large tables are splayed: every column is a separate file inside the partition. The `par.txt` mechanism can spread partitions across several storage locations. Symbol columns are enumerated against a shared file called `sym` to keep them compact.

```text
/hdb
  /2026.10.30/trade/{time,sym,price,size}
  /2026.10.31/trade/{time,sym,price,size}
  sym
```

## Query language and interface

`q` is a terse, right-to-left functional language. qSQL is the table-query dialect that reads like SQL but runs inside `q`.

```q
select avg price by sym from trade where time within 09:30:00 10:00:00
select vwap:size wavg price by sym from trade
update cumSize:sums size by sym from `trade
```

Client applications connect over IPC. Opening a handle returns an integer; calling it sends a query and blocks for the result.

```q
h:hopen `::5010          / open a handle to a process on port 5010
h"select count i from trade"
hclose h
```

The `0:` and `1:` operators read and write text and binary files. The `.Q` namespace holds database utilities, including `.Q.dpft` for saving a partitioned, sorted table.

## Administration and operations

A process starts from the command line. Flags set the listening port, worker threads, and memory limits.

```bash
q tick.q sym . -p 5010 -w 64000
```

Key flags: `-p` sets the port, `-w` caps workspace memory in megabytes, `-s` sets secondary threads, and `-T` sets a query timeout in seconds. Running without `-p` keeps the process off the network entirely.

The `.z` namespace holds system callbacks. These control what happens on connection, on each message, and on a timer.

```q
.z.pg:{[q] value q}      / synchronous message handler
.z.ps:{[q] value q}      / asynchronous message handler
.z.po:{[h] 0N!(.z.a;.z.u)}  / on connection open: log client address and user
.z.ts:{ .u.end[] }       / timer callback
```

Access between processes is pure IPC. There is no separate admin console: operators connect with a handle and run `q`. Logging, backups, and end-of-day roll are all scripted in `q` and scheduled by the host operating system.

## A worked example

Compute a one-minute VWAP time series per symbol from the day's trades, then join the last quote known at each bar.

```q
bars:select vwap:size wavg price, lastPx:last price
  by sym, minute:time.minute from trade

q:select by sym, minute:time.minute from quote
res:bars lj `sym`minute xkey q
select from res where minute within 09:30 16:00
```

The `by` clause groups into bars. `lj` is a left join against a keyed table. The whole pipeline runs over column vectors without copying unrelated columns.

## Security and hardening

kdb+ historically ships with minimal built-in authentication. A process with `-p` and no further controls accepts any client that can reach the port and runs whatever `q` it is sent. Treat an open, unprotected port as remote code execution exposure (CWE-306, missing authentication for a critical function).

Apply access control in the connection handlers. `.z.pw` validates a username and password at connection time. Override `.z.pg` and `.z.ps` to parse requests and reject anything that is not an allow-listed function call, rather than passing strings to `value`.

```q
.z.pw:{[user;pwd] user in `alice`bob}   / allow only known users
.z.pg:{[q] $[-11h=type first q; allowed[q]; '`access] }
```

Use the `-u` and `-U` flags to require password-file authentication, and run with an operating-system user that owns only the database files it needs (least privilege). Store any credential file outside the repository; never commit plaintext passwords (CWE-312, cleartext storage of sensitive information; CWE-522, insufficiently protected credentials).

Enable TLS on IPC so sessions between processes are encrypted and authenticated. Set `-E 1` for plain plus TLS or `-E 2` for TLS only, and front the cluster with network isolation so only known hosts reach the ports. See /SECURE_CODING_REFERENCE.md for the input-validation and credential-handling patterns referenced here.

## Performance and scaling

Columnar storage is the main lever. Queries read only the columns they name, so wide tables stay fast. Keep hot data in the RDB and roll cold data to the HDB nightly.

Partition the HDB by date and apply the parted attribute (`p#`) to the `sym` column so date-plus-symbol queries do a direct index lookup. Attributes (`` `s# ``, `` `p# ``, `` `u# ``, `` `g# ``) trade write cost for read speed.

```q
`sym xasc `:/hdb/2026.10.31/trade/   / sort on disk before applying p#
```

Scale out by splitting work across processes: multiple HDB workers behind a gateway, secondary threads (`-s`) for parallel reads across partitions, and memory-mapped columns so the operating system page cache serves repeated reads. Watch workspace growth with `.Q.w[]` and cap it with `-w`.

## Resources

- KX Documentation (code.kx.com), the official reference for kdb+ and `q`.
- *Q for Mortals* by Jeffry Borror, a standard introduction to the `q` language.

## Related pages

- /languages/k-q.md
- /databases/README.md
- /SECURE_CODING_REFERENCE.md
- /databases/clickhouse.md
- /databases/redis.md
- /databases/cassandra.md
