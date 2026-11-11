# kdb+ and q

kdb+ is a columnar database built for time-series data at high volume. It pairs an in-memory store with an on-disk column store and is queried through the `q` language. Finance teams use it for tick data: order books, trades, and quotes recorded at microsecond resolution. A kdb+ system usually runs as several cooperating processes connected over IPC.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Database administrators, developers and security engineers who run, query or assess kdb+ and q

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,222 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are modeling data or writing queries for kdb+ and q, you are administering or hardening a deployment, or you want a worked example to start from

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Data model and architecture](#data-model-and-architecture), [Security and hardening](#security-and-hardening), [A worked example](#a-worked-example)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[K and Q](/languages/k-q.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [ClickHouse](/databases/clickhouse.md), [Redis](/databases/redis.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Security relevance

This section is the threat-facing view of kdb+: how a `q` process looks to an attacker or auditor on the wire, and which weakness classes dominate its record. The controls that defend against them are in the "Security and hardening" section that follows.

### Where it appears

- The data tier in capital-markets systems, reached as a `q` process listening on its `-p` port over the kdb+ IPC protocol. These processes often hold tick data of direct financial value.
- Recognized by the kdb+ IPC handshake on the listening port rather than by a web banner. It is a niche engine with little dedicated offensive tooling, so recognition and testing are usually manual.
- The decisive offensive fact is that the default synchronous handler passes incoming messages to `value`, so an open port with no `.z.pw` check runs whatever `q` it is sent. Defensive work is scripted in `q` itself through the `.z` callbacks and connection logging.
- The supply-chain surface is small: a single KX binary and a `q` codebase with few external dependencies.

### Dominant weakness classes

kdb+ is a mature C core hardened against memory corruption in normal use, so the practical risks are access control and the fact that the query interface is a general programming language.

- Missing authentication ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)) when a process starts with `-p` and no `-u`, `-U`, or `.z.pw` check, accepting any client that reaches the port.
- Code injection ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)) because handlers that evaluate incoming strings with `value` turn a query into arbitrary `q` execution on the host.
- Cleartext storage of sensitive information ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) when password files or credentials are committed alongside the database code.
- Improper privilege management ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)) when the process runs as an operating-system user with more access than the database files require.

### Why it matters

kdb+ is a high-value, low-volume target: recognizing an IPC port and testing whether a `value`-based handler runs arbitrary `q` is the core check, since that single fact converts a reachable port into host code execution. It maps straight to the controls the defender owns: require password-file authentication with `-u` or `-U`, validate in `.z.pw`, allow-list calls in `.z.pg` and `.z.ps` instead of calling `value`, and run under a least-privilege account. See [the database security reference](/DATABASE_SECURITY_REFERENCE.md) for the engine-agnostic hardening checklist.

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

- [K and Q](/languages/k-q.md)
- [Databases](/databases/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [ClickHouse](/databases/clickhouse.md)
- [Redis](/databases/redis.md)
- [Apache Cassandra](/databases/cassandra.md)
