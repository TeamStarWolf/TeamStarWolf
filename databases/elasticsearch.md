# Elasticsearch

Elasticsearch is a distributed search and analytics engine built on Apache Lucene. It stores JSON documents, indexes every field by default, and answers full-text and aggregation queries over a REST API. Clusters scale horizontally by splitting data into shards spread across nodes. It anchors the Elastic Stack, where it holds the data that Kibana visualizes.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Database administrators, developers and security engineers who run, query or assess Elasticsearch

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,211 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are modeling data or writing queries for Elasticsearch, you are administering or hardening a deployment, or you want a worked example to start from

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Data model and architecture](#data-model-and-architecture), [Security and hardening](#security-and-hardening), [A worked example](#a-worked-example)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [ClickHouse](/databases/clickhouse.md), [MongoDB](/databases/mongodb.md), [Redis](/databases/redis.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

Elasticsearch began as a search server and grew into a store for logs, metrics, traces, and security events. Teams use it for application search, log analytics, observability, and SIEM-style threat detection. Its strength is fast text relevance scoring combined with aggregations over large volumes.

Common deployments pair it with other stack components. Beats and Logstash ship and transform data into it. Kibana reads from it for dashboards, alerting, and investigation. The same cluster can serve a product search box and a security operations team at once.

## Data model and architecture

Data lives in indices. An index holds documents, which are JSON objects identified by an `_id`. A mapping defines the fields in an index and their types, such as `text`, `keyword`, `date`, or `long`. You can let Elasticsearch infer a mapping or define it explicitly to control analysis.

The core structure is the inverted index. Lucene tokenizes each `text` field, then records which documents contain each term. This makes term lookup fast regardless of corpus size. A `keyword` field is stored verbatim for exact matches, sorting, and aggregations.

An index is divided into shards, each a self-contained Lucene index. Primary shards hold the original data. Replica shards are copies on other nodes that provide redundancy and serve reads. A cluster of several nodes distributes shards so that losing one node does not lose data.

## Query language and interface

All interaction is over HTTP. You index a document with `PUT` or `POST`, retrieve it with `GET`, and search with the Query DSL, a JSON query language sent to the `_search` endpoint. The DSL expresses full-text queries, term filters, boolean logic, and aggregations.

```
POST /products/_search
{
  "query": {
    "bool": {
      "must":   { "match": { "name": "wireless keyboard" } },
      "filter": { "range": { "price": { "lte": 100 } } }
    }
  }
}
```

A `match` query runs analysis and scores relevance. A `term` or `range` filter runs without scoring and is cacheable. Aggregations run alongside queries to summarize results, for example a `terms` aggregation that counts documents per category.

## Administration and operations

The REST API also manages the cluster. Check health and inspect indices with the `_cat` APIs.

```
GET /_cluster/health
GET /_cat/indices?v
GET /_cat/shards?v
```

Index lifecycle management (ILM) automates aging data through hot, warm, cold, and delete phases. A policy rolls over an index when it reaches a size or age, then moves older indices to cheaper storage and eventually deletes them. This keeps time-series data such as logs under control.

```
PUT /_ilm/policy/logs-policy
{
  "policy": {
    "phases": {
      "hot":    { "actions": { "rollover": { "max_primary_shard_size": "50gb" } } },
      "delete": { "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}
```

Back up with the snapshot API. Register a repository, such as a shared filesystem or an object store, then take snapshots on a schedule.

```
PUT /_snapshot/my_backup
{ "type": "fs", "settings": { "location": "/mnt/es-backups" } }

PUT /_snapshot/my_backup/snapshot_1?wait_for_completion=true
```

## A worked example

Create an index with an explicit mapping, add a document, then search it.

```
PUT /articles
{
  "mappings": {
    "properties": {
      "title":     { "type": "text" },
      "tags":      { "type": "keyword" },
      "published": { "type": "date" }
    }
  }
}

POST /articles/_doc/1
{
  "title": "Hardening a search cluster",
  "tags": ["security", "operations"],
  "published": "2026-03-01"
}

POST /articles/_search
{
  "query": { "match": { "title": "hardening cluster" } }
}
```

The search returns the document with a relevance score in `_score`. The `tags` field, mapped as `keyword`, supports exact filtering and aggregation without analysis.

## Security relevance

This section is the threat-facing view of Elasticsearch: how the cluster appears to an attacker or auditor on the wire, and which weakness classes dominate its record. The controls that defend against them are in the "Security and hardening" section that follows.

### Where it appears

- The data tier for search, log analytics, observability, and SIEM data, reached through the REST API on port 9200 with the transport protocol on 9300, and often holding the most sensitive operational data a team keeps.
- Fingerprinted by a `GET /` on 9200, which returns a version JSON document with the project tagline, and by the `_cat` APIs. `curl` and Nmap are enough to recognize and enumerate an open cluster.
- Targeted by general tooling against 9200, Metasploit modules, and bulk `_search` dumps; Kibana and the audit log are the defensive and investigation tools written for it. The supply-chain surface is the Java runtime, Lucene, and installed plugins.

### Dominant weakness classes

Elasticsearch is a mature Java server hardened against memory corruption in normal use, so the practical risks are access control and query or script injection reaching the engine.

- Missing authentication ([CWE-306](https://cwe.mitre.org/data/definitions/306.html)) from clusters left open on 9200 with security disabled, the cause of the recurring waves of exposed and ransomed Elasticsearch data on the public internet.
- NoSQL and data-query injection ([CWE-943](https://cwe.mitre.org/data/definitions/943.html)) when the Query DSL is built from untrusted input, letting an attacker change query logic.
- Code injection ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)) through dynamic scripting in `script` queries, a feature whose sandbox has historically been escaped to reach code execution.
- Information exposure ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) when an unauthenticated or over-permissioned reader dumps whole indices.

### Why it matters

Recognizing the 9200 banner tells a practitioner what to try: whether security was ever enabled, whether indices can be dumped unauthenticated, and whether scripting is open. Each maps to a control the defender owns: set `xpack.security.enabled`, require TLS, scope roles and API keys per index, and keep the cluster off the public internet. See [the database security reference](/DATABASE_SECURITY_REFERENCE.md) for the engine-agnostic hardening checklist.

## Security and hardening

Historically the Elastic security features were not enabled by default. Many clusters ran open on the network with no authentication, which exposed data to anyone who could reach port `9200`. This caused a long series of public data leaks and maps to CWE-306, missing authentication for a critical function. Recent default distributions enable security on startup, but operators must confirm it rather than assume it.

Enable authentication and TLS in `elasticsearch.yml`, then set passwords for the built-in users.

```
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true
```

Use role-based access control to grant least privilege. Define roles that limit index access and cluster actions, then map users or API keys to them. Prefer API keys for applications and services, scoped to only the indices they need, and rotate them.

```
POST /_security/api_key
{
  "name": "log-ingest",
  "role_descriptors": {
    "writer": { "index": [ { "names": ["logs-*"], "privileges": ["create_doc"] } ] }
  }
}
```

Query injection is a real risk when the Query DSL is built from untrusted input. Concatenating user text into a query body, or passing raw input into a `script` query, can let an attacker change query logic or run expressions. This is CWE-943, improper neutralization of data within a query. Build queries with fixed structure and insert user values only into value positions, never into field names or operators, and avoid dynamic scripting on user input.

Do not place the cluster directly on the public internet. Bind it to private interfaces, put a reverse proxy or gateway in front, and encrypt data at rest on the underlying storage to address CWE-312, cleartext storage of sensitive information. See /SECURE_CODING_REFERENCE.md for query construction and secret handling guidance.

## Performance and scaling

Shard count drives scaling. Too few shards limit parallelism; too many create overhead from many small Lucene indices. Size primary shards in the tens of gigabytes and use ILM rollover rather than one ever-growing index. Add nodes to spread shards and increase throughput.

Replicas improve read capacity and availability but cost storage and indexing work. Mappings matter for performance: avoid indexing fields you never query, and use `keyword` instead of `text` for fields used only for filtering or aggregation. Bulk indexing with the `_bulk` API is far faster than one request per document. Filters are cached and should carry the non-scoring parts of a query.

## Resources

- Elasticsearch Guide (official documentation)
- Elasticsearch Reference, the REST API and Query DSL reference

## Related pages

- [Databases](/databases/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [ClickHouse](/databases/clickhouse.md)
- [MongoDB](/databases/mongodb.md)
- [Redis](/databases/redis.md)
