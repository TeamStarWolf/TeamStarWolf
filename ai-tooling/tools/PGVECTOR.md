# pgvector

> In one minute: pgvector is an open-source PostgreSQL extension that adds vector data types, distance operators, and approximate nearest-neighbor indexes to Postgres. Teams use it to keep embeddings next to their relational data, so RAG and semantic search can use SQL, joins, transactions, and existing backups. It has no security model of its own: it inherits PostgreSQL authentication, roles, and row-level security.

| | |
|---|---|
| Category | Vector database |
| Maintainer | pgvector project (pgvector on GitHub) |
| License / access | Open source (PostgreSQL License) |
| Official docs | [github.com](https://github.com/pgvector/pgvector) |
| Repository | [pgvector/pgvector](https://github.com/pgvector/pgvector) |
| Checked | 8 Oct 2026, v0.8.7 (released 1 Oct 2026) |

## What it is for

- Storing embeddings in the same Postgres database as the rows they describe.
- Exact and approximate nearest-neighbor search with plain SQL (`ORDER BY ... LIMIT`).
- Combining vector search with `WHERE` filters, joins, and full-text search (hybrid search).
- Reusing Postgres operations you already run: replication, point-in-time recovery, and ACID transactions.
- Storing single-precision, half-precision, binary, and sparse vectors.

## Quick start

1. Install the extension (Postgres 13 or later).

   Linux and macOS, from source:

   ```sh
   cd /tmp
   git clone --branch v0.8.7 https://github.com/pgvector/pgvector.git
   cd pgvector
   make
   make install # may need sudo
   ```

   Packages are also available, for example `brew install pgvector` (Homebrew Postgres) or `sudo apt install postgresql-18-pgvector` (PostgreSQL APT repository; replace `18` with your server version). A Docker image adds pgvector to the official Postgres image: `docker pull pgvector/pgvector:pg18-trixie`. On Windows, build with `nmake /F Makefile.win` from a Visual Studio x64 Native Tools prompt.

2. Enable it once in each database that will use it:

   ```sql
   CREATE EXTENSION vector;
   ```

3. Create a table, insert vectors, and find nearest neighbors by L2 distance:

   ```sql
   CREATE TABLE items (id bigserial PRIMARY KEY, embedding vector(3));
   INSERT INTO items (embedding) VALUES ('[1,2,3]'), ('[4,5,6]');
   SELECT * FROM items ORDER BY embedding <-> '[3,1,2]' LIMIT 5;
   ```

4. Add an approximate index when exact search gets slow:

   ```sql
   CREATE INDEX ON items USING hnsw (embedding vector_l2_ops);
   ```

5. After installing a newer version, update each database and confirm:

   ```sql
   ALTER EXTENSION vector UPDATE;
   SELECT extversion FROM pg_extension WHERE extname = 'vector';
   ```

## Key concepts

- **Types**: `vector` (indexable up to 2,000 dimensions), `halfvec` (up to 4,000), `bit` (up to 64,000), and `sparsevec` (up to 1,000 non-zero elements).
- **Distance operators**: `<->` L2, `<#>` negative inner product, `<=>` cosine distance, and `<+>` L1, plus Hamming and Jaccard for binary vectors.
- **Exact by default**: without an index, pgvector does exact search with perfect recall. Approximate indexes trade some recall for speed.
- **HNSW index**: a multilayer graph with better speed-recall than IVFFlat, but slower builds and more memory; it can be built on an empty table.
- **IVFFlat index**: divides vectors into `lists` and searches the nearest `probes`; build it after loading data.
- **Filtering**: with approximate indexes, `WHERE` filters apply after the index scan, which can return fewer rows; iterative index scans (0.8.0+) keep scanning until enough rows match.
- **Partitioning**: list partitioning or partial indexes keep each filter value or tenant in its own index.

## Security notes

- **Security comes from PostgreSQL.** pgvector adds no listener or login of its own. PostgreSQL's `listen_addresses` defaults to `localhost` and `ssl` defaults to `off`, so review [connection settings](https://www.postgresql.org/docs/current/runtime-config-connection.html) and [pg_hba.conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) and enable TLS before allowing remote clients.
- **Use least-privilege roles.** Give the RAG application a role that can only read the tables it searches, and a separate role for ingestion. Limit who can create tables and indexes, since the CVEs below are triggered by a database user building an index.
- **Separate tenants deliberately.** The README recommends list partitioning or separate tables for tenant isolation, because tenants sharing one approximate index affect each other's recall. For access control, use [row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html): with RLS enabled and no policy, no rows are visible. Superusers and `BYPASSRLS` roles always bypass RLS, and table owners do too unless you set `FORCE ROW LEVEL SECURITY`.
- **[CVE-2026-3172](https://nvd.nist.gov/vuln/detail/CVE-2026-3172)** (CVSS 8.1): a buffer overflow in parallel HNSW index builds (0.6.0 through 0.8.1) let a database user leak data from other relations or crash the server. Fixed in 0.8.2.
- **[CVE-2026-103484](https://nvd.nist.gov/vuln/detail/CVE-2026-103484)** (CVSS 8.8): an out-of-bounds write in IVFFlat index builds before 0.8.7 can lead to arbitrary code execution. A related integer wraparound, [CVE-2026-18022](https://nvd.nist.gov/vuln/detail/CVE-2026-18022), affected 32-bit systems before 0.8.6. Upgrade the package, then run `ALTER EXTENSION vector UPDATE` in every database.
- **Embeddings leak content.** Text can be reconstructed from embeddings ([vec2text](https://arxiv.org/abs/2310.06816) recovered 92% of 32-token inputs exactly), so vector columns, replicas, dumps, and backups deserve the same protection as the source text. See OWASP [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) and the [AI Security Reference](/AI_SECURITY_REFERENCE.md).
- **Guard the ingest path.** Rows inserted into an embedding table can end up in a model's prompt, so validate sources and audit writes to limit RAG poisoning. Related: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).

## Learn more

- [pgvector README](https://github.com/pgvector/pgvector): installation, indexing, filtering, tuning, and FAQ.
- [Changelog](https://github.com/pgvector/pgvector/blob/master/CHANGELOG.md): release notes, including security fixes.
- [Docker image](https://hub.docker.com/r/pgvector/pgvector): supported tags by Postgres version.
- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html): RLS behavior and bypass rules.
- [PostgreSQL client authentication](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html): configuring `pg_hba.conf`.
