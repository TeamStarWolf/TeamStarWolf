# Qdrant

> In one minute: Qdrant is an open-source vector database and similarity search engine written in Rust, with REST and gRPC APIs and official clients for several languages. Teams use it as the retrieval store behind RAG, semantic search, and recommendation systems, self-hosted or as Qdrant Cloud. Its own docs warn that a self-hosted deployment is not secure by default, so authentication, TLS, and network binding need deliberate setup.

| | |
|---|---|
| Category | Vector database |
| Maintainer | Qdrant (qdrant on GitHub) |
| License / access | Open source (Apache-2.0); managed Qdrant Cloud also available |
| Official docs | [qdrant.tech](https://qdrant.tech/documentation/) |
| Repository | [qdrant/qdrant](https://github.com/qdrant/qdrant) |
| Checked | 8 Oct 2026, v1.19.2 (released 5 Oct 2026) |

## What it is for

- Storing embeddings with JSON payloads for RAG retrieval and semantic search.
- Filtered vector search, such as "similar documents, but only from this department."
- Serving many tenants from one collection using payload-based partitioning.
- Recommendation and matching workloads that need nearest-neighbor lookups at scale.
- Running a distributed cluster with sharding and replication for large datasets.

## Quick start

1. Pull and run the server. REST listens on port 6333, gRPC on 6334, and the web UI is at `localhost:6333/dashboard`.

   ```bash
   docker pull qdrant/qdrant
   docker run -p 6333:6333 -p 6334:6334 \
       -v "$(pwd)/qdrant_storage:/qdrant/storage:z" \
       qdrant/qdrant
   ```

   On Windows, a named Docker volume may be needed instead of a folder mount.

2. Install the Python client:

   ```bash
   pip install qdrant-client
   ```

3. Connect, create a collection, add points, and search:

   ```python
   from qdrant_client import QdrantClient
   from qdrant_client.models import Distance, VectorParams, PointStruct

   client = QdrantClient(url="http://localhost:6333")

   client.create_collection(
       collection_name="test_collection",
       vectors_config=VectorParams(size=4, distance=Distance.DOT),
   )

   operation_info = client.upsert(
       collection_name="test_collection",
       wait=True,
       points=[
           PointStruct(id=1, vector=[0.05, 0.61, 0.76, 0.74], payload={"city": "Berlin"}),
           PointStruct(id=2, vector=[0.19, 0.81, 0.75, 0.11], payload={"city": "London"}),
           PointStruct(id=3, vector=[0.36, 0.55, 0.47, 0.94], payload={"city": "Moscow"}),
       ],
   )

   search_result = client.query_points(
       collection_name="test_collection",
       query=[0.2, 0.1, 0.9, 0.7],
       with_payload=False,
       limit=3
   ).points

   print(search_result)
   ```

4. For tests without a server, the Python client also has a local mode: `QdrantClient(":memory:")` or `QdrantClient(path="path/to/db")`.

## Key concepts

- **Collection**: a named set of points that share a vector configuration (size and distance metric).
- **Point**: the stored record, made of an ID, one or more vectors, and an optional JSON payload.
- **Payload and filters**: payload fields can be indexed and used in `must`, `should`, and `must_not` filter conditions alongside vector search.
- **Indexes**: HNSW is Qdrant's dense vector index; payload indexes speed up filtering and should be created before the HNSW index is built.
- **Multitenancy**: the recommended pattern is one collection with a tenant field (for example `group_id`) indexed with `is_tenant: true`, and a tenant filter on every query.
- **Snapshots**: `tar` archives of a collection's data and configuration, used for backup, migration, and recovery (including from a URL).
- **Distributed mode**: shards and replicas spread across nodes that talk over an internal gRPC port (6335).

## Security notes

- **Not secure by default.** The [security guide](https://qdrant.tech/documentation/security/) says self-hosted open-source deployments "are not secure by default and are not production-ready": no authentication and no encryption. For local work bind to loopback (`service.host: 127.0.0.1` or `docker run -p 127.0.0.1:6333:6333`); in production bind to a private interface.
- **Turn on API keys and TLS together.** Set `service.api_key` (or `QDRANT__SERVICE__API_KEY`), and optionally a `service.read_only_api_key`. Enable TLS with `service.enable_tls: true`, because an API key sent over plain HTTP can be sniffed. `service.alt_api_key` (1.17.0+) supports key rotation.
- **Use JWT RBAC for least privilege.** With `service.jwt_rbac: true`, tokens signed with the API key can grant global or per-collection read (`r`) or read-write (`rw`) access and carry an expiry. Changing the API key invalidates all tokens. Give each application the narrowest token instead of the admin key.
- **Tenant filters are only as strong as the caller.** Payload-based multitenancy depends on the application adding the tenant filter to every request; a client with direct access to the collection can omit it. Use per-collection JWT access or separate collections where tenants need strict isolation, as the multitenancy guide advises.
- **Lock down cluster traffic.** Internal gRPC (port 6335) has no key or token check by default. Enable `service.enforce_internal_auth` (1.18.0+) and `cluster.p2p.enable_tls`, and never expose 6335 publicly. [GHSA-3gph-6c29-p29v](https://github.com/qdrant/qdrant/security/advisories/GHSA-3gph-6c29-p29v) (high) showed the internal API accepting read-only keys and JWTs, letting their holders add cluster peers and write; fixed in 1.19.2.
- **File-handling CVEs**: [CVE-2024-3829](https://nvd.nist.gov/vuln/detail/CVE-2024-3829) (CVSS 9.1) allowed arbitrary file read and write through symlinks in uploaded snapshots (fixed in 1.9.0). [CVE-2026-25628](https://github.com/qdrant/qdrant/security/advisories/GHSA-f632-vm87-2m2f) (CVSS 8.5) let a read-only caller append to arbitrary files through the `/logger` endpoint (fixed in 1.15.6 per the advisory).
- **Harden the container.** Use the `-unprivileged` image or a non-root user, a read-only root filesystem with volumes for storage and snapshots, and block outbound traffic to limit SSRF through snapshot recovery. Audit logging is off by default.
- **Embeddings leak content.** Stored vectors can be inverted to recover text ([vec2text](https://arxiv.org/abs/2310.06816)), so protect storage, snapshots, and backups like the source data. See OWASP [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) and the [AI Security Reference](/AI_SECURITY_REFERENCE.md) and [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).

## Learn more

- [Quickstart](https://qdrant.tech/documentation/quickstart/): run the container and make the first search.
- [Security](https://qdrant.tech/documentation/security/): API keys, JWT RBAC, TLS, network binding, and hardening.
- [Multitenancy](https://qdrant.tech/documentation/manage-data/multitenancy/): payload partitioning and tenant sharding.
- [Filtering](https://qdrant.tech/documentation/search/filtering/): filter conditions and payload indexes.
- [Snapshots](https://qdrant.tech/documentation/snapshots/): backup, restore, and recovery priorities.
- [Client libraries](https://qdrant.tech/documentation/interfaces/): Python, JavaScript, Rust, Go, .NET, and Java.
