# Chroma

> In one minute: Chroma is an open-source vector database that stores documents, embeddings, and metadata and returns the most similar items for a query. Developers use it as the retrieval layer for RAG apps and agents, from an in-process notebook client up to a server or the hosted Chroma Cloud. Since version 1.0 the open-source server has no built-in authentication, so access control is your job.

| | |
|---|---|
| Category | Vector database |
| Maintainer | Chroma (chroma-core on GitHub) |
| License / access | Open source (Apache-2.0); hosted Chroma Cloud also available |
| Official docs | [docs.trychroma.com](https://docs.trychroma.com/docs/overview/getting-started) |
| Repository | [chroma-core/chroma](https://github.com/chroma-core/chroma) |
| Checked | 8 Oct 2026, 1.5.9 (latest `chromadb` release on PyPI, 5 May 2026) |

## What it is for

- Storing document chunks and their embeddings for retrieval-augmented generation (RAG).
- Semantic search over text, with metadata filters and full-text search.
- Giving agents long-term memory that persists between sessions.
- Prototyping retrieval in a notebook with an in-memory client, then moving to a server.
- Comparing embedding models and retrieval settings on the same data.

## Quick start

1. Install the Python package:

   ```bash
   pip install chromadb
   ```

   For JavaScript or TypeScript: `npm install chromadb @chroma-core/default-embed`.

2. Create a client and a collection, add documents, and query:

   ```python
   import chromadb
   chroma_client = chromadb.Client()

   collection = chroma_client.create_collection(name="my_collection")

   collection.add(
       ids=["id1", "id2"],
       documents=[
           "This is a document about pineapple",
           "This is a document about oranges"
       ]
   )

   results = collection.query(
       query_texts=["This is a query document about hawaii"], # Chroma will embed this for you
       n_results=2 # how many results to return
   )
   print(results)
   ```

3. To keep data on disk, use `chromadb.PersistentClient(path="/path/to/save/to")`.

4. To run Chroma as a server (default `localhost:8000`) and connect over HTTP:

   ```bash
   chroma run --path /db_path
   ```

   ```python
   import chromadb
   chroma_client = chromadb.HttpClient(host='localhost', port=8000)
   ```

   Or use Docker:

   ```bash
   docker run -v ./chroma-data:/data -p 8000:8000 chromadb/chroma
   ```

## Key concepts

- **Clients**: `Client()` (in-memory), `PersistentClient` (local files), `HttpClient` and `AsyncHttpClient` (remote server), and `CloudClient` (Chroma Cloud, with an API key).
- **Collection**: a named store of IDs, documents, embeddings, and metadata. Names must be unique within a database.
- **Embedding function**: turns text into vectors. The default uses the Sentence Transformers `all-MiniLM-L6-v2` model, runs locally, and downloads its model files on first use. Hosted providers (OpenAI, Cohere, and others) can be plugged in.
- **Query and get**: `query` finds nearest neighbors for query text or vectors; `get` fetches by ID or filter.
- **Metadata filtering**: `where` clauses narrow results by metadata, and full-text search filters on document content.
- **Tenants and databases**: the server API organizes collections into databases that belong to tenants.
- **Deployment modes**: single-node local Chroma and distributed Chroma (which Chroma Cloud runs) use different storage subsystems.
- **Server config**: a YAML file sets port, persist path, CORS origins, and `allow_reset` (default `false`).

## Security notes

- **No built-in authentication.** The [migration log](https://docs.trychroma.com/docs/overview/migration) states that from v1.0.0 "Chroma no longer provides built-in authentication implementations." Any client that reaches the port can read, write, and delete collections. `chroma run` binds to `localhost` by default; keep it there, or put an authenticating reverse proxy with TLS in front. In Docker, publish to loopback only, for example `-p 127.0.0.1:8000:8000`.
- **Keep `allow_reset` off.** With reset allowed, a single client call empties the whole database.
- **[CVE-2026-45829](https://nvd.nist.gov/vuln/detail/CVE-2026-45829)** (CVSS 10.0): in the Python FastAPI server from 1.0.0, a create-collection request can name a malicious Hugging Face embedding model with `trust_remote_code` set, and the server loads it before checking authentication. [HiddenLayer](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth) reports that the Rust server used by `chroma run` and the Docker images is not affected. The upstream [issue](https://github.com/chroma-core/chroma/issues/6717) was still open on 8 Oct 2026. Do not expose the Python server to untrusted clients.
- **Tenants are not a hard boundary.** [CVE-2026-45830](https://nvd.nist.gov/vuln/detail/CVE-2026-45830) (Python) and [CVE-2026-8828](https://nvd.nist.gov/vuln/detail/CVE-2026-8828) (Rust) let any authenticated user read or change another tenant's collection given its UUID. No fixed version was listed when checked. For strict separation, use separate instances per tenant or enforce access in your application layer, and treat collection IDs as sensitive.
- **Embeddings leak content.** Research has shown text can be reconstructed from embeddings: [vec2text](https://arxiv.org/abs/2310.06816) recovered 92% of 32-token inputs exactly. Protect the persist directory, volumes, and backups as you would the source documents. OWASP tracks these risks as [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/); see the [AI Security Reference](/AI_SECURITY_REFERENCE.md).
- **Guard the ingest path.** Anyone who can add documents can plant content that later reaches a model's prompt (RAG poisoning). Validate sources and log writes.
- **Hosted embedding functions send your text out.** Provider-based embedding functions transmit document and query text to that provider; the default model runs locally.
- Related library pages: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md).

## Learn more

- [Getting started](https://docs.trychroma.com/docs/overview/getting-started): install and first query.
- [Chroma clients](https://docs.trychroma.com/docs/run-chroma/clients): in-memory, persistent, HTTP, and Cloud clients.
- [Client-server mode](https://docs.trychroma.com/docs/run-chroma/client-server): running and connecting to a server.
- [Docker deployment](https://docs.trychroma.com/guides/deploy/docker): container setup and YAML configuration.
- [Embedding functions](https://docs.trychroma.com/docs/embeddings/embedding-functions): the default model and provider integrations.
- [Metadata filtering](https://docs.trychroma.com/docs/querying-collections/metadata-filtering): `where` filters and operators.
