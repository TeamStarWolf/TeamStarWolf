# FAISS

> In one minute: FAISS (Facebook AI Similarity Search) is an open-source C++ library with Python bindings for fast similarity search and clustering of dense vectors, including on GPUs. Researchers and engineers embed it inside applications and frameworks to search millions or billions of vectors in memory. It is a library, not a database server: it has no users, authentication, or network layer, so every security control belongs to the application that wraps it.

| | |
|---|---|
| Category | Vector search library |
| Maintainer | Meta (Fundamental AI Research) |
| License / access | Open source (MIT) |
| Official docs | [faiss.ai](https://faiss.ai/) |
| Repository | [facebookresearch/faiss](https://github.com/facebookresearch/faiss) |
| Checked | 8 Oct 2026, v1.15.1 (released 15 Sep 2026) |

## What it is for

- Nearest-neighbor search over embeddings inside an application, notebook, or batch job.
- Building the retrieval index behind RAG prototypes and research experiments.
- Searching very large collections with compressed indexes that fit in RAM.
- GPU-accelerated exact and approximate search, and k-means clustering.
- Benchmarking index types to choose a speed, memory, and accuracy trade-off.

## Quick start

1. Install with conda, the supported method. The CPU package covers Linux (x86-64 and aarch64), macOS (arm64), and Windows (x86-64); the GPU package is Linux x86-64 only.

   ```shell
   # CPU-only version
   conda install -c pytorch -c conda-forge faiss-cpu=1.15.1

   # GPU(+CPU) version
   conda install -c pytorch -c nvidia -c conda-forge faiss-gpu=1.15.1
   ```

2. Create sample data:

   ```python
   import numpy as np
   d = 64                           # dimension
   nb = 100000                      # database size
   nq = 10000                       # nb of queries
   np.random.seed(1234)             # make reproducible
   xb = np.random.random((nb, d)).astype('float32')
   xb[:, 0] += np.arange(nb) / 1000.
   xq = np.random.random((nq, d)).astype('float32')
   xq[:, 0] += np.arange(nq) / 1000.
   ```

3. Build an exact index, add vectors, and search:

   ```python
   import faiss                   # make faiss available
   index = faiss.IndexFlatL2(d)   # build the index
   print(index.is_trained)
   index.add(xb)                  # add vectors to the index
   print(index.ntotal)

   k = 4                          # we want to see 4 nearest neighbors
   D, I = index.search(xq, k)     # actual search
   ```

4. For faster approximate search, train an inverted-file index:

   ```python
   nlist = 100
   quantizer = faiss.IndexFlatL2(d)  # the other index
   index = faiss.IndexIVFFlat(quantizer, d, nlist)
   index.train(xb)
   index.add(xb)                  # add may be a bit slower as well
   index.nprobe = 10              # default nprobe is 1, try a few more
   D, I = index.search(xq, k)
   ```

## Key concepts

- **Index**: the core object that stores vectors and answers searches by L2 distance or inner product. Cosine similarity is inner product on normalized vectors.
- **IDs**: vectors are identified by integers. Flat indexes do not support `add_with_ids`; wrap them in `IndexIDMap` to supply your own IDs.
- **Exact indexes**: `IndexFlatL2` and `IndexFlatIP` compare the query with every vector.
- **Training**: IVF and product quantization (PQ) indexes must be trained on representative data before vectors are added.
- **IVF**: partitions vectors into `nlist` cells and searches the `nprobe` nearest cells (default 1).
- **HNSW and compression**: `IndexHNSWFlat` is graph-based; `IndexPQ`, `IndexIVFPQ`, and `IndexScalarQuantizer` store compact codes to save memory.
- **Index factory**: `index_factory(128, "PCA80,Flat")` builds an index from a description string; components include `Flat`, `IVF4096`, `HNSW32`, and `PQ16`.
- **GPU indexes**: drop-in GPU versions, such as `GpuIndexFlatL2`, accept data from CPU or GPU memory.

## Security notes

- **No built-in access control.** FAISS runs inside your process. Any service that exposes FAISS search must add its own authentication, authorization, rate limits, and tenant separation.
- **Never load untrusted index files.** The [index I/O guide](https://github.com/facebookresearch/faiss/wiki/Index-IO,-cloning-and-hyper-parameter-tuning) states that no attempt is made to check loaded data. A faulty or malicious file can trigger out-of-memory errors and, if crafted expertly, code execution. Verify the source and integrity (for example, a known hash) of any file passed to `read_index` or `deserialize_index`, and store index files where only the service can write them.
- **Wrappers add their own risks.** [CVE-2024-5998](https://nvd.nist.gov/vuln/detail/CVE-2024-5998) (CVSS 7.8) affected LangChain's `FAISS.deserialize_from_bytes`, which deserialized untrusted data unsafely and allowed command execution. Treat any saved vector store bundle (index plus document store) as executable input.
- **Isolate tenants in the application.** [CVE-2026-13442](https://nvd.nist.gov/vuln/detail/CVE-2026-13442) (CVSS 7.1) in IBM Langflow let one user reuse another user's FAISS namespace, read owner-only content, and poison later results. Keep a separate index per tenant, or enforce ownership checks on every lookup.
- **Index files contain your data.** Flat and HNSW-Flat indexes store full vectors, and research shows text can be reconstructed from embeddings ([vec2text](https://arxiv.org/abs/2310.06816) recovered 92% of 32-token inputs exactly). Protect index files and backups like the source documents. See OWASP [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) and the [AI Security Reference](/AI_SECURITY_REFERENCE.md).
- **Known issues**: an NVD keyword search on 8 Oct 2026 found CVEs only in projects that wrap FAISS, not in FAISS itself, and the repository had no published security advisories.
- Related: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) covers unsafe model and artifact deserialization in more depth.

## Learn more

- [Getting started](https://github.com/facebookresearch/faiss/wiki/Getting-started): the first index and search.
- [Faster search](https://github.com/facebookresearch/faiss/wiki/Faster-search): IVF indexes, training, and `nprobe`.
- [Faiss indexes](https://github.com/facebookresearch/faiss/wiki/Faiss-indexes): every index type and its factory string.
- [Guidelines to choose an index](https://github.com/facebookresearch/faiss/wiki/Guidelines-to-choose-an-index): picking an index by size and memory.
- [Index I/O](https://github.com/facebookresearch/faiss/wiki/Index-IO,-cloning-and-hyper-parameter-tuning): saving, loading, and tuning indexes.
- [Install guide](https://github.com/facebookresearch/faiss/blob/main/INSTALL.md): conda, Pixi, and source builds.
