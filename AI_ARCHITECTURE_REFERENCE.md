# AI / ML System Architecture

> In one minute: This is the builder's reference for designing AI/ML and LLM systems end to end: data and feature pipelines, the split between the training plane and the inference plane, the model registry and versioning backbone, model-serving topologies (batch, online, streaming), Retrieval-Augmented Generation (RAG), agentic architectures and the Model Context Protocol (MCP), MLOps/LLMOps, the evaluation and guardrail layers, and GPU/accelerator scaling and cost. It pairs each design choice with its trade-offs and — because this is a security library — with the threat-informed controls that make the architecture defensible. Good architecture here is not a luxury: most real-world AI compromises exploit *infrastructure* weaknesses (exposed inference servers, code-executing model loads, poisoned corpora), so the way you lay out planes, trust boundaries, and provenance *is* your first security control. Defensive deep-dives live in [AI_INFRASTRUCTURE_SECURITY_REFERENCE.md](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI_MCP_SECURITY_REFERENCE.md](AI_MCP_SECURITY_REFERENCE.md), and [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md); this page is the blueprint they protect.

| | |
|---|---|
| Read this when | designing a new ML platform or LLM/RAG/agent application, reviewing an AI reference architecture, deciding train-vs-buy / serving topology / RAG vs fine-tune, standing up MLOps/LLMOps, or preparing an AI architecture review board |
| Start at | [Principles & Drivers](#_1-principles-drivers), [Reference Architectures & Patterns](#_2-reference-architectures-patterns), [Key Design Decisions & Trade-offs](#_4-key-design-decisions-tradeoffs), [Maturity & Checklist](#_8-maturity-checklist) |
| Pairs with | [AI_INFRASTRUCTURE_SECURITY_REFERENCE.md](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI_MCP_SECURITY_REFERENCE.md](AI_MCP_SECURITY_REFERENCE.md), [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md), [AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md), [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md), [SECURITY_ARCHITECTURE_REFERENCE.md](SECURITY_ARCHITECTURE_REFERENCE.md), [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md) |

*Standards and tool names verified against primary sources on 2026-10-08: MCP spec current revision **2025-11-25** ([modelcontextprotocol.io](https://modelcontextprotocol.io/)); OWASP Top 10 for LLM Applications **2025 (v2.0)** ([genai.owasp.org](https://genai.owasp.org/)); OWASP Top 10 for Agentic Applications **2026**; NIST AI RMF (AI 100-1) + Generative AI Profile **NIST AI 600-1** (July 2024); ISO/IEC 42001:2023; MITRE ATLAS (16 tactics). Where a version may have moved since, the text says "verify".*

---

## Table of Contents

1. [Principles & Drivers](#_1-principles-drivers)
2. [Reference Architectures & Patterns](#_2-reference-architectures-patterns)
3. [Building Blocks / Domains](#_3-building-blocks-domains)
4. [Key Design Decisions & Trade-offs](#_4-key-design-decisions-tradeoffs)
5. [Security-by-Design Integration](#_5-security-by-design-integration)
6. [Standards & Frameworks](#_6-standards-frameworks)
7. [Anti-Patterns & Pitfalls](#_7-anti-patterns-pitfalls)
8. [Maturity & Checklist](#_8-maturity-checklist)
9. [Tools & Further Reading](#_9-tools-further-reading)

---

## 1. Principles & Drivers

### 1.1 What makes AI architecture different

Classical software architecture reasons about deterministic code over data. AI systems add three properties that break those assumptions, and every pattern below exists to manage them:

| Property | Consequence for architecture |
|---|---|
| **Behavior is learned, not written** | Correctness is statistical; you need evaluation and monitoring as first-class planes, not afterthoughts. Models drift as the world changes. |
| **Data and models are executable and trusted** | A model artifact (`.pkl`, `.pt`, `.keras`) can run code on load; a retrieved document can carry instructions. Your "data" is now an attack surface. See [AI_INFRASTRUCTURE_SECURITY §2](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md). |
| **Compute is the dominant cost and constraint** | GPUs/accelerators are scarce, expensive, and shape every topology decision (batching, quantization, caching, placement). |
| **Non-determinism & emergent behavior** | Same input → different output; agents compose tools in ways you did not script. Reproducibility and guardrails must be engineered. |

### 1.2 Architectural quality attributes (the drivers)

Prioritize these explicitly — they conflict, and the conflicts drive every ADR in §4.

- **Correctness / quality** — task accuracy, groundedness (for RAG), factuality, calibration. Measured by the evaluation plane (§3.7).
- **Latency** — time-to-first-token (TTFT) and inter-token latency for streaming LLMs; p50/p95/p99 for request/response.
- **Throughput & scalability** — tokens/sec and requests/sec per GPU; ability to scale horizontally and absorb bursts.
- **Cost efficiency** — $/1k tokens, $/inference, GPU utilization. Often the binding constraint at scale.
- **Reproducibility & lineage** — rebuild any prediction from pinned data + code + config + model version. Prerequisite for debugging, audit, and rollback.
- **Observability** — traces, metrics, evals, and feedback across both planes.
- **Security, privacy & safety** — confidentiality/integrity/availability of data, models, and prompts; tenant isolation; guardrails; governance. Woven through §5.
- **Governance & compliance** — provenance, documentation (model/data cards), approvals, and regulatory mapping (§6).
- **Maintainability & portability** — avoid lock-in to a single model/provider; isolate the volatile (prompts, models) from the stable (contracts, data).

### 1.3 Core design principles

1. **Separate planes.** Keep the *training/build plane* (experimentation, data prep, training, registration) architecturally distinct from the *inference/serving plane* (low-latency, high-availability, hostile-network-facing). They have opposite requirements and opposite trust postures.
2. **Treat models as governed artifacts, not code deploys.** Everything that reaches production passes through a registry with versioning, provenance, and approval. No model enters serving without a signed, scanned, lineage-linked record (§3.3).
3. **Pin everything; make runs reproducible.** Data snapshots/versions, feature definitions, hyperparameters, base model + adapter, and container digests are all pinned. "It works on the notebook" is not an architecture.
4. **Design trust boundaries around untrusted content.** Prompts, retrieved documents, tool outputs, and model outputs are all untrusted until proven otherwise. Draw boundaries where the [prompt-injection](AI_SECURITY_REFERENCE.md) threat crosses them.
5. **Prefer retrieval and context over retraining when knowledge changes.** RAG and context engineering update knowledge without a training cycle; reserve fine-tuning for behavior/format/skill, not fresh facts (§4).
6. **Make evaluation a gate, not a report.** Offline evals gate promotion; online evals gate rollout (canary); guardrails gate every request/response.
7. **Keep humans in the loop proportionate to blast radius.** The more agency and the more irreversible the action, the more approval and sandboxing. Directly mitigates OWASP LLM06 *Excessive Agency* and ATLAS agent abuse.
8. **Engineer for cost from day one.** Caching, batching, routing to the smallest sufficient model, and quantization are architecture, not optimization you bolt on later.

---

## 2. Reference Architectures & Patterns

### 2.1 The two planes (canonical ML platform)

```
                         ┌────────────────────────── GOVERNANCE & OBSERVABILITY ──────────────────────────┐
                         │  Lineage · Model/Data cards · Policy gates · Audit · Metrics · Traces · Evals   │
                         └───────────────────────────────────────────────────────────────────────────────┘
   ┌──────────────────── TRAINING / BUILD PLANE ────────────────────┐   ┌──────────── INFERENCE / SERVING PLANE ────────────┐
   │                                                                 │   │                                                    │
   │  Sources ─▶ Ingestion ─▶ Data Lake/  ─▶ Feature  ─▶ Training ─▶ │   │  Client ─▶ API GW ─▶ Guardrail ─▶ Orchestrator ─▶  │
   │  (apps,     (batch/      Lakehouse      Pipeline    / Fine-tune │   │  (app,     (authn/   (in: PI,     (routing,         │
   │   DBs,       stream)     (Bronze/       + Feature    + Eval     │   │   agent)    quota)    policy)     prompt, RAG)      │
   │   files,                 Silver/Gold)   Store)                  │   │                                        │           │
   │   web)                        │            │          │         │   │                                        ▼           │
   │                               ▼            ▼          ▼         │   │                                  Model Server(s)  │
   │                          Data/Feature  ──────▶  MODEL REGISTRY ─┼───┼──▶ (vLLM/Triton/KServe/…) + KV cache + accelerators│
   │                          versioning              (versioned,    │   │                                        │           │
   │                          (DVC/LakeFS/            signed, scanned,│   │                                        ▼           │
   │                           Delta/Iceberg)         lineage-linked) │   │  Guardrail (out) ─▶ Response + citations + trace   │
   └─────────────────────────────────────────────────────────────────┘   └────────────────────────────────────────────────┘
          ▲  offline eval gates promotion                                      ▲  online eval / canary gates rollout
          └──────────────────────────────  REGISTRY is the hand-off  ─────────┘   feedback & traces loop back to build plane
```

The **model registry is the single hand-off** between planes and the natural place to enforce policy: nothing serves that has not been registered, signed, scanned, and approved. This is the architectural chokepoint that defends against *ML Supply Chain Compromise* (ATLAS) and OWASP **LLM03 Supply Chain** / **LLM04 Data and Model Poisoning**.

### 2.2 Model-serving topologies

| Pattern | When to use | Latency | Notes / trade-offs |
|---|---|---|---|
| **Batch / offline** | Scoring large datasets, nightly jobs, embeddings backfill | Minutes–hours | Cheapest per item; use spot/pre-emptible capacity; no online SLA. |
| **Online / real-time (request-response)** | User-facing predictions, classic ML APIs | ms–low seconds | Autoscaled replicas behind a gateway; needs warm pools to avoid cold starts. |
| **Streaming (token streaming)** | Chat/LLM UX | TTFT-driven | Server-Sent Events / gRPC streaming; optimize TTFT and inter-token latency; continuous/in-flight batching. |
| **Micro-batch / near-real-time** | Feature freshness, fraud scoring | sub-second–seconds | Kafka/Flink/Spark Structured Streaming feeding an online store. |
| **Edge / on-device** | Privacy, offline, low latency | device-bound | Quantized/distilled models (GGUF, ONNX, Core ML, TFLite); data never leaves device — strong privacy control. |

LLM-serving engines add **continuous (in-flight) batching**, **PagedAttention / KV-cache management**, **prefix/prompt caching**, **speculative decoding**, and **tensor/pipeline parallelism**. Representative engines: **vLLM**, **SGLang**, **TensorRT-LLM**, **Hugging Face TGI**, **NVIDIA Triton**, **TorchServe**, **Ray Serve**, **KServe**, **Ollama**, **llama.cpp** (verify current versions). Harden these per [AI_INFRASTRUCTURE_SECURITY §8](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) — several ship insecure-by-default (no auth) and have had unauth-RCE CVEs.

### 2.3 RAG reference architecture

RAG grounds generation in retrieved context so the model answers from *your* data without retraining. Two subsystems: an **offline ingestion/indexing pipeline** and an **online retrieval+generation path**.

```
  OFFLINE  (ingestion / indexing)                         ONLINE  (query time)
  ┌───────────────────────────────────┐                  ┌──────────────────────────────────────────┐
  │ Sources (docs, wikis, DBs, APIs)   │                  │ User query                                 │
  │        │  trust + ACL capture      │                  │   │                                        │
  │        ▼                           │                  │   ▼  (optional) query rewrite / expand     │
  │ Loaders / parsers (PDF, HTML, …)   │                  │ Embed query ─▶ Vector + keyword search     │
  │        ▼                           │                  │   │             (hybrid: dense + BM25)      │
  │ Chunking (size/overlap/semantic)   │                  │   ▼                                        │
  │        ▼                           │                  │ Retrieve top-k ─▶ Re-rank (cross-encoder)  │
  │ Embed (embedding model) ───────────┼───┐              │   ▼                                        │
  │        ▼                           │   │              │ Assemble context (+ metadata/citations)    │
  │ Vector store + metadata/ACL index  │◀──┘ same store   │   ▼                                        │
  │ (Pinecone/Weaviate/Milvus/Qdrant/  │─────────────────▶│ Prompt template + guardrail (input)        │
  │  pgvector/Chroma)                  │                  │   ▼                                        │
  └───────────────────────────────────┘                  │ LLM generate ─▶ guardrail (output) ─▶ cite │
                                                          └──────────────────────────────────────────┘
```

Design levers that move quality the most, in rough order: **chunking strategy**, **hybrid retrieval (dense + sparse/BM25)**, **re-ranking**, **metadata filtering / query routing**, **context assembly & prompt**, and **groundedness/citation enforcement**. Advanced variants: **GraphRAG** (knowledge-graph-structured retrieval), **agentic / iterative RAG** (the model decides what to retrieve and when), **multi-hop**, and **contextual retrieval** (prepend chunk-level context before embedding).

**Security note woven in:** retrieved content is untrusted input — it is a primary **indirect prompt-injection** vector (ATLAS; OWASP **LLM01**). Carry **document-level ACLs into the vector store and enforce them at query time** so retrieval can never return data the caller cannot see; broken tenant/ACL isolation maps to OWASP **LLM08 Vector and Embedding Weaknesses** and **LLM02 Sensitive Information Disclosure**. See [AI_INFRASTRUCTURE_SECURITY §4–§5](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).

### 2.4 Agentic architecture & MCP

An **agent** is an LLM given a goal, memory, and tools, run in a loop (plan → act → observe → repeat). Composition patterns:

| Pattern | Shape | Use / caution |
|---|---|---|
| **Single agent + tools** | One LLM loop, tool calls | Simplest; cap iterations and tool scope. |
| **Router / supervisor** | A planner delegates to sub-agents | Good for separation of concerns; the supervisor is a trust chokepoint. |
| **Sequential / pipeline** | Fixed hand-off chain | Predictable; less flexible. |
| **Hierarchical / swarm** | Many agents, shared memory/board | Powerful and dangerous: horizontal technique diffusion, cascading failures (see [AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md)). |
| **Reflection / critic** | Generator + evaluator loop | Improves quality; adds cost/latency. |

```
  ┌────────────────────────────── AGENT RUNTIME ──────────────────────────────┐
  │  Goal/Task ─▶ Planner (LLM) ─▶ Policy/Guardrail ─▶ Tool Router              │
  │                   ▲                                   │                     │
  │                   │                                   ▼                     │
  │              Working memory ◀── Observations ◀── Tool execution (sandboxed) │
  │              (short-term)                             │                     │
  │                   ▲                                   ▼                     │
  │              Long-term memory                   MCP clients  ───────────────┼──▶ MCP servers
  │              (vector/store)                     (one per server)            │    (files, DB, SaaS, web,
  │                                                                             │     code-exec, internal APIs)
  └─────────────────────────────────────────────────────────────────────────────┘
```

**MCP (Model Context Protocol)** is the open, vendor-neutral standard (introduced by Anthropic, Nov 2024; current spec revision **2025-11-25** — verify) for connecting models/agents to tools and data via a **host → client → server** model. Architecturally it decouples capability providers (MCP servers) from the agent, which is excellent for modularity — and it widens the trust boundary: each server is remote code your agent will invoke. **Every tool is a privilege; every MCP server is a trust decision.** Enforce least-privilege scopes, human approval for irreversible/high-blast-radius actions, server allow-lists, and output treated as untrusted. Full threat model and hardening: [AI_MCP_SECURITY_REFERENCE.md](AI_MCP_SECURITY_REFERENCE.md). Agentic risk taxonomy: **OWASP Top 10 for Agentic Applications (2026)** — ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse, ASI05 Unexpected Code Execution, etc.

### 2.5 Buy / rent / build spectrum

```
  Fully managed API            Managed platform / fine-tune        Self-hosted open-weight         Train from scratch
  (OpenAI, Anthropic,     ◀──  (Bedrock, Vertex, Azure AI     ──▶  (Llama/Mistral/Qwen on     ──▶  (rare; frontier labs,
   Google via API)              Foundry, Databricks)                your vLLM/KServe cluster)         deep domain need)
  ─ fastest, least ops         ─ balance control/ops               ─ data residency, cost at         ─ maximal control + cost;
  ─ data leaves your estate      (still a 3rd-party trust           scale, no egress of data           months, large GPU fleet
    (contractual controls)       boundary)                         ─ you own the hardening
```

Most organizations should start right-to-left only as far as a requirement forces them: **start with a managed API, move to self-hosted open-weight when data residency, cost-at-scale, latency, or customization demands it, and fine-tune/pre-train only when retrieval + prompting provably cannot meet the need.**

---

## 3. Building Blocks / Domains

### 3.1 Data & feature pipelines

The foundation — model quality is bounded by data quality and freshness.

- **Ingestion:** batch (scheduled ELT) and streaming (CDC via Debezium/Kafka; events via Kafka/Kinesis/Pub/Sub). Capture **source, ACLs, and consent/lineage at ingest**, not later.
- **Storage:** data lake / **lakehouse** with medallion layering (Bronze raw → Silver cleaned → Gold curated). Open table formats **Delta Lake**, **Apache Iceberg**, **Apache Hudi** give ACID + time-travel (reproducibility).
- **Transformation / orchestration:** dbt for SQL transforms; **Airflow / Dagster / Prefect** for orchestration; Spark/Flink for scale.
- **Data versioning:** **DVC**, **LakeFS**, lakehouse time-travel — so a training run pins an exact snapshot.
- **Feature store (Feast, Tecton, Databricks/SageMaker/Vertex feature stores):** the contract between training and serving. Solves **train/serve skew** by serving the *same* feature definitions offline (training) and online (inference). Online store (Redis/DynamoDB) for low-latency reads; offline store (warehouse/lake) for training.
- **Data quality & contracts:** Great Expectations / Soda / dbt tests + schema contracts; validate at pipeline boundaries. Integrity failures here are **data poisoning** exposure (ATLAS *Poison Training Data*; OWASP LLM04).

### 3.2 Training & fine-tuning plane

- **Experimentation:** notebooks + experiment tracking (MLflow, Weights & Biases) — every run logs params, metrics, data version, code commit, environment.
- **Training:** distributed training (PyTorch DDP/FSDP, DeepSpeed, Megatron) for large models; data/tensor/pipeline parallelism.
- **LLM customization ladder (cheapest/most-reversible first):**
  1. **Prompt / context engineering** (no training)
  2. **RAG** (no training; updates knowledge)
  3. **PEFT / LoRA / QLoRA adapters** (hours, small GPU, swappable)
  4. **Full fine-tuning / instruction tuning** (days, larger fleet)
  5. **Preference optimization** (RLHF/DPO/RLAIF) for alignment/style
  6. **Continued pre-training / from scratch** (rare, large fleet)
- **Reproducibility:** pin base model + adapter + tokenizer + data snapshot + container digest.

### 3.3 Model registry & versioning

The governance backbone and the inter-plane hand-off.

- **What it stores:** versioned model artifacts + **metadata/lineage** (training data version, code commit, metrics, eval results), stage (staging/production/archived), approvals.
- **Tools:** **MLflow Model Registry** (MLflow 3 added GenAI tracing, a prompt registry, LLM-judge evaluation, and a `LoggedModel` lineage hub — verify), SageMaker/Vertex/Azure registries, Hugging Face Hub (for open-weight).
- **Security gates at the registry (chokepoint):**
  - **Provenance & signing** — sign model artifacts and verify on load (sigstore / `model-transparency`); generate an **SBOM / model card**.
  - **Malware & deserialization scanning** — scan `.pkl`/`.pt`/`.keras` for unsafe deserialization before promotion; **prefer `safetensors`** (see [AI_INFRASTRUCTURE_SECURITY §2–§3](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md)).
  - **Approval workflow** — human sign-off, immutable audit, and one-click **rollback** to the previous signed version.

### 3.4 Model serving / inference

- **Serving runtime:** containerized model servers (see §2.2) behind an **API gateway** (authn/z, rate limiting, quotas).
- **Scaling:** HPA/KEDA on GPU/queue metrics; **request queueing + continuous batching**; warm pools to kill cold starts; multi-model serving / model multiplexing to pack GPUs.
- **Optimization:** quantization (INT8/FP8/INT4, GPTQ/AWQ), distillation, compilation (TensorRT, ONNX Runtime), KV-cache + prefix caching, speculative decoding.
- **Routing / gateways (LLM):** an **LLM gateway** (LiteLLM, Portkey, cloud AI gateways — verify) centralizes provider routing, fallback, caching, budget/rate limits, PII redaction, and audit — a single control point to enforce §5 policy.
- **Resilience:** circuit breakers, timeouts, graceful degradation (fall back to smaller/cached model), multi-region for availability (OWASP **LLM10 Unbounded Consumption** is both a cost and a DoS concern).

### 3.5 RAG components

See §2.3. Building blocks: **loaders/parsers**, **chunker**, **embedding model**, **vector store** (+ metadata/ACL), **hybrid retriever**, **re-ranker**, **context assembler**, **generation + citation**. Keep the **ingestion pipeline and the vector index versioned** so you can re-embed when you change the embedding model (changing embedding models invalidates the whole index).

### 3.6 Agent runtime & orchestration

- **Orchestration frameworks:** **LangGraph**, **LangChain**, **LlamaIndex**, **DSPy**, **Semantic Kernel**, **CrewAI**, **AutoGen**, **Haystack**, **Pydantic AI** (verify current).
- **Core pieces:** planner, tool registry/router, short-term (working) + long-term (vector) **memory**, **MCP clients**, and a **sandboxed execution** environment for code/tool actions.
- **Controls:** iteration/step caps (loop-breaker), per-tool scopes, cost ceilings, and human-approval gates for high-blast-radius actions. Memory is a poisoning surface (OWASP Agentic **ASI06 Memory & Context Poisoning**).

### 3.7 MLOps / LLMOps & the evaluation/guardrail layers

**MLOps** = CI/CD/CT (continuous training) for the whole lifecycle: automated pipelines, registry-gated promotion, monitoring, and retraining triggers. **LLMOps** adds prompt management, tracing, token/cost tracking, and LLM-specific evaluation.

Evaluation operates at three gates:

| Gate | What runs | Blocks |
|---|---|---|
| **Offline eval** | Benchmark/golden datasets, LLM-as-judge, RAG metrics (groundedness, context precision/recall, faithfulness) | Promotion in the registry |
| **Online eval** | Canary / A-B / shadow, live quality + business metrics, user feedback | Full rollout |
| **Runtime guardrails** | Input + output filters every request | The individual request/response |

- **Eval tooling:** **Ragas**, **DeepEval**, **TruLens**, **promptfoo**, **Arize Phoenix**, **LangSmith**, **Langfuse**, **MLflow evaluate** (verify).
- **Guardrails:** input/output validation, PII detection/redaction, prompt-injection and jailbreak detection, topical/toxicity filters, schema/format validation, groundedness checks. Tools: **NeMo Guardrails**, **Guardrails AI**, **Llama Guard** / **Prompt Guard** (verify current version), **Azure AI Content Safety**, cloud provider content filters.
- **Monitoring/observability:** latency/throughput/cost, quality drift, data/feature drift (PSI/KL), embedding drift, plus full **tracing** of prompts → retrieval → tool calls → output. Drift and feedback trigger retraining, closing the loop back to the build plane.

### 3.8 Compute, accelerators & scaling

- **Accelerators:** NVIDIA GPUs (H100/H200/Blackwell-class — verify current SKUs), AMD MI-series, Google TPUs, AWS Trainium/Inferentia, and inference-focused silicon. Match accelerator to workload (training vs inference, memory-bound vs compute-bound).
- **Scheduling / sharing:** Kubernetes + GPU operator, **MIG** partitioning, **time-slicing**, queue-based schedulers (Ray, Volcano, Slurm for training). **Topology/placement** matters — NVLink/InfiniBand for multi-GPU training.
- **Memory is the LLM constraint:** model weights + KV cache dominate VRAM; quantization and PagedAttention exist to fit more context/throughput per card.
- **Cost architecture:** spot/pre-emptible for training and batch; reserved/committed for steady serving; autoscale-to-zero for spiky dev; cache aggressively; route to the smallest model that passes eval; track **$/token** and **GPU utilization** as SLOs. Unbounded agent loops and recursive RAG are real cost/DoS risks (OWASP LLM10).

---

## 4. Key Design Decisions & Trade-offs

ADR-style: decision → options → recommendation. Record these for any AI system under review.

### ADR-1 — RAG vs fine-tuning vs long context
- **RAG:** best when knowledge changes, must be attributable/citable, or is large/proprietary. Updatable without training; adds retrieval latency + infra.
- **Fine-tuning:** best for *behavior, format, tone, domain skill, or latency/cost* at steady state — **not** for fresh facts. Needs curated data + eval + retrain discipline.
- **Long context:** simplest when the knowledge fits a prompt and freshness is per-request; costs tokens/latency and risks "lost in the middle."
- **Recommendation:** **RAG for knowledge, fine-tune for behavior, long context for small/transient context — and combine.** Reach for fine-tuning only after retrieval+prompting demonstrably fail an eval.

### ADR-2 — Managed API vs self-hosted open-weight
- **Managed API:** fastest, least ops; data leaves your estate (contractual, not technical, control); provider lock-in; per-token cost.
- **Self-hosted open-weight:** data residency, cost-at-scale, customization, no egress; you own GPU ops *and* the hardening ([AI_INFRASTRUCTURE_SECURITY](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md)).
- **Recommendation:** default to managed API; self-host when **data sensitivity/residency, cost at volume, latency, or deep customization** cross a threshold. Keep a provider-neutral interface (gateway in §3.4) to avoid lock-in either way.

### ADR-3 — Synchronous vs streaming vs batch serving
- Streaming for chat UX (optimize TTFT); synchronous for tool/structured responses; batch for bulk scoring/embeddings.
- **Recommendation:** pick by UX and SLA; use **continuous batching** under the hood regardless, and a batch path for backfills to protect the online tier.

### ADR-4 — Vector store choice & index
- **Dedicated (Pinecone/Weaviate/Milvus/Qdrant)** vs **bring-your-DB (pgvector, Elasticsearch/OpenSearch, Redis)**.
- Trade-offs: scale/recall/latency (HNSW vs IVF-PQ), hybrid-search support, **multi-tenant isolation & metadata filtering (security-critical)**, and operational burden.
- **Recommendation:** if you already run Postgres/OpenSearch and corpus is modest, **pgvector/OpenSearch** minimizes moving parts; adopt a dedicated store for large-scale, high-QPS, or when you need first-class hybrid + metadata ACL filtering. Require **tenant isolation and ACL-at-query-time** as a hard requirement (OWASP LLM08).

### ADR-5 — Model size & routing
- One big model is simple but expensive; a **router** (small model triages, escalates hard queries to a big one) cuts cost dramatically.
- **Recommendation:** route to the **smallest model that passes eval** for each task; cache; reserve frontier models for the hard tail. Measure with the eval plane so routing never silently degrades quality.

### ADR-6 — Agent autonomy & tool access
- More autonomy = more capability and more blast radius (OWASP **LLM06 Excessive Agency**, Agentic ASI02/ASI03/ASI05).
- **Recommendation:** least-privilege tools, explicit allow-lists, **sandboxed execution**, step/cost caps, and **human approval scaled to irreversibility**. Never give an agent a credential broader than the single action requires.

### ADR-7 — Build-time reproducibility vs iteration speed
- Rigorous pinning slows experimentation; loose pinning destroys reproducibility and audit.
- **Recommendation:** loose in the sandbox, **strictly pinned the moment a run can be promoted** — enforce pinning as a registry gate, not a convention.

### Trade-off cheat-sheet

| Decision | Optimizes | Costs | Watch for |
|---|---|---|---|
| RAG | Freshness, attributability | Retrieval latency, infra | Injection via retrieved docs |
| Fine-tune | Behavior, latency, $/token | Retrain discipline, drift | Stale facts baked in |
| Quantization | Cost, throughput, VRAM | Small quality loss | Silent accuracy regression — eval it |
| Caching | Cost, latency | Staleness, cache poisoning | Per-tenant cache isolation |
| Model routing | Cost | Routing complexity | Quality drift on misroutes |
| Agent autonomy | Capability | Blast radius, cost | Excessive agency, loops (LLM06/LLM10) |

---

## 5. Security-by-Design Integration

This is a security library: architecture is the first control. Good structure *reduces vulnerability exposure* before a single detection rule exists. Map the design to **MITRE ATLAS** (AI-specific tactics/techniques), **OWASP LLM Top 10 (2025)** and **OWASP Agentic Top 10 (2026)**, and classical controls (**NIST SP 800-53**, **CIS Controls v8.1**, **NIST CSF 2.0**, **NIST SSDF SP 800-218 / 800-218A for AI**).

### 5.1 Trust boundaries — draw them explicitly

```
   [User/App] ──(1)──▶ [API GW / AuthZ] ──(2)──▶ [Guardrail-in] ──▶ [Orchestrator/LLM]
                                                                         │   ▲
                                                             (3) tools   │   │ (4) retrieval
                                                                         ▼   │
                                        [Sandbox + MCP servers]    [Vector store (ACL)]
                                                                         │
   [Response] ◀──(5)── [Guardrail-out] ◀────────────────────────────────┘

   (1) authn/z + quota   (2) untrusted prompt   (3) untrusted tool output + least-priv
   (4) untrusted retrieved content (indirect PI)   (5) untrusted model output → validate before use/exec
```

Everything crossing a numbered boundary is **untrusted**. This single diagram defends against most LLM-era attacks when enforced.

### 5.2 Threat-to-control map

| Architectural threat | ATLAS / OWASP | Design control (where it lives) |
|---|---|---|
| Malicious model artifact (RCE on load) | ATLAS *ML Supply Chain Compromise*; LLM03 | Signing + scanning + `safetensors` at the **registry** (§3.3) |
| Training-data / RAG-corpus poisoning | ATLAS *Poison Training Data*; LLM04 | Data contracts, provenance, source ACLs, quality gates (§3.1, §2.3) |
| Direct prompt injection / jailbreak | ATLAS; LLM01 | Guardrail-in, system-prompt hardening, output not trusted (§5.1) |
| Indirect prompt injection (via retrieved/tool content) | ATLAS; LLM01 | Treat retrieval/tool output as untrusted; content provenance; sandboxing (§2.3–2.4) |
| Sensitive-data leakage / cross-tenant retrieval | LLM02, LLM08 | ACL-at-query-time, tenant isolation, PII redaction at gateway (§3.4–3.5) |
| Model/prompt theft, extraction | ATLAS *Exfiltrate/Extract*; LLM07 | AuthZ, rate limits, response filtering, no secrets in system prompt |
| Excessive agency / tool misuse | LLM06; Agentic ASI02/ASI03/ASI05 | Least-priv tools, sandbox, approval gates, step caps (§3.6, ADR-6) |
| Unbounded consumption (cost/DoS) | LLM10 | Quotas, budgets, loop caps, circuit breakers (§3.4, §3.8) |
| Insecure MCP server / inter-agent comms | Agentic ASI07; MCP threat model | Server allow-list, scoped auth, signed messages ([AI_MCP_SECURITY](AI_MCP_SECURITY_REFERENCE.md)) |
| Supply-chain injection in ML CI/CD | LLM03; ATLAS | Pinned deps, SLSA provenance, no secrets in notebooks ([AI_INFRASTRUCTURE_SECURITY §7](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md)) |

### 5.3 How architecture reduces exposure (defense-in-depth for AI)

- **Plane separation** keeps the hostile-network-facing serving tier away from training data, notebooks, and credentials — a compromised inference node should not reach the data lake.
- **The registry chokepoint** means *nothing executable reaches production unsigned, unscanned, or unapproved* — collapsing the supply-chain attack surface to one auditable gate.
- **Gateway centralization** gives one enforcement point for authn/z, quotas, PII redaction, and audit — so controls are not re-implemented (and forgotten) per service.
- **Least-privilege tools + sandboxing** bound agent blast radius so a hijacked goal cannot pivot to the estate (counters cascading failure, Agentic ASI08).
- **Guardrails + evals as gates** make safety a runtime property, not documentation.
- **Reproducible lineage** turns incident response from guesswork into "rebuild the exact prediction, diff the inputs."

### 5.4 Data governance & privacy by design
- Classify and tag data at ingest; carry classification into features, embeddings, and caches. Minimize and pseudonymize PII before it reaches training sets or vector stores.
- Honor data residency and consent in the *architecture* (regional stores, per-tenant indexes), not just policy.
- Define retention/deletion for prompts, traces, embeddings, and fine-tune data — and prove it (right-to-erasure applies to derived artifacts too). See [PRIVACY_ENGINEERING_REFERENCE.md](PRIVACY_ENGINEERING_REFERENCE.md) and [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md).

---

## 6. Standards & Frameworks

| Standard / framework | What it is | Architectural use |
|---|---|---|
| **NIST AI RMF (AI 100-1)** + **Generative AI Profile (NIST AI 600-1, Jul 2024)** | Voluntary risk framework; core functions **Govern, Map, Measure, Manage**; 600-1 enumerates 12 GAI risks with suggested actions (Action IDs) | Organize AI risk management and tie design decisions to actions |
| **ISO/IEC 42001:2023** | AI Management System (AIMS) — certifiable, Annex A controls | Governance/management-system backbone; auditable AI program |
| **ISO/IEC 23894:2023** | AI risk management guidance | Complements NIST AI RMF |
| **ISO/IEC 22989 / 25059 / TR 24028** | AI concepts/terminology, quality model, trustworthiness | Common vocabulary and quality attributes |
| **OWASP Top 10 for LLM Applications 2025 (v2.0)** | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption | Threat checklist for LLM apps ([genai.owasp.org](https://genai.owasp.org/)) |
| **OWASP Top 10 for Agentic Applications (2026)** | ASI01–ASI10 agentic risks | Threat checklist for agents/MCP ([AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md)) |
| **MITRE ATLAS** | ATT&CK-style matrix for AI (16 tactics incl. AI Model Access, AI Attack Adaptation) | Map attacks to technique IDs ([ATLAS_REFERENCE.md](ATLAS_REFERENCE.md)) |
| **NIST SSDF (SP 800-218) + 800-218A** | Secure software development; 800-218A augments for generative AI/dual-use models | Secure the ML build pipeline |
| **CSA / Databricks / cloud AI frameworks** | AI security & well-architected guidance | Cloud reference alignment |
| **EU AI Act** | Risk-tiered AI regulation (prohibited/high-risk/limited/minimal) | Classify system risk tier; drives documentation, logging, human-oversight obligations — verify current timelines |
| **NIST CSF 2.0 / SP 800-53 / CIS Controls v8.1** | Classical control catalogs | The enabling weaknesses (authn, logging, segmentation) are ordinary controls — reuse them |

*Verify version/edition numbers and regulatory timelines at publication time — several of these revise frequently.*

---

## 7. Anti-Patterns & Pitfalls

| Anti-pattern | Why it hurts | Do instead |
|---|---|---|
| **Notebook-to-prod** | No reproducibility, no gate, no rollback | Registry-gated promotion with pinned lineage (§3.3) |
| **Train/serve skew** | Features computed differently offline vs online → silent accuracy loss | Shared feature definitions via a feature store (§3.1) |
| **No evaluation gate** | Quality regressions ship unnoticed; "vibes-based" releases | Offline/online/runtime eval gates (§3.7) |
| **Fine-tuning to add facts** | Expensive, stale fast, un-citable, hard to update | Use RAG for knowledge (ADR-1) |
| **RAG without re-ranking / hybrid** | Poor retrieval → confident wrong answers | Hybrid search + re-rank + groundedness check (§2.3) |
| **Changing embedding model without re-indexing** | Query and doc vectors become incomparable | Treat embeddings as a versioned, re-buildable index (§3.5) |
| **Trusting model/tool/retrieved output** | Injection, improper output handling (LLM01/LLM05) | Untrusted-by-default; validate before use/exec (§5.1) |
| **Over-privileged agents / broad tool creds** | Excessive agency; estate-wide blast radius (LLM06, ASI08) | Least-privilege, sandbox, approval gates (ADR-6) |
| **Unbounded loops / recursion / context** | Runaway cost and DoS (LLM10) | Step caps, budgets, circuit breakers (§3.8) |
| **Insecure defaults on inference servers** | Unauth RCE, model theft | Harden per [AI_INFRASTRUCTURE_SECURITY §8](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) |
| **Secrets in prompts / notebooks** | System-prompt leakage, credential theft (LLM07) | Secrets manager; nothing sensitive in the prompt (§5.3) |
| **No drift / cost monitoring** | Silent decay; surprise bills | Observability + drift + $/token SLOs (§3.7–3.8) |
| **Single-provider lock-in** | Price/availability risk; no fallback | Provider-neutral gateway (§3.4, ADR-2) |
| **No model/data cards or provenance** | Un-auditable; fails governance | Generate cards + SBOM at registration (§3.3, §6) |

---

## 8. Maturity & Checklist

### 8.1 Maturity model

| Level | Data/Features | Models | Serving | Ops/Eval | Security |
|---|---|---|---|---|---|
| **0 Ad hoc** | Manual pulls, no versioning | Notebooks, no registry | Hand-deployed | None | None / default-insecure |
| **1 Repeatable** | Scheduled ETL, some versioning | Registry exists | Containerized API | Basic metrics | AuthN, secrets mgmt |
| **2 Managed** | Lakehouse + feature store | Gated promotion, lineage | Autoscale, gateway | Offline eval + monitoring | Guardrails, scanning, ACLs |
| **3 Automated** | Data contracts, quality gates | CI/CD/CT pipelines | Canary/shadow, routing | Online eval, drift-triggered retrain | Signing, SBOM, tenant isolation |
| **4 Optimized** | Self-serve, governed | Auto-eval-gated, auto-rollback | Cost-optimized, multi-region | Closed-loop eval + feedback | Threat-informed, red-teamed, ATLAS-mapped |

### 8.2 Architecture review checklist

**Planes & platform**
- [ ] Training and inference planes are architecturally and trust-separated
- [ ] A model registry is the sole hand-off; nothing serves unregistered
- [ ] Runs are reproducible (pinned data + code + config + model + container digest)

**Data & features**
- [ ] Lakehouse/medallion layering; data versioning in place
- [ ] Feature store eliminates train/serve skew
- [ ] Data quality contracts validate at boundaries; provenance + ACLs captured at ingest

**Models**
- [ ] Customization choice justified (prompt → RAG → PEFT → fine-tune ladder)
- [ ] Registry gates: signing, deserialization/malware scan, model card + SBOM, approval, rollback

**Serving**
- [ ] Topology matches SLA (batch/online/streaming); continuous batching used
- [ ] Gateway enforces authn/z, quotas, budgets, PII redaction, audit
- [ ] Resilience: timeouts, circuit breakers, graceful degradation, autoscale

**RAG (if used)**
- [ ] Hybrid retrieval + re-ranking; groundedness/citation enforced
- [ ] Document ACLs carried into the vector store and enforced at query time
- [ ] Embedding index versioned and re-buildable

**Agents/MCP (if used)**
- [ ] Least-privilege tools; sandboxed execution; step/cost caps
- [ ] Human approval scaled to irreversibility/blast radius
- [ ] MCP servers allow-listed, scoped auth, outputs untrusted ([AI_MCP_SECURITY](AI_MCP_SECURITY_REFERENCE.md))

**Eval, ops & cost**
- [ ] Offline eval gates promotion; online eval/canary gates rollout; runtime guardrails
- [ ] Tracing of prompt → retrieval → tools → output; drift + $/token monitored
- [ ] GPU utilization, caching, and model routing manage cost

**Security & governance**
- [ ] Trust boundaries drawn; all crossing content treated as untrusted
- [ ] Mapped to OWASP LLM Top 10 (2025), Agentic Top 10 (2026), and ATLAS
- [ ] NIST AI RMF / ISO 42001 governance in place; EU AI Act risk tier classified
- [ ] Privacy-by-design: classification, minimization, residency, retention/erasure

---

## 9. Tools & Further Reading

*Representative, vendor-neutral where possible; verify current versions/names before standardizing.*

| Domain | Tools |
|---|---|
| Orchestration (pipelines) | Airflow, Dagster, Prefect, Kubeflow Pipelines, Argo Workflows |
| Data/table formats & versioning | Delta Lake, Apache Iceberg, Apache Hudi, DVC, LakeFS, dbt |
| Feature stores | Feast, Tecton, Databricks / SageMaker / Vertex feature stores |
| Experiment tracking & registry | MLflow (3.x), Weights & Biases, SageMaker/Vertex/Azure registries |
| Training (distributed) | PyTorch (DDP/FSDP), DeepSpeed, Megatron-LM, Ray Train |
| Fine-tuning (PEFT) | Hugging Face PEFT (LoRA/QLoRA), Axolotl, TRL, Unsloth |
| LLM serving engines | vLLM, SGLang, TensorRT-LLM, Hugging Face TGI, Triton, TorchServe, Ray Serve, KServe, Ollama, llama.cpp |
| LLM gateways / routing | LiteLLM, Portkey, cloud AI gateways |
| Vector stores | Pinecone, Weaviate, Milvus, Qdrant, Chroma, pgvector, OpenSearch/Elasticsearch, Redis |
| RAG / agent frameworks | LangChain, LangGraph, LlamaIndex, DSPy, Haystack, Semantic Kernel, CrewAI, AutoGen, Pydantic AI |
| Agent connectivity | Model Context Protocol (MCP) — spec revision 2025-11-25 (verify) |
| Evaluation | Ragas, DeepEval, TruLens, promptfoo, Arize Phoenix, LangSmith, Langfuse, MLflow evaluate |
| Guardrails / safety | NeMo Guardrails, Guardrails AI, Llama Guard / Prompt Guard, Azure AI Content Safety, cloud content filters |
| Model integrity / supply chain | sigstore `model-transparency`, model/data cards, SBOM tooling, ModelScan |
| Compute / scheduling | Kubernetes + GPU operator, MIG, Ray, Volcano, Slurm |

**In-library cross-references**
- [AI_INFRASTRUCTURE_SECURITY_REFERENCE.md](AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) — hardening the pipes/servers/stores behind this architecture
- [AI_MCP_SECURITY_REFERENCE.md](AI_MCP_SECURITY_REFERENCE.md) — MCP and agent-tool threat model & hardening
- [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md) — prompt injection, guardrails, OWASP LLM Top 10 detail
- [AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md) — agentic/swarm attack patterns, OWASP Agentic Top 10 (2026)
- [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md) — MITRE ATLAS techniques & mitigations for AI systems
- [AI_OFFENSIVE_SECURITY_REFERENCE.md](AI_OFFENSIVE_SECURITY_REFERENCE.md) — offensive AI testing/red-teaming
- [SECURITY_ARCHITECTURE_REFERENCE.md](SECURITY_ARCHITECTURE_REFERENCE.md), [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md), [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md), [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md), [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md), [PRIVACY_ENGINEERING_REFERENCE.md](PRIVACY_ENGINEERING_REFERENCE.md)

**External primary sources (verify at time of use)**
- NIST AI RMF (AI 100-1) & Generative AI Profile (NIST AI 600-1) — [nist.gov AI Resource Center](https://airc.nist.gov/)
- OWASP GenAI Security Project (LLM Top 10 2025; Agentic Top 10 2026) — [genai.owasp.org](https://genai.owasp.org/)
- MITRE ATLAS — [atlas.mitre.org](https://atlas.mitre.org/)
- Model Context Protocol — [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- ISO/IEC 42001:2023 (AI management system) — [iso.org](https://www.iso.org/standard/81230.html)
- NIST SSDF SP 800-218 / 800-218A — [csrc.nist.gov](https://csrc.nist.gov/)
