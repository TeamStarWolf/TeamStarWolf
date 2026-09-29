# AI Infrastructure & MLOps Security

> **In one minute** — This is the defender's reference for the *infrastructure* behind AI systems: model registries and artifact provenance, unsafe model deserialization (pickle/PyTorch/Keras/joblib) and the scanners that catch it, training-data and RAG-corpus poisoning, vector-store and feature-store security, the ML CI/CD supply chain, GPU and inference-server hardening, model access control and rate-limiting, and secrets in notebooks. It is deliberately *not* about prompt injection or model-level adversarial ML — those live in [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md) and [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md). This doc covers the pipes, servers, stores, and build systems an attacker takes over to steal models, poison outputs, or get RCE on the platform. Every section pairs concepts with concrete hardening steps, real tooling (named and current), and the CVEs that make the risk non-theoretical.

| | |
|---|---|
| **Read this when** | you are threat-modeling or hardening an ML platform (registry, feature store, inference tier), reviewing whether it is safe to load a third-party model artifact, standing up model signing or SBOM-for-models, securing a Jupyter/Kubeflow environment, or triaging a CVE in an AI-serving component |
| **Start at** | [The AI Infrastructure Attack Surface](#1-the-ai-infrastructure-attack-surface), [Unsafe Model Deserialization](#2-model-serialization--unsafe-deserialization), [GPU & Inference-Server Hardening](#8-gpu--inference-server-hardening), [Consolidated Hardening Checklist](#10-consolidated-hardening-checklist) |
| **Pairs with** | [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md), [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md), [DEVSECOPS_REFERENCE.md](DEVSECOPS_REFERENCE.md), [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md) |

*Sources: [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final), [CISA/NSA AI Data Security CSI (2025)](https://www.cisa.gov/news-events/alerts/2025/05/22/new-best-practices-guide-securing-ai-data-released), [OWASP GenAI Security Project](https://genai.owasp.org/), [Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/), [sigstore/model-transparency](https://github.com/sigstore/model-transparency). Facts verified 2026-09-29.*

---

## 1. The AI Infrastructure Attack Surface

Prompt injection gets the headlines, but most *real* AI compromises reported in 2024–2025 were plain infrastructure attacks — unauthenticated inference servers, RCE on model load, exposed pipeline orchestrators — that would look familiar to any web or cloud pentester. The AI-specific twist is that the "data" (models, embeddings, training sets) is executable, trusted, and huge, and the platforms that move it were built by ML teams optimizing for iteration speed, not for a hostile network.

| Layer | Representative components | Primary infra risks | Deep-dive |
|---|---|---|---|
| **Model artifacts** | `.pkl`, `.pt`/`.bin`, `.h5`, `.keras`, `.joblib`, `.gguf`, `.safetensors` | Code execution on load, backdoored weights, tampering | [§2](#2-model-serialization--unsafe-deserialization) |
| **Registry / artifact store** | MLflow, Hugging Face Hub, S3/GCS/Azure Blob, JFrog, Nexus | Unauthenticated pull/push, no provenance, malicious upload | [§3](#3-model-registries--artifact-provenance) |
| **Training data & RAG corpus** | Data lakes, DVC, LakeFS, web-scraped sets, RAG document stores | Poisoning, backdoor triggers, split-view/frontrunning | [§4](#4-training-data--rag-corpus-poisoning) |
| **Vector store** | Chroma, Pinecone, Weaviate, Milvus, Qdrant, pgvector | Broken tenant isolation, corpus poisoning, embedding inversion | [§5](#5-vector-store--embedding-security) |
| **Feature store** | Feast, Tecton, SageMaker/Vertex/Databricks feature stores | Integrity/skew, PII exposure, weak access control | [§6](#6-feature-stores) |
| **ML pipeline / CI-CD** | Kubeflow, Airflow, Argo, MLflow Pipelines, GitHub Actions | Supply-chain injection, secrets in notebooks, weak provenance | [§7](#7-ml-pipeline--cicd-supply-chain) |
| **Serving / GPU tier** | Triton, TorchServe, vLLM, Ray Serve, Ollama, KServe | Unauth RCE, model theft, resource exhaustion, tenant escape | [§8](#8-gpu--inference-server-hardening) |
| **Access & governance** | API gateways, IAM, quotas, audit logs | Missing authn/authz, no rate limits, no audit trail | [§9](#9-model-access-control--rate-limiting) |

**Framing for threat models.** Map these to MITRE ATLAS tactics for AI systems — *ML/AI Supply Chain Compromise*, *Poison Training Data*, *Manipulate AI Model*, and *Exfiltrate/Extract AI Model* — but treat the enabling weaknesses (missing auth, deserialization, exposed dashboards) as ordinary [SECURE_CODING_REFERENCE.md](SECURE_CODING_REFERENCE.md) and [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md) problems. See [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md) for current technique IDs and names.

---

## 2. Model Serialization & Unsafe Deserialization

The single most exploited AI-infra weakness: model files that execute arbitrary code the moment they are loaded. Python's `pickle` (and everything built on it) runs constructor bytecode during deserialization, so **loading a model is equivalent to running the publisher's code**.

### Formats ranked by risk

| Format | Code-exec on load? | Why | Guidance |
|---|---|---|---|
| `pickle` / `.pkl`, `cloudpickle` | **Yes** | `__reduce__`/`REDUCE` opcodes call arbitrary callables | Never load untrusted; scan first |
| PyTorch `.pt`/`.bin` (legacy `torch.load`) | **Yes** | ZIP wrapper around pickle | Use `weights_only=True` on **PyTorch ≥ 2.6**; scan |
| Keras `.h5` / legacy SavedModel (Lambda layers) | **Yes** | Lambda layers serialize Python; H5 ignores `safe_mode` | Prefer `.keras` v3 + `safe_mode=True`; avoid H5 from third parties |
| Joblib `.joblib` | **Yes** | Pickle-based | Scan; treat as pickle |
| NumPy `.npy`/`.npz` with `allow_pickle=True` | **Yes** | Object arrays pickle | Load with `allow_pickle=False` |
| GGUF (`llama.cpp`) | No (data-only) | Tensor container, no code | Safer by design; keep the *parser* patched (memory-safety bugs) |
| **`safetensors`** | **No** (data-only) | Pure tensor format, zero-copy, no exec | **Preferred distribution format** |

### The CVEs that make this concrete

- **PyTorch — CVE-2025-32434** (CVSS 9.3): `torch.load(..., weights_only=True)` — the setting everyone was told was safe — still reached RCE on **PyTorch ≤ 2.5.1**. Fixed in **2.6.0**, which also flips `weights_only` to default `True`. *Source: [GHSA-53q9-r3pm-6pq6](https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6).*
- **Keras — CVE-2024-3660**: Lambda layers execute arbitrary Python on model load in Keras **< 2.13**. `safe_mode=True` (default from 2.13 / Keras 3) blocks it for the `.keras` v3 format — but the **legacy H5 format ignores `safe_mode`**, so a malicious `.h5` still executes on a patched runtime (JFrog / Oligo "downgrade" research). *Source: [JFrog](https://jfrog.com/blog/keras-safe_mode-bypass-vulnerability/), [NVD](https://www.wiz.io/vulnerability-database/cve/cve-2024-3660).*
- **MLflow — CVE-2024-37052 through CVE-2024-37060** (the "unsafe deserialization" cluster, disclosed by HiddenLayer via Protect AI's huntr): malicious models in a registry run code when a victim calls `mlflow.<flavor>.load_model` (e.g. CVE-2024-37059 PyTorch, CVE-2024-37054 pyfunc/cloudpickle). Fixed in **MLflow 2.14.2**. *Source: [mlflow#12256](https://github.com/mlflow/mlflow/issues/12256).*

> **"Sleepy Pickle" and friends.** Even a fully-loaded, "correct" model can carry a payload that patches the model object in memory or hooks downstream code (Trail of Bits demonstrated this class in 2024). Scanning before load is necessary; provenance/signing (§3) is what actually establishes trust.

### Prefer safetensors; gate legacy loads

```python
# Distribute and load weights as safetensors (no code execution path)
from safetensors.torch import save_file, load_file
save_file(model.state_dict(), "model.safetensors")
state = load_file("model.safetensors")          # data-only, safe to load untrusted

# If you MUST load a .pt, pin a patched runtime and weights_only
import torch                                     # require torch >= 2.6.0
state = torch.load("model.pt", weights_only=True)

# Keras: use the v3 format and keep safe_mode on; refuse third-party .h5
import keras
m = keras.models.load_model("model.keras", safe_mode=True)
```

### Scan every artifact before it enters the registry or a runner

| Scanner | Maintainer | Covers | Notes |
|---|---|---|---|
| **modelscan** | Protect AI | Pickle, PyTorch, Keras (H5 & v3), TF SavedModel, NumPy, Joblib | Open-source; CI-friendly exit codes |
| **picklescan** | Hugging Face | Pickle / PyTorch | Runs in the HF Hub scanning pipeline |
| **Fickling** (allowlist scanner) | Trail of Bits | Pickle | Sep 2025 release; import **allowlist** instead of blocklist |
| **ModelAudit** | Promptfoo | Multiple model formats | Open-sourced 2025; CI scanning |
| **Guardian** | Protect AI | 35+ formats (commercial) | Registry/gateway enforcement |

```bash
# Fail a pipeline stage if a model file carries a dangerous opcode/import
modelscan -p ./artifacts/model.pkl            # non-zero exit = block promotion
picklescan -p ./checkpoints/model.ckpt
```

**Enforcement pattern:** scan at *ingest* (before an artifact is written to the registry) and again at *promotion* (dev→prod). A blocklist scanner can be evaded with structure-aware fuzzing (Cisco AI research, 2025), so favor allowlist-based checks and combine scanning with signing, not either alone.

---

## 3. Model Registries & Artifact Provenance

A model registry is a build-artifact repository whose artifacts are executable and often pulled straight into production. Apply the same rigor you would to a container registry ([CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md)) plus model-specific provenance.

**Baseline controls**

- **Authentication and authorization on every path.** MLflow historically shipped with no auth; treat any registry/tracking server as internet-reachable and put authn (SSO/OIDC) and RBAC in front of read *and* write. Segment by environment.
- **No anonymous push.** Uploads must be authenticated, attributed, and logged. Malicious-upload was the exploit path for the MLflow CVEs (§2).
- **Immutability and retention.** Version tags are immutable; keep the artifact, its scan result, and its provenance together. Never overwrite a released version in place.
- **Scan-on-ingest gate** (§2) wired into the registry's admission path.

### Provenance: signing, SBOMs, and model cards

- **Model signing (Sigstore / OpenSSF).** `sigstore/model-transparency` and the **OpenSSF Model Signing (OMS)** specification bring keyless Sigstore signatures (or self-signed / KMS keys) to model artifacts of any format and size, verifiable at hub upload or at load. Google detailed production use of Sigstore for model signing with OpenSSF in 2025; a **Sigstore Model Validation Operator** enforces signatures at admission in Kubernetes. *Sources: [Sigstore blog](https://blog.sigstore.dev/model-transparency-v1.0/), [OpenSSF](https://openssf.org/blog/2025/07/23/case-study-google-secures-machine-learning-models-with-sigstore/).*

```bash
# Illustrative model-signing flow (sigstore/model-transparency CLI shape)
model_signing sign   ./model_dir --signature model.sig      # keyless (Sigstore) or --private-key
model_signing verify ./model_dir --signature model.sig --identity <expected-signer>
```

- **SBOM for models / AI-BOM.** Record training data sources, base model, libraries, and evaluation lineage. This extends software-supply-chain SBOM practice — see [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md) for CycloneDX/SPDX, cosign, and SLSA build levels, which apply directly to the model build.
- **SLSA-style build provenance.** Produce and verify provenance attestations for the training/fine-tuning job so consumers can confirm *which pipeline* produced a weight file — the same "signature validates origin, not integrity of the build" caveat from SolarWinds applies to model builds.
- **Model cards** capture intended use, eval results, and known limitations — governance metadata, not a security control, but required by NIST/CoSAI/EU AI Act processes.

**Third-party model intake checklist:** verify signature/provenance → confirm publisher identity → scan artifact (§2) → prefer safetensors variant → pin by digest, not tag → load in a sandboxed, network-restricted runner first.

---

## 4. Training-Data & RAG-Corpus Poisoning

Poisoning targets integrity of the data that shapes model behavior. It is an *infrastructure* problem because the fix is provenance, access control, and validation on the data plane — not a model tweak.

**Attack classes**

- **Web-scale poisoning is practical.** Research (Carlini et al., "Poisoning Web-Scale Training Datasets is Practical") showed **split-view** poisoning (content at a scraped URL changes after the snapshot) and **frontrunning** poisoning (editing a resource, e.g. a wiki page, right before a known crawl) let an attacker taint a meaningful fraction of a public corpus cheaply.
- **Backdoor / trigger poisoning.** A small set of poisoned samples binds a trigger phrase or pattern to an attacker-chosen output; the model behaves normally otherwise, defeating accuracy-based QA.
- **Model-hub poisoning.** Publicly editable hubs let attackers upload surgically edited models (the Mithril "PoisonGPT" demonstration uploaded a model that spread targeted misinformation) — a data-integrity problem solved by signing/provenance (§3).
- **RAG-corpus poisoning.** The retrieval corpus is a live training surface: an attacker who can write to an indexed document store (ticketing system, wiki, shared drive, crawled site) plants content that the retriever surfaces and the model treats as trusted context. This is the indirect-injection bridge to [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md); the *infra* mitigation is controlling and vetting what gets indexed.

**Defenses**

| Control | What it does |
|---|---|
| **Data provenance & versioning** (DVC, LakeFS, Delta/Iceberg time-travel, content hashes) | Reproducible, tamper-evident datasets; detect drift between snapshot and use |
| **Source allowlisting & ingestion review** | Only vetted sources enter training/RAG corpora; human or automated review of new documents |
| **Data validation / anomaly detection** (Great Expectations, statistical outlier and duplicate checks) | Catch label flips, near-duplicate flooding, out-of-distribution injects |
| **RAG write-path controls** | Authn/authz on what can be indexed; separate "trusted" vs "user-supplied" corpora; strip active content |
| **Immutable snapshots + integrity hashes** | Pin exactly which data version trained which model (ties to §3 provenance) |
| **Least-privilege on the data plane** | Restrict who/what can write to lakes, corpora, and index pipelines |

The **CISA/NSA/FBI + allied "AI Data Security" CSI (22 May 2025)** is the authoritative baseline here — 10 best practices covering data provenance, integrity, and protection across the AI data lifecycle, building on the NSA/CISA *Deploying AI Systems Securely* guidance (April 2024). *Source: [CISA](https://www.cisa.gov/news-events/alerts/2025/05/22/new-best-practices-guide-securing-ai-data-released).*

---

## 5. Vector-Store & Embedding Security

Vector databases (Chroma, Pinecone, Weaviate, Milvus, Qdrant, `pgvector`) back most RAG systems and are frequently deployed with the defaults-open posture of an early datastore.

**Risks**

- **Missing/weak authentication and network exposure** — self-hosted vector DBs are routinely stood up without auth on an open port; treat them like any exposed database.
- **Broken multi-tenant isolation** — one embedding space serving many customers/users without per-tenant partitioning or metadata filtering leaks documents across tenants via similarity search.
- **Corpus poisoning** (§4) delivered through the index.
- **Embedding inversion / membership inference** — embeddings are not anonymized; research shows text can be partially reconstructed from stored vectors, and membership can be inferred. Treat embeddings as sensitive derivatives of the source data.
- **Metadata leakage** — chunk metadata (paths, ACLs, PII) returned alongside matches.

**Hardening checklist**

- [ ] Authentication + RBAC enabled; management/API ports not internet-exposed (network policy / private endpoints)
- [ ] Per-tenant namespaces/collections **and** enforced metadata filters on every query (never rely on filtering in app code alone)
- [ ] Encrypt at rest and in transit; classify embeddings at the sensitivity of their **source** documents
- [ ] Access control that mirrors the *source-document* ACLs (a user must not retrieve chunks from documents they can't read)
- [ ] Ingestion pipeline authenticated and logged; separate trusted vs untrusted corpora
- [ ] Query rate limits and result-count caps to blunt bulk extraction of the corpus
- [ ] Audit logging of queries and index writes

---

## 6. Feature Stores

Feature stores (Feast, Tecton, and managed Databricks / SageMaker / Vertex AI feature stores) serve engineered features to both training (offline) and inference (online) and centralize sensitive, often-PII data — a high-value, under-secured target.

- **Integrity = correctness.** Tampering with feature values, or **training–serving skew** (offline and online stores drift out of sync), silently degrades or manipulates model behavior; monitor parity between offline and online values and alert on drift.
- **Access control & lineage.** RBAC on feature groups; log who reads/writes; capture lineage from raw source → feature → model so a poisoned or wrong feature can be traced.
- **PII governance.** Features frequently embed regulated data — apply classification, minimization, masking/tokenization, and retention. See [DATA_SECURITY_REFERENCE.md](DATA_SECURITY_REFERENCE.md) and [PRIVACY_ENGINEERING_REFERENCE.md](PRIVACY_ENGINEERING_REFERENCE.md).
- **Online-store exposure.** The low-latency online store (often Redis/DynamoDB-class) is network-reachable from serving — authenticate it, isolate it, and don't expose it beyond the inference tier.

---

## 7. ML Pipeline / CI-CD Supply Chain

"CI/CD for models" inherits every software supply-chain risk plus a few of its own. Read [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md) and [DEVSECOPS_REFERENCE.md](DEVSECOPS_REFERENCE.md) first; the ML-specific deltas:

- **Notebooks as unreviewed production code.** Jupyter/Colab notebooks run with broad credentials, are rarely code-reviewed, and often reach out to install packages and pull data at runtime. Route notebook-originated code through the same review/scan gates as app code; disallow arbitrary `pip install` from inside production runs.
- **Orchestrator exposure.** Kubeflow Pipelines, Airflow, Argo, and MLflow servers are web apps with powerful permissions — a long history of exposed Airflow UIs and Kubeflow dashboards led to cryptomining and cluster takeover. Put them behind SSO, restrict network reach, patch, and scope their service accounts tightly.
- **Dependency risk is amplified.** ML stacks pull enormous, fast-moving dependency trees (and models-as-dependencies). Pin and hash-verify dependencies, scan for known-vulnerable and typosquatted/dependency-confusion packages, and vendor critical ones.
- **Build provenance for models.** Emit SLSA-style provenance from training/fine-tuning jobs and sign outputs (§3); verify at deploy.
- **Least-privilege pipeline identities.** Short-lived, workload-scoped credentials (OIDC to cloud, no long-lived keys); a single over-broad pipeline token is the "cascading failure" enabler seen in agentic-swarm intrusions ([AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md)).

---

## 8. GPU & Inference-Server Hardening

The serving tier is where most *public* AI-infra compromises landed — unauthenticated model servers reachable from the internet, several with critical RCE. Model servers must be treated as untrusted-input-facing services on a hostile network.

### Recent, verified inference-server CVEs

| Component | CVE(s) | Impact | Fix / control |
|---|---|---|---|
| **NVIDIA Triton Inference Server** | CVE-2025-23319 (+ CVE-2025-23320, CVE-2025-23334; also CVE-2025-23317) | Chained unauthenticated RCE via the Python backend (shared-memory info-leak → full server takeover) | Upgrade Triton **and Python backend to 25.07**; isolate ([Wiz](https://www.wiz.io/blog/nvidia-triton-cve-2025-23319-vuln-chain-to-ai-server)) |
| **TorchServe ("ShellTorch")** | CVE-2023-43654 (SSRF→RCE, 9.8) + CVE-2022-1471 (SnakeYAML deserialization, 9.9) | Default-open management API + model-URL allowlist accepting all domains → malicious model → RCE | Patch; set `allowed_urls`; bind management API to localhost ([Oligo](https://www.oligo.security/blog/shelltorch-torchserve-ssrf-vulnerability-cve-2023-43654)) |
| **Ray** | CVE-2023-48022 ("ShadowRay", 9.8) | Jobs API has no authn by default → RCE; actively exploited for cryptomining/botnets | **Network-isolate the dashboard/Jobs API** (maintainers treat no-auth as intended trust model); later releases added optional auth — do not rely on defaults ([TXOne](https://www.txone.com/blog/ai-infrastructure-under-siege-cve-2023-48022/)) |
| **Ollama** | CVE-2024-37032 ("Probllama") | Path traversal via `/api/pull` from a rogue registry → arbitrary file write → RCE | Upgrade to **0.1.34+**; don't expose the API; don't pull from untrusted registries ([Wiz](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)) |

### Hardening controls

- **Authentication and network isolation, always.** Assume every model server ships insecure-by-default. Bind management/admin APIs to localhost, put inference behind an authenticated gateway, and place the tier on a private network/segment. The recurring root cause above is *reachability without auth*.
- **Restrict model-load sources.** Load only from your signed registry (§3); allowlist model-fetch URLs; never let a request tell the server where to pull a model from (the SSRF/registry-poisoning pattern in ShellTorch and Probllama).
- **Patch aggressively and track KEV.** AI-serving components are now routine CVE targets; some are in CISA KEV. Feed them into normal vuln management ([VULNERABILITY_MANAGEMENT_REFERENCE.md](VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE_REFERENCE.md](CVE_REFERENCE.md)).
- **Resource limits & DoS controls.** Cap request size, batch size, context length, and concurrency; set GPU memory/timeouts. Unbounded consumption (the OWASP LLM "Unbounded Consumption" risk) is cheap to trigger and expensive on GPUs.
- **Multi-tenant GPU isolation.** Use hardware/driver isolation (e.g. NVIDIA MIG partitions, per-tenant nodes) rather than sharing a GPU context across tenants; scrub GPU memory between tenants; keep drivers/CUDA patched.
- **Container & K8s hardening for serving pods** — non-root, read-only rootfs, dropped capabilities, seccomp, network policies, admission control (verify model signatures at admission). See [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md) and [CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md).
- **Egress control.** A compromised inference/worker pod should not reach the internet or the credential/metadata service freely — restrict egress and block IMDS abuse.

---

## 9. Model Access Control & Rate-Limiting

The model endpoint is an asset to protect (against theft/extraction) and a resource to meter (against abuse and cost).

- **AuthN/AuthZ per consumer.** Every inference call is attributable to an identity; scope keys/tokens to specific models and actions; rotate and revoke. No shared "one key for the whole platform."
- **Rate limits and quotas** per identity — request-rate, token, and cost budgets — to blunt **model-extraction** (systematically querying to clone behavior/decision boundaries) and denial-of-wallet. Add anomaly detection on query volume and patterns.
- **Output and error hygiene.** Don't leak logits/probabilities or verbose internals that accelerate extraction; generic errors.
- **Audit logging.** Log prompts/inputs (with privacy controls), model+version, identity, and decisions to a tamper-evident store for IR and abuse investigation ([SIEM_REFERENCE.md](SIEM_REFERENCE.md)).
- **Gateway pattern.** Front models with an AI/API gateway that centralizes authn, quotas, logging, and payload policy — the natural chokepoint for these controls ([API_SECURITY_REFERENCE.md](API_SECURITY_REFERENCE.md)).

---

## 10. Consolidated Hardening Checklist

| Layer | Do this |
|---|---|
| **Artifacts** | Prefer `safetensors`/GGUF; scan pickle/PyTorch/Keras/joblib on ingest **and** promotion; PyTorch ≥ 2.6 with `weights_only=True`; refuse third-party `.h5` |
| **Registry** | Authn + RBAC on read/write; no anonymous push; scan-on-ingest gate; sign models (Sigstore/OMS) and verify at load/admission; pin by digest |
| **Provenance** | AI-BOM (data + base model + libs); SLSA-style build provenance for training jobs; model cards for governance |
| **Training/RAG data** | Versioned, hashed, provenance-tracked datasets; source allowlists; validation/anomaly checks; controlled RAG write-path; align to CISA/NSA AI Data Security CSI |
| **Vector store** | Auth + RBAC; private networking; per-tenant isolation + enforced metadata filters; encrypt; mirror source ACLs; query rate limits |
| **Feature store** | RBAC + lineage; offline/online parity monitoring; PII classification/minimization; isolate the online store |
| **Pipeline / CI-CD** | Review/scan notebook code; SSO + network limits on orchestrators; pin+hash deps; scan for typosquat/confusion; short-lived scoped identities |
| **Serving / GPU** | Authn + network isolation by default; allowlist model sources; patch (Triton 25.07, Ollama 0.1.34+, TorchServe, Ray-isolate); resource caps; MIG/tenant isolation; egress control |
| **Access** | Per-consumer authn/authz; rate/token/cost quotas; extraction anomaly detection; audit logging; AI gateway chokepoint |

---

## 11. Standards & Frameworks (infra-relevant)

| Reference | Publisher | What it gives you | Status / date |
|---|---|---|---|
| [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) — SSDF Community Profile for GenAI & dual-use foundation models | NIST | Secure-development tasks specific to AI model dev (extends SSDF 800-218) | Final, **26 Jul 2024** |
| [NIST AI RMF (AI 100-1)](https://airc.nist.gov/) + Generative AI Profile (NIST AI 600-1) | NIST | Risk-management functions (Govern/Map/Measure/Manage); GenAI profile added 2024 | In use |
| [CISA/NSA/FBI + allies — AI Data Security CSI](https://www.cisa.gov/news-events/alerts/2025/05/22/new-best-practices-guide-securing-ai-data-released) | CISA/NSA/FBI/ACSC/NCSC-NZ/NCSC-UK | 10 best practices for securing AI data lifecycle | **22 May 2025** |
| [Deploying AI Systems Securely](https://www.nsa.gov/) | NSA/CISA + allies | Deployment-hardening guidance this doc's serving/access controls map to | Apr 2024 |
| [CoSAI](https://www.coalitionforsecureai.org/) (OASIS) — incl. CoSAI Risk Map, model-signing & incident-response frameworks | OASIS Open Project | Vendor-neutral secure-AI guidance; Google donated SAIF data (Sep 2025); two frameworks released Nov 2025 | Active |
| [Google SAIF](https://safety.google/intl/en/safety/saif/) | Google | Secure AI Framework + risk assessment (now feeding CoSAI) | Active |
| [OpenSSF Model Signing (OMS)](https://github.com/ossf/model-signing-spec) + [sigstore/model-transparency](https://github.com/sigstore/model-transparency) | OpenSSF / Sigstore | Standard + tooling to sign and verify model artifacts | Active |
| [OWASP GenAI Security Project](https://genai.owasp.org/) — LLM Top 10, ML Security Top 10, AI Exchange | OWASP | Risk taxonomies incl. Supply Chain, Data/Model Poisoning, Unbounded Consumption | Ongoing |
| [MITRE ATLAS](https://atlas.mitre.org/) | MITRE | Adversary techniques for AI systems (supply chain, poisoning, model extraction) | Living |

---

## Related Resources

- [AI_SECURITY_REFERENCE.md](AI_SECURITY_REFERENCE.md) — OWASP LLM Top 10, prompt injection, adversarial ML (the model/application layer this doc complements)
- [AI_MCP_SECURITY_REFERENCE.md](AI_MCP_SECURITY_REFERENCE.md) — securing Model Context Protocol servers and tool integrations
- [AI_OFFENSIVE_SECURITY_REFERENCE.md](AI_OFFENSIVE_SECURITY_REFERENCE.md) — offensive/red-team view of AI systems
- [AGENTIC_AI_ATTACK_REFERENCE.md](AGENTIC_AI_ATTACK_REFERENCE.md) — autonomous-agent swarm intrusions and cascading failures
- [ATLAS_REFERENCE.md](ATLAS_REFERENCE.md) — MITRE ATLAS techniques and mitigations for AI
- [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md) — SBOMs, Sigstore/cosign, SLSA (apply directly to model builds)
- [DEVSECOPS_REFERENCE.md](DEVSECOPS_REFERENCE.md) — CI/CD hardening the ML pipeline inherits
- [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md) · [CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md) — where inference/GPU workloads run
- [SECRETS_MANAGEMENT_REFERENCE.md](SECRETS_MANAGEMENT_REFERENCE.md) — secrets in notebooks and pipeline identities
- [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md) — managed ML platform (SageMaker/Vertex/Databricks) hardening
- [disciplines/ai-ml-security.md](disciplines/ai-ml-security.md) · [disciplines/ai-llm-security.md](disciplines/ai-llm-security.md) — discipline learning paths

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
