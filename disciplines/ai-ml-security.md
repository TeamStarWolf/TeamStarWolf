# AI/ML Security

AI/ML security is the discipline of identifying, exploiting, and defending against vulnerabilities that are unique to machine learning systems — systems that learn behavior from data rather than executing explicit logic. The attack surface spans the full ML lifecycle: training data, model architecture, serving infrastructure, and the interfaces that expose model behavior to users and downstream systems.

The stakes are high in both directions. Adversaries can manipulate model outputs without touching the underlying code, extract proprietary model weights through black-box queries, poison training pipelines to embed persistent backdoors, and abuse large language models to bypass safety controls and execute unauthorized actions. Defenders must secure not only traditional application and infrastructure layers but also the data pipelines, model registries, embedding stores, and agentic runtimes that have no equivalent in classical software security.

The discipline accelerated sharply with the widespread deployment of large language models (LLMs) in production systems. Prompt injection, jailbreaks, and LLM-assisted agent abuse are now documented attack classes with real-world impact, and the threat model for LLM-integrated applications — particularly agentic systems that can call tools and take external actions — is substantially different from conventional API security.

---

## Where to Start

Begin with classical ML attack concepts — adversarial examples, model inversion, and membership inference — before moving to LLM-specific threats. Understanding why gradient-based perturbations fool neural networks builds the intuition needed to reason about why prompt injection works and why it is difficult to defend against systematically. The OWASP LLM Top 10 is the most accessible entry point for practitioners coming from a web application security background.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Adversarial ML concepts, the ML model lifecycle, the OWASP LLM Top 10, prompt injection fundamentals, API key and model artifact security | OWASP LLM Top 10 (owasp.org), Microsoft AI Red Team blog, Adversarial Robustness Toolbox (ART) documentation, Lakera AI blog |
| Practitioner | Prompt injection exploitation and defenses, jailbreak taxonomy, RAG security (retrieval-augmented generation), LLM agent threat modeling, model supply chain risks, red-teaming LLMs with tools like Garak | MITRE ATLAS matrix, Anthropic red-teaming papers, Garak LLM vulnerability scanner, NIST AI RMF (AI 100-1), LLM Security community resources |
| Advanced | Gradient-based adversarial attacks, membership inference and model inversion, backdoor/trojan detection in neural networks, agentic system threat modeling (multi-agent, tool-use, long-horizon tasks), formal AI safety and alignment-related security properties | Cleverhans research, Papernot et al. adversarial ML literature, Sleeper Agents paper (Anthropic), AI Safety Gridworlds, IEEE S&P AI security track papers |

---

## Free Training

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — The most widely referenced taxonomy of LLM application vulnerabilities; covers prompt injection, insecure output handling, training data poisoning, supply chain risks, and seven additional categories; the essential starting reference for any practitioner entering this space
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for Artificial-Intelligence Systems; ATT&CK-style matrix of adversary tactics and techniques targeting ML systems; covers both classical ML attacks and LLM-specific threats with real-world case studies; free and actively maintained
- [Microsoft AI Red Team Blog](https://www.microsoft.com/en-us/security/blog/topic/ai-security/) — Free practitioner-level content from the team that red-teams Microsoft's production AI systems; covers prompt injection, agentic security, jailbreak taxonomies, and lessons from real-world AI red team engagements
- [NIST AI Risk Management Framework (AI RMF)](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf) — NIST's framework for identifying, assessing, and managing AI-related risks; the governance and compliance anchor for enterprise AI security programs; free PDF
- [Garak Documentation](https://docs.garak.ai/) — Documentation for Garak, the open-source LLM vulnerability scanner; covering the probe library, detector architecture, and how to run structured assessments against local and hosted LLMs
- [Lakera AI Blog](https://www.lakera.ai/blog) — Free practitioner content covering prompt injection defenses, LLM security fundamentals, and real-world LLM attack examples; consistently high signal-to-noise ratio
- [Anthropic Research Papers](https://www.anthropic.com/research) — Free research publications from Anthropic covering red-teaming, jailbreak resistance, backdoor behavior in LLMs, and alignment-adjacent security properties; technically rigorous and directly relevant to understanding frontier model threats
- [Adversarial Robustness Toolbox (ART) Documentation](https://adversarial-robustness-toolbox.readthedocs.io/) — IBM's comprehensive documentation for the ART library covering adversarial attack implementation, evaluation, and defense; the best free resource for hands-on classical adversarial ML work
- [AI Village at DEF CON](https://aivillage.org/) — Free recordings and presentations from the DEF CON AI Village covering offensive and defensive AI security research; the premier community venue for applied AI/ML security work
- [Weights & Biases AI Security Resources](https://wandb.ai/site) — Free resources on ML experiment tracking, model lineage, and supply chain hygiene; relevant for practitioners focused on securing ML development pipelines

---

## Attack Taxonomy

### Classical ML Attacks

**Adversarial Examples**
Imperceptibly small perturbations to input data — pixels, audio samples, or text tokens — that cause a model to misclassify with high confidence. Attacks are gradient-based (white-box: FGSM, PGD, C&W) or transfer-based and query-based (black-box: Square Attack, NES). Primarily a concern for vision models in high-stakes settings such as autonomous vehicles and biometric authentication.

**Model Inversion**
Recovering training data features or reconstructing approximate training samples from model outputs and confidence scores. An attacker with API access to a model that trained on private medical records may be able to reconstruct patient features correlated with specific predictions.

**Membership Inference**
Determining whether a specific data record was part of a model's training set by observing how the model responds to it. Models typically show higher confidence and lower loss on training examples; this difference is exploitable. A successful inference reveals that a specific individual's data was used to train a model — a direct privacy violation under GDPR and HIPAA in sensitive contexts.

**Model Extraction (Model Stealing)**
Reconstructing a functionally equivalent copy of a proprietary model by querying it systematically and training a surrogate on the query-response pairs. High-value targets include commercial models behind paid APIs where the model architecture or training investment represents significant IP.

**Backdoor / Trojan Attacks**
Embedding hidden behavior in a model during training: the model performs normally on clean inputs but produces a targeted misclassification whenever a specific trigger pattern is present. Triggers can be pixel patches, text phrases, or acoustic tones. Highly relevant for organizations that fine-tune models on third-party pretrained weights — supply chain backdoors can survive fine-tuning.

**Data Poisoning**
Injecting malicious samples into the training dataset to degrade model accuracy, introduce targeted misclassifications, or embed backdoors. Feasible against models with open training pipelines, crowdsourced data collection, web-scraped corpora, or active learning loops. Even small poisoning rates (0.1–1% of training data) can be sufficient for targeted attacks.

---

### LLM-Specific Attacks

**Prompt Injection**
Supplying adversarial instructions in user-controlled input that cause an LLM to override its system prompt, ignore prior constraints, or execute attacker-specified behaviors. Direct injection targets the model through the user turn; indirect injection embeds instructions in external content the model retrieves (web pages, documents, emails, database records) and processes as part of a task. Indirect injection is the more dangerous form in agentic contexts because the user-visible interface shows no attack.

**Jailbreaking**
Techniques that cause an LLM to produce outputs its safety training was designed to prevent — instructions for harmful activities, unfiltered content, or confidential information. Methods include role-play framing, many-shot prompting, encoding tricks (Base64, Pig Latin, hex), token manipulation, and adversarial suffixes identified through gradient-based optimization. Jailbreaks do not require API access to model weights; they operate entirely through the text interface.

**System Prompt Extraction**
Eliciting the contents of a confidential system prompt through repeated queries, role-play scenarios, or instruction-overriding techniques. System prompts often contain proprietary instructions, business logic, and PII that operators intend to keep confidential. Not universally achievable but widely attempted; many production deployments are vulnerable.

**Insecure Output Handling**
Downstream code treating LLM-generated text as trusted input without sanitization or validation. An LLM that generates SQL queries, OS commands, code for execution, or HTML/JavaScript that is rendered without escaping is a vector for SQL injection, command injection, XSS, and SSRF depending on the downstream consumer.

**Retrieval-Augmented Generation (RAG) Poisoning**
Injecting malicious content into the documents, databases, or knowledge bases that a RAG system retrieves to augment LLM context. When the retrieval pipeline fetches attacker-controlled content, it becomes a delivery mechanism for indirect prompt injection that executes inside the privileged LLM context.

**Agentic / Tool-Use Exploitation**
Targeting LLM agents that are authorized to call external tools — web search, code execution, file system access, email, calendar, API calls. Indirect prompt injection delivered via tool outputs (a malicious web page returned by a search tool, a poisoned document in a file read) can hijack the agent's action sequence: exfiltrating data, sending unauthorized messages, modifying files, or pivoting to additional tool calls the user never authorized.

---

## MITRE ATLAS — Key Techniques

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the authoritative taxonomy for ML system attacks, modeled after ATT&CK. Key techniques relevant to practitioners:

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Reconnaissance | Discover ML Artifacts | AML.T0000 | Identify model APIs, documentation, and exposed endpoints |
| Resource Development | Acquire Public ML Artifacts | AML.T0002 | Download pretrained models and datasets for attack development |
| ML Attack Staging | Craft Adversarial Data | AML.T0020 | Generate adversarial examples to fool deployed models |
| ML Attack Staging | Backdoor ML Model | AML.T0018 | Embed trojans in model weights during training |
| Initial Access | ML Supply Chain Compromise | AML.T0010 | Compromise third-party models, datasets, or training pipelines |
| Exfiltration | Model Inversion Attack | AML.T0024 | Recover training data from model outputs |
| Exfiltration | Membership Inference Attack | AML.T0023 | Determine whether a record was used in training |
| Impact | Evade ML Model | AML.T0015 | Craft inputs that evade model detection or classification |
| Impact | Erode ML Model Integrity | AML.T0031 | Poison data to degrade or manipulate model behavior |

Full matrix: [atlas.mitre.org](https://atlas.mitre.org)

---

## LLM Application Threat Model

A production LLM application has multiple distinct trust boundaries, each with its own attack surface:

```
[User]
   │  direct prompt injection
   ▼
[LLM Context Window]
   │  system prompt leakage, jailbreak
   ▼
[Retrieval / Tool Call Outputs]  ◄── indirect injection (web, docs, DB)
   │  insecure output handling
   ▼
[Downstream Consumers]
   │  SQL, OS command, code exec, HTML render
   ▼
[Actions / External Systems]    ◄── agentic exploitation
```

**OWASP LLM Top 10 (2025)**

| Rank | Vulnerability | Description |
|---|---|---|
| LLM01 | Prompt Injection | Direct and indirect override of LLM instructions via input |
| LLM02 | Sensitive Information Disclosure | LLM exposes PII, credentials, or confidential system prompt contents |
| LLM03 | Supply Chain | Vulnerabilities in third-party models, datasets, fine-tuning pipelines, or plugins |
| LLM04 | Data and Model Poisoning | Manipulation of training or fine-tuning data to alter model behavior |
| LLM05 | Improper Output Handling | Downstream processing of LLM output without validation or sanitization |
| LLM06 | Excessive Agency | LLM agent granted more permissions, tools, or autonomy than required for its task |
| LLM07 | System Prompt Leakage | System prompt contents exposed through elicitation or verbose error output |
| LLM08 | Vector and Embedding Weaknesses | Manipulation of embedding stores, semantic search, or RAG retrieval pipelines |
| LLM09 | Misinformation | Model produces confidently incorrect outputs used in security-critical decisions |
| LLM10 | Unbounded Consumption | Resource exhaustion via adversarial inputs that trigger disproportionate compute |

---

## Red-Teaming LLMs

LLM red-teaming is the structured, adversarial evaluation of an LLM system to discover vulnerabilities before they are exploited. It differs from traditional software penetration testing: there is no code path to trace, no CVE to query, and success is often probabilistic rather than deterministic — the same input may or may not trigger a vulnerability depending on sampling parameters, context length, and model version.

### Red Team Process

**1. Scope Definition**
Define what the model is permitted and not permitted to do. Identify the harm categories most relevant to the deployment: CSAM, weapons synthesis, PII exfiltration, unauthorized actions (for agents), brand damage, and so on. Clarify which behaviors are safety-critical versus policy violations.

**2. Threat Model**
Identify who can interact with the system (anonymous users, authenticated users, internal operators), what input channels exist (direct user prompt, retrieved context, tool outputs, multi-agent messages), and what downstream impact is possible (UI rendering, API calls, file writes, emails).

**3. Attack Execution**
- **Manual adversarial prompting** — role-play personas, hypothetical framings, many-shot examples, encoding tricks, instruction hierarchies
- **Automated scanning** with tools like Garak (probes across hundreds of vulnerability classes), PyRIT (Microsoft's AI red-teaming toolkit), or custom harnesses
- **Indirect injection testing** — inject payloads into every external data source the system retrieves and verify whether the model executes them

**4. Documentation and Scoring**
Record every successful attack with: input payload, model response, harm category, reproducibility rate across 10+ trials, and severity rating. Use the model's stated policy as the ground truth for what constitutes a violation.

**5. Remediation and Retest**
Classify failures by root cause: training-time (safety training gap), inference-time (missing guardrails), or application-level (insecure output handling, excessive agency). Retest all fixed vulnerabilities after remediation; regression is common.

---

## Defensive Controls

### Prompt Injection Defenses

| Control | Layer | Effectiveness | Notes |
|---|---|---|---|
| Input validation and sanitization | Application | Low–Medium | Signatures are trivially bypassed; useful as one layer only |
| Instruction hierarchy enforcement | Model | Medium | System prompt marked as higher trust than user input; bypassable but raises the bar |
| Separate retrieval from instruction context | Architecture | Medium–High | Retrieved content treated as data, never as instructions; requires architectural discipline |
| LLM-based input/output classifiers | Application | Medium | Second model judges whether first model's output violates policy; adversarial prompt can target the classifier |
| Privilege separation for tool-use agents | Architecture | High | Minimal-permission tools; human-in-the-loop confirmation for high-impact actions |
| Canary tokens in system prompts | Detection | Medium | Leaked token detection alerts on exfiltration attempts |

### Supply Chain and Model Security

- Pin pretrained model weights to a verified hash and store in a controlled registry; never pull from public hubs without integrity verification
- Audit fine-tuning datasets for poisoning before training; track data provenance with lineage tooling
- Scan models for known backdoor patterns before deployment using tools such as TrojAI or model scanning services
- Apply SLSA provenance to model artifacts the same way it is applied to software build artifacts
- Treat model weights as high-value IP: encrypt at rest, restrict access via IAM, and log all access to model artifacts

### Agentic System Hardening

- **Minimal privilege** — grant tools only the permissions they need for the defined task; never grant write access when read suffices
- **Explicit confirmation gates** — require human approval before irreversible or high-impact actions (send email, delete file, make API call with side effects)
- **Output sandboxing** — execute LLM-generated code in an isolated runtime with no network access and no persistent storage by default
- **Action logging and auditability** — log every tool call with the full context that triggered it; maintain an immutable audit trail
- **Scope bounding** — define a strict task scope; reject or escalate any agent action that falls outside the originally stated objective

---

## Tools and Repositories

### Adversarial ML and Classical Attacks
- [Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) — IBM's Adversarial Robustness Toolbox (ART); the most comprehensive open-source library for adversarial attacks, defenses, and evaluation across frameworks (TensorFlow, PyTorch, Scikit-learn); essential for classical adversarial ML work
- [cleverhans-lab/cleverhans](https://github.com/cleverhans-lab/cleverhans) — Adversarial example library from Ian Goodfellow and Nicolas Papernot; reference implementations of FGSM, PGD, and other foundational attacks; widely cited in research
- [bethgelab/foolbox](https://github.com/bethgelab/foolbox) — Fast adversarial attack library supporting 30+ attack algorithms; integrates with PyTorch, TensorFlow, and JAX; good for benchmarking model robustness
- [Trusted-AI/AIX360](https://github.com/Trusted-AI/AIX360) — IBM's AI Explainability 360 toolkit; explainability methods used to audit model decision boundaries for bias and manipulation susceptibility

### LLM Security and Red-Teaming
- [leondz/garak](https://github.com/leondz/garak) — The most complete open-source LLM vulnerability scanner; 100+ probes covering prompt injection, jailbreaks, hallucination, information disclosure, and toxic content generation; runs against local models and hosted APIs; output structured for reporting
- [Azure/PyRIT](https://github.com/Azure/PyRIT) — Microsoft's Python Risk Identification Toolkit for generative AI; red-teaming framework for LLMs and multimodal models; supports automated attack orchestration with scoring and reporting
- [NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — NeMo Guardrails; programmable guardrail library for LLM applications; defines allowed and disallowed conversation flows using Colang; one of the more practical open-source guardrail implementations
- [protectai/rebuff](https://github.com/protectai/rebuff) — Prompt injection detection API and self-hardening library; detects prompt injection in user input before it reaches the LLM using heuristics, vectorstore lookup of known attacks, and an LLM classifier layer
- [BerriAI/litellm](https://github.com/BerriAI/litellm) — Unified LLM API proxy with built-in logging, rate limiting, and budget controls; useful for instrumenting LLM API calls for security monitoring
- [langchain-ai/langchain](https://github.com/langchain-ai/langchain) — The most widely deployed LLM application framework; understanding its architecture is essential for threat modeling LangChain-based applications; security issues are regularly disclosed in this codebase

### Scanning, Guardrails, and Monitoring
- [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) — Meta's open-source AI safety and security toolkit; includes Llama Guard (input/output safety classifier), CyberSec Eval (LLM cybersecurity capability benchmarks), and Code Shield (insecure code detection)
- [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — Vigil; real-time LLM input/output security scanning library with prompt injection detection, PII detection, and canary token injection for exfiltration detection
- [protectai/llm-guard](https://github.com/protectai/llm-guard) — Production-ready LLM security guardrail library; input and output scanners covering prompt injection, PII, toxic content, code security, and prompt leakage; designed for inline deployment in LLM serving pipelines

### MLOps Security and Supply Chain
- [DataDog/guarddog](https://github.com/DataDog/guarddog) — Malicious package detection for PyPI and npm; relevant for securing ML dependency pipelines where researchers regularly install packages from public registries
- [microsoft/counterfit](https://github.com/azure/counterfit) — Microsoft's command-line tool for security testing of AI systems; supports adversarial attack execution against local and remote ML models with minimal setup
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — Credential and secret scanning; critical for ML pipelines where API keys, Hugging Face tokens, and cloud credentials are frequently hardcoded in notebooks and training scripts

---

## Certifications

| Cert | Provider | Focus | Notes |
|---|---|---|---|
| [GAISC](https://www.giac.org/certifications/artificial-intelligence-security-certified-gaisc/) (GIAC AI Security Certified) | SANS Institute | AI/ML security fundamentals, LLM threats, governance | Newest GIAC cert in this domain; exam-based |
| [Certified AI Red Teamer](https://learn.microsoft.com/en-us/credentials/) | Microsoft | LLM red-teaming methodology, responsible AI | Vendor-specific; Microsoft-aligned curriculum |
| [AI Security Practitioner](https://www.isaca.org/) | ISACA | AI risk, governance, and security management | Governance-oriented; complements technical certs |
| [AWS Certified AI Practitioner](https://aws.amazon.com/certification/certified-ai-practitioner/) | AWS | AI/ML services on AWS, responsible AI, governance | Vendor-specific; useful for cloud AI security roles |
| [Professional Machine Learning Engineer](https://cloud.google.com/certification/machine-learning-engineer) | Google Cloud | ML system design and security on GCP | Vendor-specific; relevant for GCP-focused practitioners |

*Note: Dedicated AI/ML security certifications are still maturing as of 2025–2026. SANS SEC595 (Applied Data Science and AI/ML for Cybersecurity Professionals) is the most technically rigorous course in this space, though it leads to the GAISC rather than a standalone certification.*

---

## Governance and Compliance

AI security intersects with a rapidly expanding regulatory landscape. Key frameworks practitioners encounter in enterprise settings:

| Framework / Regulation | Scope | Key Requirements |
|---|---|---|
| [NIST AI RMF (AI 100-1)](https://www.nist.gov/artificial-intelligence) | US voluntary framework | Risk governance: GOVERN, MAP, MEASURE, MANAGE functions; adversarial ML explicitly addressed |
| [EU AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689) | EU mandatory (2024) | Risk-tiered regulation; high-risk AI systems require security testing, logging, and human oversight |
| [NIST AI 100-2e (Adversarial ML)](https://airc.nist.gov/Docs/1) | US technical guidance | Taxonomy of adversarial ML attacks and mitigations; companion to AI RMF for practitioners |
| [ISO/IEC 42001](https://www.iso.org/standard/81230.html) | International standard | AI management system standard; governance, risk, and audit requirements |
| [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | Community standard | Vulnerability taxonomy for LLM applications; widely referenced in security assessments |
| [MITRE ATLAS](https://atlas.mitre.org/) | Community standard | Adversarial ML threat matrix; ATT&CK-compatible; used for threat modeling and red-team scope |

---

## Related Disciplines

- [Penetration Testing](penetration-testing.md) — Traditional application and infrastructure testing methodology that underpins LLM application security assessments
- [Red Teaming](red-teaming.md) — Adversarial simulation techniques and operator mindset foundational to LLM red-teaming
- [Container & Kubernetes Security](container-kubernetes-security.md) — Securing the infrastructure on which ML training and serving workloads run
- [Threat Hunting](threat-hunting.md) — Hypothesis-driven detection that applies to ML pipeline anomalies and model artifact tampering
- [SIEM and SOAR](siem-soar.md) — Monitoring and automated response for LLM API abuse, model exfiltration attempts, and adversarial input detection
