# AI & LLM Security

AI and Large Language Model security covers two intersecting domains: securing AI systems against adversarial attack, and understanding how AI enables new categories of offensive capability. As organizations deploy LLMs in production, a distinct class of vulnerabilities has emerged — prompt injection, jailbreaking, training data poisoning, model inversion, and supply-chain attacks on model weights — while defenders simultaneously explore how AI agents can automate red-teaming, accelerate threat detection, and reason over massive datasets.

This is the fastest-moving field in security. Threat taxonomies like MITRE ATLAS are maturing in public, the OWASP LLM Top 10 has become the reference framework for application-layer LLM risks, and the researchers defining best practices are doing so in real time. Practitioners entering this space need strong security fundamentals combined with enough ML knowledge to reason about model behavior — deep research experience is not required, but understanding what LLMs can and cannot do is essential for building meaningful threat models.

---

## Where to Start

AI security demands fluency in both ML fundamentals and traditional offensive/defensive security. Start with a concrete threat model: decide whether you want to focus on attacking and evaluating AI systems or on defending them in production, then expand outward from there. MITRE ATLAS is the closest equivalent to ATT&CK for AI/ML — the best single framework for building a shared vocabulary. Start there, then work through the OWASP LLM Top 10 to understand application-level risks.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | LLM architecture basics, prompt injection concepts, OWASP LLM Top 10 threat categories, MITRE ATLAS framework | Anthropic's free courses (GitHub), OWASP LLM Top 10, MITRE ATLAS |
| Practitioner | Red-teaming LLM deployments, evaluation frameworks, guardrail implementation, AI-assisted security tooling | Microsoft PyRIT docs, NVIDIA garak, DEF CON AI Village talks (YouTube, free) |
| Advanced | Adversarial ML research, AI supply chain security, autonomous agent security, threat taxonomy contribution | MITRE ATLAS in depth, ArXiv adversarial ML papers, AI Village CTFs, BIML architectural risk analysis |

---

## Free Training

- [Anthropic Courses](https://github.com/anthropics/courses) — Anthropic's official free courses covering prompt engineering, tool use, AI safety, and responsible Claude deployment; the most practical starting point for understanding LLM behavior from the model creator's perspective
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — The definitive free reference for LLM application security risks; covers prompt injection, insecure output handling, training data poisoning, model denial of service, and supply-chain vulnerabilities
- [DEF CON AI Village Talks](https://www.youtube.com/@AIVillage) — Free YouTube archive of AI Village talks from DEF CON covering jailbreaking, red-teaming, AI-enabled attacks, and adversarial ML from leading practitioners
- [Microsoft AI Red Team Resources](https://learn.microsoft.com/en-us/security/ai-red-team/) — Microsoft's public guidance on AI red-teaming methodology, threat modeling for AI systems, and lessons from their internal AI Red Team
- [MITRE ATLAS](https://atlas.mitre.org) — Free adversarial threat landscape framework for AI systems; the ATT&CK equivalent for machine learning with real-world case studies from actual model attacks
- [Google Secure AI Framework (SAIF)](https://safety.google/cybersecurity-advancements/saif/) — Google's free framework covering six core elements of securing AI systems; useful for building organizational AI security programs
- [ArXiv ML Security Papers](https://arxiv.org/search/?searchtype=all&query=adversarial+machine+learning) — Free pre-publication adversarial ML and LLM security research; the primary venue for cutting-edge findings before they reach courses
- [BHIS Webcasts on AI Threats](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering AI-enabled offensive techniques and defending against AI-generated threats
- [LLM Security Resource Hub](https://llmsecurity.net) — Curated aggregator of LLM security research, attack papers, and real-world vulnerability disclosures; excellent for staying current with the pace of the field
- [Anthropic Claude Cookbooks](https://github.com/anthropics/claude-cookbooks) — Jupyter notebooks covering secure API interaction patterns, tool use, and agentic workflow design
- [SANS SEC595 Content Previews](https://www.youtube.com/@SansInstitute) — SANS Applied Data Science and AI/ML for Cybersecurity course previews; while SEC595 is a SANS course (not a standalone certification), the freely available summit content covers ML fundamentals, adversarial ML, and AI-enabled detection

---

## Tools & Repositories

### LLM Red Teaming & Evaluation
- [NVIDIA/garak](https://github.com/NVIDIA/garak) — Comprehensive LLM vulnerability scanner probing for hallucination, data leakage, prompt injection, jailbreaks, and dozens of other failure modes; the closest available automated LLM security assessment suite
- [microsoft/PyRIT](https://github.com/microsoft/PyRIT) — Microsoft's Python Risk Identification Toolkit; orchestration framework for automated red-teaming, adversarial prompt generation, and scoring LLM responses at scale
- [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) — AI-assisted penetration testing using LLMs to guide traditional pen-test workflows; demonstrates the dual-use nature of AI in security
- [QData/TextAttack](https://github.com/QData/TextAttack) — Framework for adversarial attacks, data augmentation, and adversarial training in NLP; foundational for understanding text-based model manipulation

### Prompt Injection Defense
- [protectai/rebuff](https://github.com/protectai/rebuff) — Self-hardening prompt injection detection using heuristics, an LLM-based classifier, and canary tokens to identify and block injection attempts
- [protectai/llm-guard](https://github.com/protectai/llm-guard) — Production-grade input/output security filtering for LLM applications; scans for prompt injection, sensitive data leakage, and harmful content at the API boundary
- [OWASP/www-project-top-10-for-large-language-model-applications](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) — The OWASP LLM Top 10 project repository; the essential reference for LLM deployment threat modeling
- [NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) — Open-source toolkit for adding programmable guardrails to LLM-based applications; topical, safety, and security rails defined in a custom DSL

### AI Attack Frameworks
- [Azure/counterfit](https://github.com/Azure/counterfit) — Microsoft's security testing tool for AI/ML models; CLI for adversarial attacks against ML models to assess robustness
- [Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) — IBM's Adversarial Robustness Toolbox (ART); comprehensive framework for attacks and defenses across evasion, poisoning, extraction, and inference threats
- [microsoft/CyberBattleSim](https://github.com/microsoft/CyberBattleSim) — Microsoft Research simulation using reinforcement learning agents to model network lateral movement; demonstrates AI-driven autonomous attack concepts

### Guardrails & Runtime Protection
- [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) — Python library for structured validation, output parsing, and safety checks on LLM responses; enforces schemas and constraints before outputs reach application logic
- [anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) — Official Anthropic Python SDK; the standard interface for building Claude-powered applications with proper input handling and response validation
- [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript) — Official Anthropic TypeScript/JavaScript SDK for Claude API integration with built-in safety system support
- [anthropics/claude-cookbooks](https://github.com/anthropics/claude-cookbooks) — Jupyter notebooks demonstrating secure API interaction patterns, tool use, and agentic workflow design

### AI-Assisted Security Tools
- [anthropics/courses](https://github.com/anthropics/courses) — Anthropic's free structured courses on prompt engineering, tool use, and responsible LLM deployment
- [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) — Meta's tools for assessing LLM safety including CyberSecEval benchmarks for cybersecurity risk in LLM-generated code
- [microsoft/msticpy](https://github.com/microsoft/msticpy) — Microsoft Threat Intelligence Python library with Azure Sentinel integration and AI-assisted threat hunting capabilities

### Research & Reference
- [Trusted-AI/AIX360](https://github.com/Trusted-AI/AIX360) — IBM's AI Explainability 360; explainability is a prerequisite for auditing model behavior and detecting backdoored or manipulated models

---

## Commercial & Enterprise Platforms

The AI security market is nascent but growing rapidly. These platforms address the specific challenges of securing LLM applications in production and evaluating AI systems for security weaknesses.

| Platform | Strength |
|---|---|
| **Lakera Guard** | Real-time prompt injection detection and LLM security firewall; integrates at the API layer to detect and block adversarial inputs, PII leakage, and jailbreak attempts; one of the most deployed commercial LLM security solutions |
| **Protect AI** | AI/ML security platform covering model scanning, MLOps pipeline protection, and LLM vulnerability assessment; the most comprehensive platform for organizations with significant ML infrastructure |
| **HiddenLayer** | AI detection and response; behavioral analysis of model inputs and outputs to detect adversarial attacks, model theft attempts, and prompt injection without requiring access to model internals |
| **Robust Intelligence (now part of Cisco)** — AI security testing and validation platform; automated red-teaming of LLMs and ML models with structured risk assessment; acquired by Cisco in 2024 |
| **AWS Bedrock Guardrails** | Native guardrails for Amazon Bedrock LLM deployments; content filtering, topic denial, PII redaction, and grounding checks integrated into the AWS AI platform |
| **Azure AI Content Safety** | Microsoft's API for detecting harmful content, prompt injection, and policy violations in LLM applications; native integration with Azure OpenAI Service and the broader Azure AI stack |
| **Google Vertex AI Safety Filters** | Content moderation and safety systems built into Google's Vertex AI platform; configurable harm categories and fine-grained safety thresholds for Gemini-based deployments |
| **Wiz AI Security** | Cloud security platform extending into AI workload protection; scanning model registries, detecting sensitive data in training datasets, and identifying misconfigured AI pipelines |
| **Snyk AI Security** | Developer-focused AI security scanning for LLM application code, identifying insecure patterns in AI application development |
| **Garak (NVIDIA, open source)** | While open-source, NVIDIA offers enterprise support and integration pathways; the most comprehensive automated LLM red-teaming tool with over 100 probe types |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Adversarial Machine Learning | Joseph, Nelson, Rubinstein, Tygar | The foundational academic text on ML system attacks; covers evasion, poisoning, and privacy attacks with rigorous threat modeling that predates LLMs but applies directly |
| The Alignment Problem | Brian Christian | Deep exploration of why AI systems fail to do what designers intend; understanding misalignment is foundational to understanding why AI security differs from traditional software security |
| AI Snake Oil | Narayanan & Kapoor | Critical examination of AI capability claims and failure modes; essential for calibrating threat models and avoiding both over- and under-estimating AI security risks |
| Security Engineering (3rd ed.) | Ross Anderson | Chapter 26 covers ML security; the surrounding threat modeling and system design chapters provide essential context for approaching AI security rigorously; free online |

---

## Certifications

Note: AI security is an emerging field and formal certification infrastructure is still maturing. Most practitioners build credibility through research, CTF performance, public tooling, and published work rather than credentials alone. Certifications that exist today may not reflect the field's current state — prioritize demonstrated skill.

- **GDAT** (GIAC Defending Advanced Threats) — Covers advanced defensive techniques including AI-enabled security tools and adversarial threat detection; the most applicable GIAC certification for AI security practitioners focused on defense
- **AWS Certified Machine Learning — Specialty** — Includes security domains for AI workloads on AWS; valuable for practitioners securing AI deployments in AWS environments; covers model protection and access control
- **Azure AI Engineer Associate (AI-102)** — Azure AI security controls, responsible AI principles, and secure AI service deployment in the Microsoft ecosystem
- **AI Bug Bounty Programs** — Anthropic, OpenAI, Google, and Meta run active bug bounty programs accepting AI-specific vulnerability reports; successful findings serve as stronger credentials than most formal certifications in this space

---

## Channels

- [AI Village @ DEF CON](https://www.youtube.com/@AIVillage) — The premier community for AI security research; annual DEF CON village with talks, CTFs, and red-team exercises; YouTube archive contains some of the best freely available AI security content anywhere
- [Anthropic Research](https://www.youtube.com/@anthropic-ai) — Research talks on AI safety, interpretability, and responsible deployment; direct insight into frontier model safety from a leading AI lab
- [Yannic Kilcher](https://www.youtube.com/@YannicKilcher) — Deep paper reviews of ML research including adversarial ML and AI safety topics; essential for engaging with the academic literature
- [Microsoft Security](https://www.youtube.com/@MicrosoftSecurity) — AI Red Team content, responsible AI research, and Azure AI security guidance
- [Two Minute Papers](https://www.youtube.com/@TwoMinutePapers) — Accessible summaries of recent AI research; useful for tracking capability advances that often precede new attack surfaces
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — AI-enabled offensive techniques and defending against AI-augmented attacks

---

## Who to Follow

- [@simonw](https://x.com/simonw) — Simon Willison; the most consistent and grounded voice on LLM security risks, prompt injection, and AI application security; his research has shaped how the field thinks about these threats
- [@goodside](https://x.com/goodside) — Riley Goodside; pioneered public prompt injection research; his early demonstrations established the threat category
- [@random_walker](https://x.com/random_walker) — Arvind Narayanan; Princeton professor, co-author of AI Snake Oil; rigorous critical analysis of AI capabilities and risks
- [@garymcgraw](https://x.com/garymcgraw) — Gary McGraw; software security pioneer now focused on AI security through BIML; publishes systematic architectural risk analysis of ML systems
- [@AIVillage_DC](https://x.com/AIVillage_DC) — DEF CON AI Village official; research, CTF announcements, and community findings
- [@wunderwuzzi23](https://x.com/wunderwuzzi23) — Johann Rehberger; prolific researcher on prompt injection and AI agent security; maintains a blog with dozens of real-world LLM attack demonstrations
- [@leonderczynski](https://x.com/leonderczynski) — Leon Derczynski; creator of garak; publishes on LLM evaluation, safety, and red-teaming methodology
- [@josephthacker](https://x.com/josephthacker) — AI security researcher publishing practical attack techniques for LLM-powered applications
- [@lakeraai](https://x.com/lakeraai) — Lakera AI; prompt injection research, attack benchmarks, and LLM security findings
- [@llm_sec](https://x.com/llm_sec) — Aggregator of LLM security research, vulnerability disclosures, and attack technique publications
- [@schneierblog](https://x.com/schneierblog) — Bruce Schneier; AI security policy and the broader implications of AI in adversarial contexts

---

## Key Resources

- [MITRE ATLAS](https://atlas.mitre.org) — The authoritative adversarial threat landscape framework for AI/ML systems; the ATT&CK equivalent for machine learning with real-world case studies
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — The most widely adopted framework for LLM application security risk; ten critical vulnerability categories with scenarios and mitigation guidance
- [NIST AI Risk Management Framework](https://airc.nist.gov/RMF) — NIST's comprehensive framework for managing risk across the AI system lifecycle; the governance foundation for regulated environments
- [Google SAIF](https://safety.google/cybersecurity-advancements/saif/) — Google's Secure AI Framework covering six core elements for building and securing AI systems
- [Anthropic Safety Research](https://www.anthropic.com/research) — Published research on Constitutional AI, interpretability, and safety evaluation from a leading frontier model developer
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — AI-assisted security analysis in practice; uses data-driven technique correlation to help analysts reason over ATT&CK at scale — the same class of capability that AI security practitioners are both building and defending against
- [LLM Security (llmsecurity.net)](https://llmsecurity.net) — Curated aggregator of LLM vulnerability research and real-world incident disclosures; the best single source for staying current
- [Microsoft AI Red Team Blog](https://www.microsoft.com/en-us/security/blog/topic/microsoft-ai-red-team/) — Case studies and methodology from Microsoft's dedicated AI Red Team practice
- [Berryville Institute of Machine Learning (BIML)](https://berryvilleiml.com) — Gary McGraw's systematic architectural risk analysis of ML systems; rigorous engineering perspective on AI security
- [ArXiv AI Security Papers](https://arxiv.org/search/?searchtype=all&query=llm+security) — Pre-publication adversarial ML and LLM security research; following this feed is essential given how rapidly new attack techniques emerge
