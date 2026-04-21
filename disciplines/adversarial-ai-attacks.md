# Adversarial AI Attacks

AI systems occupy a unique position in the modern threat landscape: they are simultaneously high-value targets and increasingly powerful attack tools. Language models, image classifiers, fraud detectors, autonomous agents, and recommendation systems now underpin critical infrastructure, financial systems, healthcare diagnostics, and enterprise workflows — making them attractive targets for adversaries who understand their failure modes. Unlike traditional software, AI systems fail in ways that are non-obvious, often imperceptible, and deeply tied to their training data and model architecture. A carefully crafted input that looks innocuous to a human can reliably fool a state-of-the-art classifier; a single sentence embedded in a webpage can redirect an autonomous agent to exfiltrate data.

Understanding how AI systems are attacked is essential knowledge for defenders who need to anticipate novel failure modes, red teamers who must evaluate AI deployments against realistic adversarial pressure, and AI engineers who need to build systems that are robust by design rather than by assumption. The attacks covered in this discipline are not theoretical: prompt injection has been demonstrated against deployed production systems, adversarial examples defeat real biometric authentication, and data poisoning has been executed against models trained on live web data. Every organization deploying AI systems needs practitioners who understand this attack surface.

---

## Attack Categories

### Prompt Injection

Prompt injection exploits the fundamental architecture of large language models: a single context window that mixes system instructions, developer-supplied data, and user-supplied input with no hard enforcement boundary between them. When an LLM processes a context, it cannot reliably distinguish between instructions it should follow and data it should treat as inert — which means any untrusted text that reaches the context window is a potential instruction vector.

**Direct Prompt Injection** occurs when the attacker interacts with the model directly — typically via a chat interface or API — and submits input designed to override or extend the system prompt. Common patterns include:

- Instruction override: telling the model to disregard prior instructions
- Role reassignment: telling the model it is a different system without the original constraints
- Delimiter injection: using tokens the model interprets as ending the system prompt and beginning a new instruction block
- Privilege escalation: convincing the model the user has elevated permissions that permit otherwise restricted actions

**Indirect Prompt Injection** is more dangerous and harder to defend. Here the attacker does not interact with the model directly; instead, they embed malicious instructions in content that the model will later retrieve and process — a webpage the model browses, a document it summarizes, an email it reads, or a database record it looks up. The injected instructions then execute with the authority of the model's context when it processes that content. This is the primary attack vector against LLM agents with tool access.

**Why it works**: LLMs are trained to follow instructions and to be helpful. The same generalization that makes them capable of following novel instructions also makes them susceptible to instructions from unexpected sources. Instruction-following is a feature that becomes a vulnerability when the model cannot reliably determine who issued the instruction.

**Example attack flow (indirect)**: A user asks an LLM agent to summarize their inbox. One email contains hidden text instructing the agent to forward all emails before summarizing. If the model processes retrieved content without isolating it from instructions, it may treat the injected text as a legitimate directive and invoke its email-sending tools accordingly.

**References**: [OWASP LLM Top 10 — LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [Kai Greshake et al., "Not What You've Signed Up For"](https://arxiv.org/abs/2302.12173)

---

### Jailbreaking LLMs

Jailbreaking refers to a class of techniques that cause a model to produce outputs that its safety training was designed to prevent — harmful content, dangerous instructions, personal attacks, or policy violations. Unlike prompt injection (which typically targets a specific deployed system to override its instructions), jailbreaking usually targets the base model's safety training directly.

**Roleplay and Persona Attacks**
The attacker asks the model to adopt a persona that is not bound by the model's normal values — a fictional AI with no restrictions, an older uncensored version of itself, or a character who would provide the restricted information. These work because the model's role-playing capability and its safety training were optimized somewhat independently.

**Fictional Framing**
Wrapping a request in fictional framing distributes the safety signal across a creative context — writing a story in which a character provides dangerous information. The model may produce harmful content as dialogue within a narrative frame, effectively laundering the output through a fictional wrapper.

**Many-Shot Jailbreaking**
As context windows have expanded, researchers demonstrated that providing many (dozens to hundreds) of examples of the model compliantly answering progressively more sensitive questions conditions it toward compliance for the final harmful request. This exploits in-context learning — the same mechanism that makes LLMs few-shot learners makes them susceptible to compliance conditioning at scale.

**Encoding and Obfuscation Tricks**
Requesting output in Base64, ROT13, Leetspeak, reversed text, or other encodings can bypass safety classifiers that operate on the surface form of text. The model encodes a response it would not produce in plaintext. Variations include token smuggling (inserting zero-width characters) or asking the model to respond character by character.

**Virtualization / Simulation Attacks**
Asking the model to simulate what an unrestricted system would output exploits the model's ability to reason about other systems and agents. The model may reason that it is merely describing what another system would say — while producing the harmful content regardless.

**Automated Jailbreak Search**
Gradient-based methods like GCG (Greedy Coordinate Gradient) automatically discover adversarial suffixes appended to prompts that reliably elicit harmful outputs. These suffixes look like gibberish to humans but are highly effective jailbreak triggers, and they transfer across models.

**References**: [Perez & Ribeiro, "Ignore Previous Prompt"](https://arxiv.org/abs/2211.09527), [Zou et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models" (GCG)](https://arxiv.org/abs/2307.15043), [Anil et al., "Many-Shot Jailbreaking"](https://www.anthropic.com/research/many-shot-jailbreaking)

---

### Adversarial Inputs to ML Models

Classical machine learning models — particularly image classifiers, audio recognizers, and intrusion detection systems — are vulnerable to adversarial examples: inputs that have been imperceptibly modified to cause misclassification. To a human observer the input looks identical to the original; to the model it lands in a completely different class.

**Why adversarial examples exist**: Neural networks learn decision boundaries that are locally non-linear and can be dramatically different from human perception. The high-dimensional input space contains directions along which the model's confidence changes rapidly while human perception does not. Small perturbations along these directions cross decision boundaries.

**Fast Gradient Sign Method (FGSM)**
The simplest white-box attack. Compute the gradient of the model's loss with respect to the input, take the sign of each gradient component, and add a small perturbation in that direction. One step, computationally cheap, surprisingly effective. The perturbation magnitude is controlled by epsilon — a small value ensures human-imperceptible changes.

**Projected Gradient Descent (PGD)**
An iterative refinement of FGSM. Repeat gradient steps in a loop, projecting the result back into an L-infinity ball of radius epsilon around the original input after each step. More powerful than FGSM and the standard baseline for adversarial robustness evaluation. Introduced by Madry et al. and widely considered the de facto white-box attack benchmark.

**Carlini and Wagner (C&W) Attack**
Formulates adversarial example generation as an optimization problem minimizing both the perturbation magnitude and a custom loss function that enforces misclassification. More computationally expensive than PGD but finds smaller perturbations and is more effective at evading defenses designed to counter FGSM/PGD. Demonstrated to break many earlier adversarial defenses.

**Black-Box Attacks**
When model weights are not accessible, attackers use substitute models (trained on model outputs) to craft adversarial examples that transfer to the target, or use query-efficient methods like boundary attack, HopSkipJump, or Square Attack that estimate gradient information from output labels alone.

**Physical-World Adversarial Examples**
Perturbations can be materialized in the physical world: adversarial stickers on stop signs that fool autonomous vehicle classifiers, adversarial glasses that defeat face recognition, adversarial patches on clothing that cause person detectors to fail. These attacks are robust to camera angle, lighting, and printing variations.

**Impact**: Defeating malware classifiers (evasion), bypassing biometric authentication, fooling autonomous vehicle perception, evading network intrusion detection, manipulating medical image diagnostic systems.

**References**: [Goodfellow et al., FGSM (2014)](https://arxiv.org/abs/1412.6572), [Madry et al., PGD (2017)](https://arxiv.org/abs/1706.06083), [Carlini and Wagner, C&W (2016)](https://arxiv.org/abs/1608.04644), [Eykholt et al., Physical Adversarial Examples (2018)](https://arxiv.org/abs/1707.08945)

---

### Data Poisoning

Data poisoning attacks corrupt the training process by introducing malicious examples into the training dataset, causing the trained model to have degraded performance, misbehave on targeted inputs, or contain a hidden backdoor the attacker can activate.

**Availability Attacks (Degradation)**
Poison a fraction of training data — by flipping labels, injecting outliers, or adding corrupted samples — to degrade the model's overall accuracy or its performance on a specific class. Relatively detectable because the poisoned model simply performs worse.

**Backdoor / Trojan Attacks**
The attacker injects training examples containing a trigger pattern (a pixel patch, a specific word, a particular formatting pattern) with an incorrect label. The model learns to associate the trigger with the attacker's desired output class. At inference time, the model behaves correctly on clean inputs but produces the attacker's desired output whenever the trigger is present — a persistent hidden capability invisible to standard evaluation.

**Targeted Poisoning**
Rather than installing a trigger, the attacker crafts poisoning examples that cause the model to misclassify a specific target input (chosen by the attacker) while performing normally on all other inputs. Highly stealthy because standard evaluation metrics do not reveal the attack.

**Federated Learning Poisoning**
In federated learning, a malicious participant submits poisoned model updates (gradients) that push the global model toward the attacker's goals. Because the aggregation server does not inspect training data, this is harder to detect than centralized data poisoning.

**Web Data Poisoning**
Large models trained on web-crawled data are vulnerable to an attacker who publishes content designed to influence future training runs. By controlling web-accessible content, an attacker can embed poisoning examples that will be crawled and incorporated into future training datasets.

**Impact**: Bypassing malware detection, defeating content moderation, compromising medical diagnostic AI, enabling persistent backdoors in production models.

**References**: [Chen et al., "Targeted Backdoor Attacks on Deep Learning" (2017)](https://arxiv.org/abs/1712.05526), [Carlini et al., "Poisoning Web-Scale Training Datasets" (2023)](https://arxiv.org/abs/2302.10149)

---

### Model Extraction / Stealing

Model extraction attacks allow an adversary to reconstruct a functional approximation of a proprietary model — including its decision boundaries, confidence scores, and learned representations — by querying the model's API and observing its outputs.

**How it works**:
1. The attacker queries the target model on a large, representative input distribution and collects input-output pairs.
2. A substitute model is trained on these pairs to replicate the target's input-output mapping.
3. The substitute model approximates the original's decision boundary, sometimes closely enough to achieve comparable accuracy.

**Query efficiency**: Naive extraction requires many queries. Active learning and adaptive sampling strategies dramatically reduce query counts. The Knockoff Nets attack showed that only a fraction of the labeled training set is needed to extract a competitive substitute model.

**Exploitation paths after extraction**:
- Use the substitute model as a surrogate for crafting white-box adversarial examples against the original (adversarial examples transfer between models with similar decision boundaries)
- Deploy the stolen model commercially to avoid licensing costs or reproduce a proprietary capability
- Analyze the substitute model to infer information about the training data, architecture, or model capabilities

**Model inversion**: Related but distinct — model inversion attacks reconstruct training data (e.g., faces from a face recognition model) rather than the decision boundary, by optimizing inputs to maximize confidence for a target class.

**Impact**: Intellectual property theft, enabling downstream adversarial attacks, unauthorized reproduction of commercial models.

**References**: [Tramer et al., "Stealing Machine Learning Models" (2016)](https://arxiv.org/abs/1609.02943), [Orekondy et al., "Knockoff Nets" (2019)](https://arxiv.org/abs/1812.02766)

---

### Membership Inference

Membership inference attacks determine whether a specific data record was included in a model's training set. This is a privacy attack: if a model was trained on sensitive data (medical records, financial transactions, private communications), an attacker can confirm whether a particular individual's data was used.

**Why it works**: Models tend to behave differently on examples they were trained on versus unseen examples. Specifically, models often exhibit higher confidence, lower loss, and more consistent predictions on training data — a consequence of overfitting. This signal, while noisy, is statistically detectable.

**Shadow model attack (Shokri et al.)**:
1. Train multiple shadow models on datasets of known composition (attacker knows which records are in/out).
2. Collect the prediction vectors these shadow models produce on their training members vs. non-members.
3. Train a membership inference classifier on these labeled prediction vectors.
4. Apply the classifier to the target model's prediction vectors to infer membership.

**Likelihood ratio and threshold attacks**: Simpler approaches compare the model's confidence on a target record to a threshold calibrated on a reference population. Records with confidence above the threshold are classified as training members.

**Differential privacy as defense**: Adding calibrated noise during training (differential privacy) provides provable membership inference resistance at the cost of some model utility.

**Legal and regulatory implications**: Under GDPR, the right to erasure requires that data removed from a dataset no longer influences the model. Membership inference provides a way to audit whether model unlearning has been effective.

**References**: [Shokri et al., "Membership Inference Attacks Against Machine Learning Models" (2017)](https://arxiv.org/abs/1610.05820), [Carlini et al., "Membership Inference Attacks From First Principles" (2022)](https://arxiv.org/abs/2112.03570)

---

### AI Agent Hijacking

LLM agents combine language model reasoning with tool use — the ability to execute code, browse the web, read and write files, send emails, query databases, and call external APIs. This dramatically expands the blast radius of prompt injection and related attacks because a successfully hijacked agent can take consequential real-world actions, not just produce harmful text.

**Attack surface unique to agents**:
- **Tool invocation**: If an attacker can redirect what tools the agent calls and with what arguments, they can cause code execution, data exfiltration, or unauthorized transactions
- **Memory systems**: Agents with persistent memory can be poisoned through malicious content that gets written to memory and influences future sessions
- **Multi-agent pipelines**: In systems where agents call other agents, a compromised agent can propagate malicious instructions downstream across a trust chain
- **Environment observation**: Agents that read files, emails, or web pages are exposed to indirect prompt injection from any content in those environments

**Attack scenario — web browsing agent**:
A user asks an agent to research a topic. The attacker publishes a webpage containing hidden instructions directing the agent to perform unauthorized actions before returning results. If the agent has network tools and insufficient instruction-isolation guardrails, it may execute those instructions as if they were legitimate directives.

**Attack scenario — code execution agent**:
An agent is asked to analyze a data file. The file contains embedded content designed to be interpreted as instructions when processed. Without proper content isolation, the agent may pass the malicious content to its execution environment.

**Privilege escalation via agent chaining**: In multi-agent systems, an attacker who compromises an outer orchestrator agent can issue instructions to inner agents with higher privilege — for example, directing a privileged data-access agent to exfiltrate records.

**Defenses**: Principle of least privilege for agent tool access, human-in-the-loop confirmation for destructive or exfiltrating actions, prompt isolation between retrieved content and instructions, output monitoring for anomalous tool call patterns.

**References**: [Greshake et al., "Not What You've Signed Up For" (2023)](https://arxiv.org/abs/2302.12173), [OWASP LLM Top 10 — LLM06: Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

### Supply Chain Attacks on ML

The ML ecosystem has a rich software supply chain — pretrained model weights, open-source libraries, training datasets, and model hubs — each of which is a potential attack surface. Unlike traditional software supply chain attacks, ML supply chain attacks can be nearly invisible because a malicious model may perform correctly on standard benchmarks while containing a hidden backdoor.

**Unsafe Deserialization in ML Model Files**
Many ML frameworks have historically used serialization formats that execute arbitrary code when a model file is loaded. This means that loading a malicious model file can result in immediate code execution on the machine with no user interaction beyond a single load call — equivalent to running an untrusted binary. Safe serialization alternatives (such as the safetensors format) exist and should be preferred for any model loaded from an untrusted source.

**Malicious Pretrained Weights on HuggingFace and Model Hubs**
HuggingFace Hub hosts hundreds of thousands of model repositories. An attacker can publish weights that contain code-execution payloads in model files, implement a hidden backdoor (the model performs correctly on benchmarks but misbehaves when a trigger is present), use names resembling popular legitimate models (typosquatting), or replace legitimate model repositories after gaining contributor access.

**Compromised Training Pipelines**
ML training pipelines pull from multiple sources: package managers, data pipelines, and configuration files. A compromised dependency in any of these can inject malicious behavior or exfiltrate training data and model weights, analogous to traditional software supply chain attacks.

**Dataset Poisoning via Web Crawls**
Large models trained on web-crawled data are vulnerable to attackers who control web-accessible URLs included in the dataset index. By publishing carefully crafted content at those URLs before the dataset is assembled, an attacker can influence what the model learns — including installing backdoors in vision-language models by poisoning image-caption pairs.

**Mitigation**: Use safe serialization formats for model weights, verify model checksums against trusted manifests, scan model files with tools like ModelScan before loading, prefer models from verified organizations on model hubs, treat model loading as equivalent to code execution.

**References**: [Hugging Face Model Security](https://huggingface.co/docs/hub/security), [ProtectAI/modelscan](https://github.com/protectai/modelscan), [Carlini et al., "Poisoning Web-Scale Training Datasets" (2023)](https://arxiv.org/abs/2302.10149)

---

## MITRE ATLAS Techniques

[MITRE ATLAS](https://atlas.mitre.org) (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the authoritative taxonomy for adversarial AI techniques, analogous to ATT&CK for traditional cyber attacks. The matrix organizes techniques by tactics (the adversary's goal at each stage) and provides real-world case studies.

| ATLAS ID | Technique Name | Description |
|---|---|---|
| AML.T0043 | Craft Adversarial Data | Generate perturbed inputs (images, text, audio) to cause misclassification or unexpected model behavior |
| AML.T0018 | Backdoor ML Model | Insert a hidden trigger into a model during training or fine-tuning that activates on attacker-controlled inputs |
| AML.T0020 | Poison Training Data | Introduce malicious examples into the training dataset to degrade performance or implant a backdoor |
| AML.T0024 | Exfiltration via ML Inference API | Use the model inference endpoint to extract sensitive information about training data or model internals |
| AML.T0025 | Exfiltrate Model Artifacts via Cyber Intrusion | Steal model weights, hyperparameters, or training data through traditional intrusion techniques |
| AML.T0016 | Obtain Capabilities — ML Attack Tooling | Acquire adversarial ML libraries (ART, Foolbox, TextAttack) to conduct attacks |
| AML.T0040 | ML Model Inference API Access | Query a model API to gather information for extraction, membership inference, or evasion attacks |
| AML.T0031 | Erode ML Model Integrity | Degrade the reliability of a model through persistent interference with training updates |
| AML.T0012 | Valid Accounts | Use legitimate credentials to access ML platforms, model repositories, or training infrastructure |
| AML.T0048 | LLM Prompt Injection | Inject instructions into an LLM prompt via untrusted content to hijack the model's behavior |
| AML.T0051 | LLM Jailbreak | Use adversarial prompting to cause an LLM to bypass its safety training and produce restricted outputs |
| AML.T0054 | LLM Plugin Compromise | Exploit plugins or tool integrations connected to an LLM agent to achieve code execution or data exfiltration |
| AML.T0035 | ML Supply Chain Compromise | Introduce malicious components at any stage of the ML pipeline — data, model, library, or infrastructure |
| AML.T0044 | Full ML Model Access | Obtain complete access to model weights enabling white-box attacks and unrestricted analysis |

---

## Tools for Attacking AI

| Tool | Purpose | Link |
|---|---|---|
| **garak** | LLM vulnerability scanner; automated probing for prompt injection, jailbreaks, hallucination, data leakage, and dozens of other failure modes across local and API-hosted models | [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) |
| **PyRIT** | Python Risk Identification Toolkit for Generative AI; Microsoft's red-teaming framework for LLMs with multi-turn attack orchestration, scoring, and dataset support | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) |
| **ART (Adversarial Robustness Toolbox)** | IBM's comprehensive adversarial ML library; implements FGSM, PGD, C&W, backdoor attacks, membership inference, model extraction, and many defenses across TensorFlow, PyTorch, and scikit-learn | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Counterfit** | Microsoft's command-line security testing tool for AI systems; wraps ART and TextAttack with a unified interface for assessing ML model robustness | [github.com/Azure/counterfit](https://github.com/Azure/counterfit) |
| **PromptBench** | Unified evaluation framework for adversarial robustness of LLMs; implements adversarial prompt attacks and measures model sensitivity to input perturbations | [github.com/microsoft/promptbench](https://github.com/microsoft/promptbench) |
| **TextAttack** | Python framework for adversarial attacks and augmentation in NLP; implements dozens of word-level and character-level attacks against text classification models | [github.com/QData/TextAttack](https://github.com/QData/TextAttack) |
| **Foolbox** | Python toolbox for adversarial example generation; clean API supporting hundreds of attacks across PyTorch, TensorFlow, and JAX models | [github.com/bethgelab/foolbox](https://github.com/bethgelab/foolbox) |
| **CleverHans** | Adversarial example library from Google Brain; reference implementations of FGSM, JSMA, C&W, and other canonical attacks | [github.com/cleverhans-lab/cleverhans](https://github.com/cleverhans-lab/cleverhans) |
| **ModelScan** | Supply chain security scanner for ML model files; detects code-execution payloads in model serialization formats before loading | [github.com/protectai/modelscan](https://github.com/protectai/modelscan) |
| **Boofuzz** | Python-based network protocol fuzzer adaptable to ML API endpoints; useful for discovering unexpected behavior at inference APIs | [github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz) |
| **LLMFuzzer** | Fuzzing framework specifically for LLM APIs; generates and mutates prompts to discover jailbreaks and unexpected behaviors | [github.com/mnns/LLMFuzzer](https://github.com/mnns/LLMFuzzer) |
| **PromptMap** | Tool for systematic prompt injection testing in LLM applications and RAG pipelines | [github.com/reversengineered/PromptMap](https://github.com/reversengineered/PromptMap) |

---

## Hands-On Practice

### Beginner — Prompt Injection and Jailbreaking

- **[Gandalf (Lakera)](https://gandalf.lakera.ai)** — The most widely played prompt injection challenge; players attempt to extract a secret password from an LLM that has been instructed not to reveal it, across increasingly hardened levels. Essential first experience with prompt injection mechanics.
- **[HackAPrompt](https://www.hackaprompt.com)** — Competition-style prompt injection challenge with scored levels; teaches direct and indirect injection, instruction override, and delimiter attacks. Writeups available from previous competition rounds.
- **[Prompt Airlines (Wiz)](https://promptairlines.com)** — Indirect prompt injection challenge simulating an LLM agent; players inject through email and document content to hijack an autonomous agent.
- **[GPT Prompt Attack](https://gpa.43z.one)** — Prompt injection CTF; extract system prompts by overriding model instructions.

### Intermediate — Adversarial ML

- **[ART Tutorial Notebooks](https://github.com/Trusted-AI/adversarial-robustness-toolbox/tree/main/notebooks)** — IBM ART tutorial notebooks covering evasion, poisoning, extraction, and inference attacks with hands-on code.
- **[CleverHans Tutorials](https://github.com/cleverhans-lab/cleverhans/tree/master/tutorials)** — Hands-on notebooks implementing FGSM and iterative attacks against MNIST and CIFAR classifiers.
- **[RobustBench Leaderboard](https://robustbench.github.io)** — Benchmark for adversarial robustness; useful for understanding the state of the field and testing attacks against standardized models.
- **[AI Village CTF (DEF CON)](https://aivillage.org/competitions/)** — Annual adversarial ML challenges at DEF CON covering evasion, extraction, and LLM attacks.

### Advanced — Red Teaming and Agent Attacks

- **[Crucible (Dreadnode)](https://crucible.dreadnode.io)** — AI security challenge platform with practical red-teaming exercises against deployed models.
- **[DEFCON AI Village Red Team Exercises](https://aivillage.org)** — Community-run exercises focusing on real-world AI red teaming scenarios.
- **[MITRE ATLAS Case Studies](https://atlas.mitre.org/studies/)** — Real-world adversarial AI attack case studies organized by ATLAS technique; invaluable for understanding how these attacks manifest in practice.

---

## Detection and Mitigation

Understanding how attacks are detected is as important for attackers (to evade detection) as for defenders (to build effective controls). The following covers the primary defensive mechanisms and their limitations.

### Prompt Injection Detection
- **Input scanning**: LLM classifiers trained to detect injection patterns in user inputs; effective against known patterns, weak against novel formulations
- **Output monitoring**: Analyzing model outputs for anomalous content or instruction-like structures suggesting the model was hijacked
- **Context isolation**: Structuring prompts so retrieved content is clearly delimited from instructions; reduces but does not eliminate injection risk
- **Privilege separation**: Using separate model instances for instruction processing versus content processing

### Adversarial Example Detection
- **Adversarial training**: Training the model on adversarial examples (using iterative gradient-based methods) is the most effective defense, making the model more robust by including adversarial inputs in the training distribution
- **Certified defenses**: Randomized smoothing provides provable robustness certificates — the model's prediction is guaranteed to be stable within a given radius around clean inputs
- **Input preprocessing**: JPEG compression, bit-depth reduction, and feature squeezing can reduce adversarial perturbations but also reduce model accuracy
- **Detection networks**: Training a separate classifier to distinguish clean vs. adversarial inputs; often brittle against adaptive attacks

### Backdoor Detection and Mitigation
- **Neural Cleanse**: Reverse-engineer potential trigger patterns from a trained model; triggers appear as anomalously small perturbations that achieve high misclassification
- **Activation Clustering**: Training examples with different true labels but identical internal representations suggest a backdoor
- **STRIP**: Superimpose random images on inputs — clean predictions are disrupted, but backdoor-triggered predictions are robust, revealing the trigger
- **Dataset auditing**: Outlier detection on training data distributions before training begins

### Model Extraction Defense
- **Output truncation**: Return only top-k predictions or rounded confidence scores to reduce information available to extraction attacks
- **Rate limiting**: Restrict API query rates to increase extraction cost
- **Watermarking**: Embed verifiable patterns in model outputs that can identify extracted copies

### Supply Chain
- **Safe serialization formats**: Use formats designed to prevent code execution on load (e.g., safetensors) instead of formats that execute arbitrary code during deserialization
- **ModelScan**: Scan model files for code-execution payloads before loading
- **Model hash verification**: Verify checksums against trusted manifests before deploying model weights
- **Sandboxed loading**: Load untrusted model files in isolated environments without network access

---

## Adversarial Machine Learning Attacks

**Adversarial Examples (Evasion Attacks)**
- Definition: Carefully crafted inputs that cause ML model to misclassify with high confidence
- Classic example: Goodfellow et al. 2014 — panda image + imperceptible noise = gibbon (99.3% confidence)
- Types:
  - White-box: Full access to model gradients; most powerful (FGSM, PGD, C&W)
  - Black-box: Query-only access; no gradient access; harder but practical (ZOO, NES attacks)
  - Physical-world: Adversarial patches, glasses, stop sign stickers that fool real cameras (Eykholt et al. 2018)
- Security relevance: Bypass malware classifiers, face recognition, autonomous vehicle perception, spam filters

**Key Evasion Attack Algorithms**
- FGSM (Fast Gradient Sign Method): Single gradient step; fast; weak but demonstrates vulnerability
- PGD (Projected Gradient Descent): Multi-step; strongest known attack; standard for adversarial training
- C&W (Carlini & Wagner): Optimized attack finding minimal perturbation; defeats many defenses
- Adversarial patch: Print and place physical patch that universally fools classifiers in a scene

**Model Inversion Attacks**
- Goal: Reconstruct training data from model predictions
- Face reconstruction: Given facial recognition model, reconstruct what training faces look like
- Attribute inference: Given model, infer sensitive attributes of training subjects (medical conditions, demographics)
- Defense: Differential privacy; prediction confidence hiding; output smoothing

**Membership Inference Attacks**
- Goal: Determine if specific sample was in the training dataset
- Method: Training samples typically have higher confidence and lower loss than non-training samples
- Security impact: Can expose that specific individuals' data was used (medical records, private photos)
- Defense: Differential privacy; regularization; early stopping to reduce overfitting

**Data Poisoning Attacks**
- Clean-label poisoning: Add carefully crafted samples to training data causing model to misbehave on specific inputs
- Backdoor/Trojan attack: Insert trigger pattern; model behaves normally except when trigger present
- Model supply chain: Hugging Face malicious models; poisoned datasets on public repositories
- Defense: Data provenance; anomaly detection in training data; certified defenses

## MITRE ATLAS Framework

ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) — MITRE's ML threat matrix

**Key ATLAS Tactics and Techniques**

| Tactic | Technique | Example |
|--------|-----------|---------|
| Reconnaissance | AML.T0000 - Search for Victim | Finding ML model endpoints via API docs, LinkedIn, GitHub |
| Resource Development | AML.T0008 - Develop Capabilities | Building surrogate model for black-box transfer attacks |
| Initial Access | AML.T0012 - Valid ML Accounts | Compromising API keys for ML services |
| Execution | AML.T0040 - ML Supply Chain Compromise | Malicious PyPI/Conda package injecting backdoor |
| Evasion | AML.T0015 - Evade ML Model | Adversarial examples bypassing image classifier |
| Exfiltration | AML.T0024 - Invert ML Model | Model inversion to reconstruct training data |
| Impact | AML.T0031 - Erode ML Model Integrity | Poisoning deployed model's behavior |

**Security AI Applications and Their Attack Surfaces**

| Application | Attack Surface | Adversarial Technique | Impact |
|-------------|---------------|----------------------|--------|
| Malware classification | PE feature manipulation | Evasion attack (modify binary without breaking function) | Bypass detection |
| Spam/phishing detection | Adversarial text | Text-based evasion (typos, homoglyphs, paraphrasing) | Phishing delivery |
| Facial recognition | Physical adversarial examples | Adversarial glasses/makeup | Bypass authentication |
| Network intrusion detection | Packet manipulation | Feature-space evasion | IDS bypass |
| CAPTCHA solving | Neural network solvers | Black-box query attack | Bot automation |
| Autonomous vehicles | Camera adversarial patches | Physical adversarial examples | Safety risk |

## Defenses Against Adversarial ML

**Certified Defenses**
- Randomized smoothing: Add Gaussian noise during inference; provable robustness radius
- Certified training: Interval Bound Propagation (IBP) — verify no adversarial examples exist within epsilon ball
- Limitation: Certified defenses have significantly lower accuracy on clean data

**Practical Defenses**
- Adversarial training (PGD-AT): Include adversarial examples in training data; most practical defense
- Input preprocessing: JPEG compression, bit-depth reduction, feature squeezing — reduce adversarial perturbation signal
- Ensemble defenses: Multiple models must agree; harder to fool simultaneously
- Anomaly detection: Flag inputs with unusual gradient/activation patterns as potential adversarial examples
- Input validation: For LLMs, validate inputs against known injection patterns before passing to model

## Related Disciplines

- [ai-ml-security.md](ai-ml-security.md) — Defensive coverage of AI/ML systems: securing the ML pipeline, MLSecOps, model governance
- [ai-llm-security.md](ai-llm-security.md) — LLM-specific security: RAG security, LLM deployment hardening, agentic system security
- [red-teaming.md](red-teaming.md) — Adversarial simulation methodology; AI red teaming is a growing subdiscipline
- [offensive-security.md](offensive-security.md) — Core offensive techniques that apply to AI infrastructure and support AI-enabled attacks
