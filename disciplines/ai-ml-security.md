# AI / ML Security

AI/ML security addresses the attack surface introduced by machine learning systems: the training pipeline, model artifacts, inference APIs, and the data they depend on. This discipline is distinct from LLM security (see [AI & LLM Security](ai-llm-security.md)), which focuses on large language model-specific threats such as prompt injection and jailbreaking. AI/ML security focuses on the broader class of learned model vulnerabilities that apply to image classifiers, fraud detection models, recommendation systems, autonomous systems, and any ML component in a production stack.

---

## Core Threat Categories

### Evasion Attacks (Inference-Time)

An adversary crafts inputs that cause a trained model to misclassify or produce incorrect output, without access to the model internals in the black-box case.

- **White-box evasion**: Attacker has full access to model weights and gradients. Methods: FGSM (Fast Gradient Sign Method), PGD (Projected Gradient Descent), C&W attack.
- **Black-box evasion**: Attacker can only query the model via API. Methods: boundary attack, HopSkipJump, square attack, transfer attacks using surrogate models.
- **Physical adversarial examples**: Perturbations printed or applied to real-world objects — stop sign stickers that fool autonomous vehicle classifiers, adversarial patches on clothing that defeat person detection.

**Impact**: Bypassing malware classifiers, CAPTCHA solvers, biometric authentication, intrusion detection systems, autonomous vehicle perception.

### Poisoning Attacks (Training-Time)

An adversary influences the training data or fine-tuning process to degrade model performance or install a backdoor.

| Attack Type | Description |
|---|---|
| Label flipping | Corrupt a fraction of training labels to degrade accuracy on targeted classes |
| Backdoor / trojan | Inject a hidden trigger pattern during training; model behaves normally except when trigger present |
| Gradient-based poisoning | For models trained with federated learning, a malicious participant submits poisoned gradient updates |
| Data injection | Poison a web-crawled or continuously updated dataset; affects models retrained on live data |

**Impact**: Persistent classifier bypass for any input bearing the trigger; degraded model reliability in targeted scenarios.

### Model Inversion

Reconstruct approximations of training data from a model's outputs or internal states.

- **Gradient inversion**: In federated learning, intercepted gradients can partially reconstruct training samples.
- **Model inversion attack**: Query the model repeatedly to reconstruct a representative sample for a given class — used to reconstruct faces from face recognition models.
- **GAN-based inversion**: Use a GAN trained against the target model to generate realistic training samples.

**Impact**: Exposure of sensitive training data (medical records, biometric data, proprietary business data).

### Membership Inference

Determine whether a specific data record was part of the model's training set.

- Statistical shadow model approach: train multiple shadow models on known data, then train a membership inference classifier on their outputs.
- Threshold-based approach: models tend to have higher confidence on training data; simple thresholding can reveal membership.

**Impact**: Privacy violation — confirms that an individual's record was used to train a model, relevant under GDPR and HIPAA.

### Model Extraction / Stealing

Reconstruct a functional approximation of a proprietary model by querying its API.

- Query the model on a representative input distribution, collect (input, output) pairs.
- Train a substitute model to replicate the decision boundary.
- The extracted model can be used to mount more effective white-box attacks or to steal IP.

**Impact**: Intellectual property theft; enables downstream white-box evasion attacks against the original model.

---

## MLSecOps — Securing the ML Pipeline

The ML development pipeline introduces attack surface at every stage.

Data Collection → Data Preprocessing → Training → Evaluation → Packaging → Deployment → Monitoring

Threats at each stage: data poisoning, supply chain dependency hijacking, backdoor injection, benchmark manipulation, serialization attacks, API security, model drift tampering.

### Data Pipeline Security

| Risk | Control |
|---|---|
| Untrusted training data sources | Data provenance tracking; cryptographic signing of datasets |
| Web-crawled data poisoning | Anomaly detection on data distributions; human review of label quality |
| Feature store tampering | Access controls, audit logging, immutable feature snapshots |
| Label poisoning by crowdworkers | Redundant labeling, agreement thresholds, anomaly detection |

### Model Artifact Security

- **Serialization attacks**: Python's pickle format allows arbitrary code execution on deserialization. Use safetensors or apply format validation before loading untrusted model files.
- **Model supply chain**: Downloading pretrained weights from untrusted sources without checksum verification introduces risk of trojanized models.
- **Dependency hijacking**: ML libraries (PyTorch, TensorFlow, Scikit-learn) have historically had CVEs; pin dependencies and use private package mirrors.

### Training Environment Security

- Isolate training jobs in containers with no outbound network access.
- Use secrets management (Vault, AWS Secrets Manager) rather than hardcoding API keys in training scripts.
- Restrict GPU cluster access; log all job submissions and model artifact writes.
- Validate hyperparameter inputs to prevent YAML deserialization attacks.

### Inference API Security

| Risk | Control |
|---|---|
| Model extraction via API | Rate limiting; query throttling; output perturbation |
| Adversarial input abuse | Input validation; adversarial detection classifiers |
| Sensitive output exposure | Output filtering; confidence score suppression |
| API authentication bypass | Standard API authentication (mTLS, API keys, OAuth) |

---

## Federated Learning Security

Federated learning distributes training across devices without centralizing raw data, but introduces unique threats.

- **Byzantine attacks**: Malicious participants send adversarial gradient updates to degrade the global model or embed backdoors.
- **Gradient inversion**: An honest-but-curious aggregation server can reconstruct training samples from submitted gradients.
- **Free-rider attacks**: Participants submit zero or random gradients without contributing real training updates.

**Defenses**: Robust aggregation (Krum, FedMedian, FLTrust); differential privacy on gradients; secure aggregation protocols; client authentication.

---

## Differential Privacy in ML

Differential privacy (DP) provides formal guarantees that model outputs do not reveal whether any individual was in the training set.

- **DP-SGD** (Differentially Private SGD): Clip per-sample gradients, then add calibrated Gaussian noise during training.
- **Privacy budget (epsilon)**: Smaller epsilon = stronger privacy guarantee but higher utility cost. Typical values: epsilon = 1–10 for practical ML.
- Implementations: TensorFlow Privacy, Opacus (PyTorch), Google DP library.

---

## MITRE ATLAS Framework

[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the AI/ML analog to MITRE ATT&CK.

| ATLAS Tactic | Description |
|---|---|
| Reconnaissance | Gather information about target ML systems (model API, architecture, training data) |
| Resource Development | Develop attack capabilities (surrogate models, adversarial tools) |
| Initial Access | Gain access to ML pipeline or model APIs |
| ML Model Access | Query model API, access model artifacts, insider access |
| Execution | Run adversarial attacks, poisoning scripts |
| Persistence | Embed backdoors in model weights or training pipelines |
| Defense Evasion | Craft adversarial examples that bypass detection |
| Exfiltration | Steal model weights, extract training data via inversion |
| Impact | Degrade model performance, cause incorrect decisions at scale |

Key ATLAS techniques: AML.T0000 (phishing for ML model credentials), AML.T0020 (poison training data), AML.T0043 (craft adversarial data), AML.T0006 (active scanning for ML systems).

---

## Tools

### Adversarial Attack Libraries

| Tool | Language | Description |
|---|---|---|
| [IBM Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox) | Python | Comprehensive library covering evasion, poisoning, extraction, inference attacks |
| [Foolbox](https://github.com/bethgelab/foolbox) | Python | Fast adversarial attacks: FGSM, PGD, boundary attack, HopSkipJump |
| [CleverHans](https://github.com/cleverhans-lab/cleverhans) | Python | Google Brain adversarial examples library; FGSM, JSMA, C&W |
| [TextAttack](https://github.com/QData/TextAttack) | Python | Adversarial attacks on NLP models; word substitution, character-level attacks |
| [Counterfit](https://github.com/Azure/counterfit) | Python | Microsoft CLI tool for security testing of ML systems via ATLAS techniques |

### Membership Inference and Privacy

| Tool | Description |
|---|---|
| [ML Privacy Meter](https://github.com/privacytrustlab/ml_privacy_meter) | Quantify privacy risk via membership inference |
| [TensorFlow Privacy](https://github.com/tensorflow/privacy) | DP-SGD training with privacy budget accounting |
| [Opacus](https://github.com/pytorch/opacus) | Differential privacy for PyTorch; per-sample gradient clipping |

### Model Scanning and Defense

| Tool | Description |
|---|---|
| [ModelScan](https://github.com/protectai/modelscan) | Scan model files (PyTorch, TensorFlow SavedModel) for malicious serialized code |
| [NB Defense](https://nbdefense.ai/) | Scan Jupyter notebooks for secrets, PII, and vulnerabilities |
| [Rebuff](https://github.com/protectai/rebuff) | Adversarial input detection API |

---

## Regulatory and Compliance Considerations

| Regulation | AI/ML Relevance |
|---|---|
| GDPR Article 22 | Right to explanation for automated decisions; model interpretability requirements |
| GDPR Article 35 | Data Protection Impact Assessment required for high-risk AI processing |
| EU AI Act (2024) | Risk-tiered regulation: prohibited AI (social scoring), high-risk AI (biometrics, critical infrastructure) requires conformity assessment |
| NIST AI RMF (2023) | AI Risk Management Framework: Govern, Map, Measure, Manage |
| CCPA / CPRA | Automated decision-making disclosure rights; opt-out of profiling |
| HIPAA | ML models trained on PHI subject to the same access and breach rules as the underlying data |

---

## Hardening Checklist

- [ ] Validate and sanitize all training data sources; log provenance
- [ ] Scan model artifact files before loading (ModelScan, safetensors validation)
- [ ] Pin all ML framework dependencies; use private package mirrors
- [ ] Rate-limit and authenticate inference APIs; suppress raw confidence scores where possible
- [ ] Apply adversarial training or certified defenses for high-stakes classifiers
- [ ] Implement input anomaly detection to flag distribution-shifted inputs at inference time
- [ ] Use DP-SGD or output perturbation for models trained on sensitive personal data
- [ ] Monitor models in production for performance drift that may indicate data poisoning
- [ ] Apply MITRE ATLAS TTPs as a threat model during ML system design reviews
- [ ] Conduct model extraction simulations before deploying high-value proprietary models

---

## Related Disciplines

- [AI & LLM Security](ai-llm-security.md) — prompt injection, jailbreaking, and LLM-specific threats
- [Application Security](application-security.md) — securing the web APIs that serve ML models
- [Cloud Security](cloud-security.md) — securing ML training infrastructure (SageMaker, Vertex AI, Azure ML)
- [Data Security](data-security.md) — protecting training data and feature stores
- [DevSecOps](devsecops.md) — integrating ML security into CI/CD pipelines
- [Privacy Engineering](privacy-engineering.md) — differential privacy, data minimization for ML
- [Threat Modeling](threat-modeling.md) — applying STRIDE and MITRE ATLAS to ML systems

---

## References

- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial threat landscape for AI systems
- [NIST AI RMF](https://airc.nist.gov/RMF_Overview) — AI Risk Management Framework
- [IBM ART Documentation](https://adversarial-robustness-toolbox.readthedocs.io/) — adversarial robustness toolbox docs
- [EU AI Act](https://artificialintelligenceact.eu/) — EU AI regulation overview
