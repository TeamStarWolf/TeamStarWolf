# AI / ML Security

AI/ML security addresses the attack surface introduced by machine learning systems: the training pipeline, model artifacts, inference APIs, and the data they depend on. As ML systems move into high-stakes domains — fraud detection, autonomous vehicles, medical diagnosis, security tooling itself — the consequences of adversarial manipulation grow from academic curiosity to critical business and safety risk.

AI/ML security practitioners must understand both how to attack ML systems (poisoning training data, extracting model parameters, generating adversarial examples) and how to defend them (adversarial training, differential privacy, model monitoring, supply chain controls for ML artifacts). This discipline connects deeply with application security, cloud security, MLOps, and the emerging field of AI governance.

## Where to Start

| Level | Description | Free Resource |
|-------|-------------|---------------|
| Beginner | Understand the ML lifecycle and where security concerns arise at each stage. Learn the key threat categories: data poisoning, model extraction, adversarial examples, and membership inference. No prior ML security experience required | [NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf) |
| Intermediate | Study MITRE ATLAS (the ML-equivalent of ATT&CK), implement basic adversarial example generation with Foolbox or ART, and assess an MLOps pipeline (MLflow, DVC) for security weaknesses including model registry access controls and CI/CD integration | [MITRE ATLAS Navigator](https://atlas.mitre.org) |
| Advanced | Design adversarial training pipelines, implement differential privacy in model training (using TensorFlow Privacy or Opacus), conduct model extraction attacks against black-box APIs, and build ML-specific threat models integrating ATLAS techniques with NIST AI RMF risk assessments | [Adversarial Robustness Toolbox (ART) Documentation](https://adversarial-robustness-toolbox.readthedocs.io) |

## Free Training

| Platform | URL | What You Learn |
|----------|-----|----------------|
| MITRE ATLAS | https://atlas.mitre.org | Adversarial ML tactics, techniques, case studies — the AI security equivalent of ATT&CK |
| NIST AI RMF | https://www.nist.gov/artificial-intelligence | Govern, Map, Measure, Manage functions for AI risk; free playbook and framework |
| Google Responsible AI Practices | https://ai.google/responsibilities/responsible-ai-practices/ | Fairness, interpretability, and security in ML system design |
| Microsoft Responsible AI Resources | https://www.microsoft.com/en-us/ai/responsible-ai | Azure AI security architecture and responsible AI tooling |
| Adversarial Robustness Toolbox Tutorials | https://github.com/Trusted-AI/adversarial-robustness-toolbox/tree/main/notebooks | Hands-on Jupyter notebooks for ART attacks and defenses |
| garak Documentation | https://github.com/leondz/garak | LLM vulnerability scanner — probing models for harmful outputs, prompt injection, and leakage |
| CleverHans Tutorials | https://github.com/cleverhans-lab/cleverhans | Adversarial example generation and defense implementation tutorials |

## Tools & Repositories

| Tool | Description | Link |
|------|-------------|-------|
| Adversarial Robustness Toolbox (ART) | IBM's comprehensive Python library for adversarial attacks and defenses across ML frameworks (TensorFlow, PyTorch, Keras, scikit-learn) | https://github.com/Trusted-AI/adversarial-robustness-toolbox |
| Foolbox | Fast and flexible adversarial attack library supporting 40+ attack methods; works with PyTorch, TensorFlow, and JAX | https://github.com/bethgelab/foolbox |
| CleverHans | Reference implementation of adversarial example attacks and defenses; originally from Google Brain and OpenAI | https://github.com/cleverhans-lab/cleverhans |
| TextAttack | Adversarial attacks, data augmentation, and adversarial training for NLP models | https://github.com/QData/TextAttack |
| garak | LLM vulnerability scanner — probes language models for prompt injection, data leakage, hallucination, harmful outputs, and jailbreak susceptibility | https://github.com/leondz/garak |
| ModelScan | Scans ML model files (pickle, ONNX, TensorFlow SavedModel) for malicious serialization payloads and supply chain attacks | https://github.com/protectai/modelscan |
| Counterfit | Microsoft's CLI for security testing of AI systems — supports black-box and white-box attacks across multiple frameworks | https://github.com/Azure/counterfit |
| PrivacyMeter | Membership inference attack framework for evaluating training data privacy leakage from deployed models | https://github.com/privacytrustlab/ml_privacy_meter |
| Audit-AI | Fairness and bias auditing toolkit with security implications for discriminatory model behavior | https://github.com/pymetrics/audit-ai |
| TensorFlow Privacy / Opacus | Libraries for differentially private training of TensorFlow and PyTorch models respectively | https://github.com/tensorflow/privacy |

## Commercial Platforms

| Platform | Description |
|----------|-------------|
| HiddenLayer Model Scanner | Enterprise ML model security platform detecting backdoors, poisoning, and adversarial vulnerabilities in model artifacts |
| Protect AI Guardian | ML model and pipeline security platform; integrates with model registries (MLflow, Hugging Face, SageMaker) |
| Robust Intelligence | AI security testing platform covering adversarial robustness, data quality, and model risk assessment |
| Arthur AI | ML monitoring platform with drift detection, fairness monitoring, and anomalous prediction alerting |
| Fiddler AI | Explainability and monitoring platform with security-relevant anomaly detection in model outputs |
| Microsoft Azure Responsible AI | Integrated suite in Azure ML for interpretability, fairness, differential privacy, and adversarial robustness |
| AWS SageMaker Clarify | Bias detection and model explainability with data drift monitoring for deployed SageMaker models |
| Google Vertex AI Model Monitoring | Production ML monitoring for data drift, prediction skew, and anomalous inference patterns |
| Lakera Guard | Real-time LLM security gateway detecting prompt injection, sensitive data leakage, and policy violations |
| CalypsoAI | Enterprise AI security platform for testing, monitoring, and governing LLM deployments |

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---------|--------|-----------|
| SA-11 | System and Services Acquisition | Developer Testing and Evaluation — mandates adversarial testing of ML systems before deployment |
| SA-15 | System and Services Acquisition | Development Process Standards — requires security requirements in ML development, including data lineage and model validation |
| RA-3 | Risk Assessment | Risk Assessment — AI-specific risk assessment including adversarial threats, model failure modes, and data privacy risks |
| SI-3 | System and Information Integrity | Malicious Code Protection — analogous to model scanning for backdoors and trojaned model artifacts |
| SC-28 | System and Communications Protection | Protection of Information at Rest — encryption of training datasets, model weights, and feature stores |
| AU-6 | Audit and Accountability | Audit Record Review — monitoring inference API logs for extraction attack patterns (unusual query volumes, boundary exploration) |
| CA-2 | Assessment, Authorization, and Monitoring | Control Assessments — includes red-teaming ML systems as part of system authorization |

## ATT&CK and MITRE ATLAS Coverage

| Technique ID | Name | Tactic / Source | Relevance |
|-------------|------|-----------------|-----------|
| AML.T0043 | Craft Adversarial Data | MITRE ATLAS — ML Attack | Generating adversarial examples that cause misclassification in deployed models |
| AML.T0006 | Active Scanning of ML Infrastructure | MITRE ATLAS — Reconnaissance | Probing ML APIs to enumerate model type, architecture, and boundaries |
| AML.T0024 | Exfiltration via ML Inference API | MITRE ATLAS — Exfiltration | Using repeated API queries to extract training data or reconstruct model parameters (model extraction / membership inference) |
| AML.T0020 | Poison Training Data | MITRE ATLAS — Persistence | Corrupting training datasets to introduce backdoors or degrade model performance |
| AML.T0031 | Erode ML Model Integrity | MITRE ATLAS — Impact | Systematic degradation of model accuracy through adversarial data injection |
| T1588.001 | Obtain Capabilities: Malware | Resource Development | Acquiring or building adversarial example generators targeting specific production models |
| T1059 | Command and Scripting Interpreter | Execution | Compromising MLOps CI/CD pipelines to inject malicious training code or poisoned data |
| T1190 | Exploit Public-Facing Application | Initial Access | Exploiting insecure ML serving endpoints (unauthenticated Jupyter notebooks, MLflow, Kubeflow) for initial access |
| T1552 | Unsecured Credentials | Credential Access | Credentials embedded in ML training scripts, notebooks, or committed to model repositories |
| T1485 | Data Destruction | Impact | Deletion or corruption of training datasets or model artifacts — destroying months of ML work |

## ML Lifecycle Attack Surface

Each phase of the ML lifecycle presents distinct security threats:

| Phase | Key Threats | Defensive Controls |
|-------|-------------|-------------------|
| Data Collection | Data poisoning, adversarial web scraping, copyright/PII violations in training data | Data lineage tracking, input validation, anomaly detection on collected data |
| Data Preprocessing | Feature store tampering, label flipping, embedding injection | Signed data artifacts, access controls on feature stores, reproducible preprocessing |
| Model Training | Backdoor injection via poisoned data, supply chain attack on base models, compute resource theft | Isolated training environments, model provenance, differential privacy, reproducible training |
| Model Evaluation | Gaming evaluation metrics, test set contamination | Held-out test sets with strict access controls, multiple evaluation metrics, red-team evaluation |
| Deployment | Model file malware (pickle exploits), insecure serving infrastructure, container escape | ModelScan, signed model artifacts, container security, API authentication |
| Inference | Adversarial examples, model extraction, membership inference, evasion attacks | Rate limiting, input validation, output monitoring, adversarial training |
| Monitoring | Alert fatigue, drift masking, adversarial drift injection | Behavioral baselines, statistical drift detection, anomalous query pattern alerting |

## LLM-Specific Threats

For Large Language Model security, see the related disciplines below. Key LLM-specific attack categories not covered in classical ML security include:
- **Prompt Injection**: Adversarial inputs that override system instructions or hijack model behavior
- **Jailbreaking**: Bypassing safety filters and content policies through crafted prompts
- **Training Data Memorization**: Models that regurgitate verbatim training data including PII and credentials
- **Indirect Prompt Injection**: Malicious instructions embedded in documents, web pages, or tool outputs that the LLM processes

See [Adversarial AI Attacks](adversarial-ai-attacks.md) and [AI LLM Security](ai-llm-security.md) for detailed LLM threat coverage.

## Certifications

| Certification | Issuer | Level | Notes |
|--------------|--------|-------|-------|
| CISSP (AI/ML Governance Domain) | (ISC)² | Advanced | Covers AI governance, ML system risk, and ethical considerations in security programs |
| Google Professional ML Engineer | Google | Intermediate | ML pipeline design, model deployment, and MLOps — foundational for ML security understanding |
| AWS Certified Machine Learning — Specialty | AWS | Intermediate | SageMaker, ML pipelines, and data security controls in AWS ML environments |
| Stanford AI Professional Certificate | Stanford Online | Intermediate | Broad AI/ML foundations with modules on AI ethics and responsible deployment |
| CDMP (Certified Data Management Professional) | DAMA | Intermediate | Data governance and quality — foundational for training data security |
| CompTIA AI Essentials | CompTIA | Entry | Entry-level AI concepts including basic security and ethical considerations |

*Note: No dedicated ML security certification exists as of 2025. Practitioners typically combine a security credential (CISSP, OSCP) with ML engineering credentials and MITRE ATLAS expertise.*

## Learning Resources

| Resource | Type | Notes |
|----------|------|-------|
| *Adversarial Machine Learning* — Battista Biggio & Fabio Roli | Paper/Book | Foundational academic work defining the field; comprehensive taxonomy of attacks |
| *Trustworthy Machine Learning* — Goodfellow, Papernot et al. | Online Book | Free resource covering robustness, privacy, fairness, and interpretability in ML | 
| MITRE ATLAS Case Studies | Online | Real-world documented adversarial ML attacks against production systems |
| NIST AI RMF 1.0 and Playbook | Standard | US government framework for AI risk — Govern, Map, Measure, Manage functions |
| *Security and Machine Learning* — Nicolas Papernot (Google) | Talks/Papers | Seminal research on adversarial examples, distillation as defense, and membership inference |
| Adversarial Robustness Toolbox Notebooks | Jupyter | Hands-on implementation of 40+ attack and defense methods |
| *The Malicious Use of Artificial Intelligence* — Brundage et al. | Paper | Comprehensive survey of AI security threats; free PDF |
| HiddenLayer ML Threat Intelligence Blog | Blog | Practical ML security research including model scanning and supply chain attacks |
| OWASP Top 10 for Machine Learning | Standard | Emerging OWASP project covering the top ML security risks |
| *Stealing Machine Learning Models via Prediction APIs* — Tramèr et al. | Paper | Foundational model extraction attack paper |

## MLOps Security

**ML Pipeline Attack Surface**

| Pipeline Stage | Attack Surface | Threat | Defense |
|---------------|---------------|--------|---------|
| Data collection | Web scraping, third-party data sources | Data poisoning, privacy violation | Curate sources; anomaly detection; differential privacy |
| Data labeling | Crowdsourced labeling (MTurk, Scale AI) | Label poisoning; backdoor injection | Label verification; redundant labeling; label poisoning detection |
| Model training | Cloud compute, shared infrastructure | Model theft via co-tenancy; gradient inversion in FL | Confidential computing (TEEs); secure aggregation in FL |
| Model storage | S3 buckets, MLflow, Hugging Face | Model exfiltration; malicious deserialization | Access controls; model signing; malicious file scanning |
| Model serving | REST API, gRPC endpoints | Adversarial inputs; model extraction; DoS | Rate limiting; input validation; anomaly detection; authentication |
| Model monitoring | Feedback loops | Concept drift exploitation; label manipulation | Drift detection; human review of edge cases |

**MLOps Security Tooling**

| Tool | Purpose |
|------|---------|
| ModelScan | Scan model files for malicious code (supports PyTorch, TensorFlow, ONNX formats) |
| Garak | LLM vulnerability scanner (jailbreaks, injection, toxicity probes) |
| Adversarial Robustness Toolbox (ART) | IBM; adversarial attack generation and defense evaluation |
| Foolbox | Adversarial example library; 30+ attack algorithms |
| TextAttack | Adversarial examples for NLP models |
| PrivacyMeter | Membership inference and attribute inference evaluation |
| ML Privacy Meter | Audit ML model privacy risks |
| TFX (TensorFlow Extended) | ML pipeline with built-in data validation |

**Supply Chain Security for AI**
- Model provenance: Who trained the model? On what data? With what code?
- Hugging Face model scanning: ModelScan (`modelscan -p model.pkl`) — detects malicious code in serialized models
- Serialization security: PyTorch saves in formats that can embed executable code; only load from trusted sources
- Safe serialization: SafeTensors format (Hugging Face) — safe alternative for model weights storage
- Dataset auditing: Check for duplicates, label errors (Cleanlab), PII in training data, copyright issues

## AI Security Governance

**NIST AI Risk Management Framework (AI RMF)**
- Govern: Policies, accountability, organizational practices for AI risk
- Map: Categorize AI risks in context of application
- Measure: Analyze, assess, and track identified risks
- Manage: Prioritize and implement risk treatments

**EU AI Act (2024) — Risk Tiers**

| Risk Level | Examples | Requirements |
|-----------|---------|-------------|
| Unacceptable (Banned) | Social scoring, subliminal manipulation, real-time biometric surveillance (public) | Prohibited |
| High Risk | Critical infrastructure, employment screening, credit scoring, law enforcement | Conformity assessment, transparency, human oversight, logging |
| Limited Risk | Chatbots, deepfakes | Transparency obligations (disclose AI nature) |
| Minimal Risk | Spam filters, recommendations | No specific requirements |

**Responsible AI Principles**
- Fairness: Detect and mitigate algorithmic bias (demographic parity, equalized odds)
- Transparency: Model cards, datasheets for datasets, explainable AI (SHAP, LIME)
- Privacy: Differential privacy, federated learning, data minimization
- Robustness: Adversarial testing; certified defenses; redundancy
- Accountability: Human oversight; audit trails; clear ownership of AI decisions

**Bias and Fairness Testing**
```python
# Fairlearn — fairness metrics and mitigation
from fairlearn.metrics import demographic_parity_difference, equalized_odds_difference

# Check if predictions differ across demographic groups
dpd = demographic_parity_difference(y_true, y_pred, sensitive_features=gender)
eod = equalized_odds_difference(y_true, y_pred, sensitive_features=gender)

print(f"Demographic Parity Difference: {dpd}")  # 0 = perfect fairness
print(f"Equalized Odds Difference: {eod}")
```

## Related Disciplines

- [Adversarial AI Attacks](adversarial-ai-attacks.md)
- [AI LLM Security](ai-llm-security.md)
- [Application Security](application-security.md)
- [Cloud Security](cloud-security.md)
- [Supply Chain Security](supply-chain-security.md)
- [Data Security](data-security.md)
- [DevSecOps](devsecops.md)
