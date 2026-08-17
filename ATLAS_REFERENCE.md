# MITRE ATLAS Reference — Adversarial Threats to AI Systems

> **[MITRE ATLAS™](https://atlas.mitre.org/)** (Adversarial Threat Landscape for Artificial-Intelligence Systems) is ATT&CK for AI. It documents **170 techniques** (101 parent + 69 sub-techniques) across **16 tactics** that adversaries use against machine-learning and AI-enabled systems — grounded in real incidents and red-team results, not hypotheticals.

ATLAS deliberately mirrors the ATT&CK structure and reuses its tactic names where behavior is the same, then adds the two tactics unique to attacking AI:

| ATLAS-specific tactic | What the adversary is doing |
|---|---|
| **AI Model Access** | Obtaining some level of access to the model itself — API, inference endpoint, weights, or the physical environment — which is a prerequisite for most AI attacks |
| **AI Attack Staging** | Preparing the attack offline: crafting adversarial examples, poisoning data, building proxy/surrogate models, verifying the exploit before deploying it |

| | |
|---|---|
| **Tactics** | 16 |
| **Techniques** | 170 (101 parent, 69 sub-techniques) |
| **Mitigations** | 35 |
| **Navigator layers** | [ATLAS matrix](navigator/ai/atlas-matrix.json) · [case-study frequency](navigator/ai/atlas-case-study-frequency.json) |
| **Datasets** | [techniques](data/ai/atlas_techniques.jsonl) · [tactics](data/ai/atlas_tactics.jsonl) · [mitigations](data/ai/atlas_mitigations.jsonl) |

**Related in this library:** [AI Security Reference](AI_SECURITY_REFERENCE.md) (OWASP LLM Top 10, prompt injection, guardrails) · [AI & MCP Security](AI_MCP_SECURITY_REFERENCE.md) · [AI Offensive Security](AI_OFFENSIVE_SECURITY_REFERENCE.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md)

---

## The ATLAS matrix

| # | Tactic | Techniques | Description |
|---|---|--:|---|
| 1 | **[Reconnaissance](https://atlas.mitre.org/tactics/AML.TA0002)** | 12 | The adversary is trying to gather information about the AI system they can use to plan future operations. Reconnaissance consists… |
| 2 | **[Resource Development](https://atlas.mitre.org/tactics/AML.TA0003)** | 26 | The adversary is trying to establish resources they can use to support operations. Resource Development consists of techniques tha… |
| 3 | **[Initial Access](https://atlas.mitre.org/tactics/AML.TA0004)** | 15 | The adversary is trying to gain access to the AI system. The target system could be a network, mobile device, or an edge device su… |
| 4 | **[AI Model Access](https://atlas.mitre.org/tactics/AML.TA0000)** 🤖 | 4 | The adversary is attempting to gain some level of access to an AI model. AI Model Access enables techniques that use various types… |
| 5 | **[Execution](https://atlas.mitre.org/tactics/AML.TA0005)** | 13 | The adversary is trying to run malicious code embedded in AI artifacts or software. Execution consists of techniques that result i… |
| 6 | **[Persistence](https://atlas.mitre.org/tactics/AML.TA0006)** | 14 | The adversary is trying to maintain their foothold via AI artifacts or software. Persistence consists of techniques that adversari… |
| 7 | **[Privilege Escalation](https://atlas.mitre.org/tactics/AML.TA0012)** | 4 | The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain… |
| 8 | **[Defense Evasion](https://atlas.mitre.org/tactics/AML.TA0007)** | 16 | The adversary is trying to avoid being detected by AI-enabled security software. Defense Evasion consists of techniques that adver… |
| 9 | **[Credential Access](https://atlas.mitre.org/tactics/AML.TA0013)** | 6 | The adversary is trying to steal account names and passwords. Credential Access consists of techniques for stealing credentials li… |
| 10 | **[Discovery](https://atlas.mitre.org/tactics/AML.TA0008)** | 16 | The adversary is trying to figure out your AI environment. Discovery consists of techniques an adversary may use to gain knowledge… |
| 11 | **[Lateral Movement](https://atlas.mitre.org/tactics/AML.TA0015)** | 5 | The adversary is trying to move through your AI environment. Lateral Movement consists of techniques that adversaries may use to g… |
| 12 | **[Collection](https://atlas.mitre.org/tactics/AML.TA0009)** | 6 | The adversary is trying to gather AI artifacts and other related information relevant to their goal. Collection consists of techni… |
| 13 | **[AI Attack Staging](https://atlas.mitre.org/tactics/AML.TA0001)** 🤖 | 17 | The adversary is leveraging their knowledge of and access to the target system to tailor the attack. AI Attack Staging consists of… |
| 14 | **[Command and Control](https://atlas.mitre.org/tactics/AML.TA0014)** | 3 | The adversary is trying to communicate with compromised AI systems to control them. Command and Control consists of techniques tha… |
| 15 | **[Exfiltration](https://atlas.mitre.org/tactics/AML.TA0010)** | 9 | The adversary is trying to steal AI artifacts or other information about the AI system. Exfiltration consists of techniques that a… |
| 16 | **[Impact](https://atlas.mitre.org/tactics/AML.TA0011)** | 19 | The adversary is trying to manipulate, interrupt, erode confidence in, or destroy your AI systems and data. Impact consists of tec… |

> 🤖 = tactic unique to ATLAS (no ATT&CK equivalent).

---

## Reconnaissance
<a id="reconnaissance"></a>

[`AML.TA0002`](https://atlas.mitre.org/tactics/AML.TA0002) · 12 techniques

The adversary is trying to gather information about the AI system they can use to plan future operations. Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organizations' AI capabilities and research efforts. This information can be leveraged by the adv…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0000 Search Open Technical Databases](https://atlas.mitre.org/techniques/AML.T0000)** | 1 | Adversaries may search for publicly available research and technical documentation to learn how and where AI is used within a victim organization. The adversary can use this information to identify ta… |
| &nbsp;&nbsp;↳ [AML.T0000.000 Journals and Conference Proceedings](https://atlas.mitre.org/techniques/AML.T0000.000) | 0 | Many of the publications accepted at premier artificial intelligence conferences and journals come from commercial labs. Some journals and conferences are open access, ot… |
| &nbsp;&nbsp;↳ [AML.T0000.001 Pre-Print Repositories](https://atlas.mitre.org/techniques/AML.T0000.001) | 0 | Pre-Print repositories, such as arXiv, contain the latest academic research papers that haven't been peer reviewed. They may contain research notes, or technical reports… |
| &nbsp;&nbsp;↳ [AML.T0000.002 Technical Blogs](https://atlas.mitre.org/techniques/AML.T0000.002) | 0 | Research labs at academic institutions and company R&D divisions often have blogs that highlight their use of artificial intelligence and its application to the organizat… |
| **[AML.T0001 Search Open AI Vulnerability Analysis](https://atlas.mitre.org/techniques/AML.T0001)** | 0 | Much like the Search Open Technical Databases, there is often ample research available on the vulnerabilities of common AI models. Once a target has been identified, an adversary will likely try to id… |
| **[AML.T0003 Search Victim-Owned Websites](https://atlas.mitre.org/techniques/AML.T0003)** | 1 | Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain technical details about their AI-enabled products or services.… |
| **[AML.T0004 Search Application Repositories](https://atlas.mitre.org/techniques/AML.T0004)** | 1 | Adversaries may search open application repositories during targeting. Examples of these include Google Play, the iOS App store, the macOS App Store, and the Microsoft Store. Adversaries may craft sea… |
| **[AML.T0006 Active Scanning](https://atlas.mitre.org/techniques/AML.T0006)** | 0 | An adversary may probe or scan the victim system to gather information for targeting. This is distinct from other reconnaissance techniques that do not involve direct interaction with the victim syste… |
| **[AML.T0064 Gather RAG-Indexed Targets](https://atlas.mitre.org/techniques/AML.T0064)** | 0 | Adversaries may identify data sources used in retrieval augmented generation (RAG) systems for targeting purposes. By pinpointing these sources, attackers can focus on poisoning or otherwise manipulat… |
| **[AML.T0087 Gather Victim Identity Information](https://atlas.mitre.org/techniques/AML.T0087)** | 0 | Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee n… |
| **[AML.T0095 Search Open Websites/Domains](https://atlas.mitre.org/techniques/AML.T0095)** | 0 | Adversaries may search public websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as socia… |
| &nbsp;&nbsp;↳ [AML.T0095.000 Code Repositories](https://atlas.mitre.org/techniques/AML.T0095.000) | 0 | Adversaries may search public code repositories for information about a victim or victim system that can be used during targeting. Victims may store code or artifacts rel… |

## Resource Development
<a id="resource-development"></a>

[`AML.TA0003`](https://atlas.mitre.org/tactics/AML.TA0003) · 26 techniques

The adversary is trying to establish resources they can use to support operations. Resource Development consists of techniques that involve adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include AI artifacts, infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0002 Acquire Public AI Artifacts](https://atlas.mitre.org/techniques/AML.T0002)** | 1 | Adversaries may search public sources, including cloud storage, public-facing services, and software or data repositories, to identify AI artifacts. These AI artifacts may include the software stack u… |
| &nbsp;&nbsp;↳ [AML.T0002.000 Datasets](https://atlas.mitre.org/techniques/AML.T0002.000) | 1 | Adversaries may collect public datasets to use in their operations. Datasets used by the victim organization or datasets that are representative of the data used by the v… |
| &nbsp;&nbsp;↳ [AML.T0002.001 Models](https://atlas.mitre.org/techniques/AML.T0002.001) | 2 | Adversaries may acquire public models to use in their operations. Adversaries may seek models used by the victim organization or models that are representative of those u… |
| &nbsp;&nbsp;↳ [AML.T0002.002 AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0002.002) | 0 | Adversaries may acquire publicly accessible AI agent configuration files to understand agent capabilities, gain unauthorized access to tools and data sources, or identify… |
| **[AML.T0008 Acquire Infrastructure](https://atlas.mitre.org/techniques/AML.T0008)** | 0 | Adversaries may buy, lease, or rent infrastructure for use throughout their operation. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure soluti… |
| &nbsp;&nbsp;↳ [AML.T0008.000 AI Development Workspaces](https://atlas.mitre.org/techniques/AML.T0008.000) | 0 | Developing and staging AI attacks often requires expensive compute resources. Adversaries may need access to one or many GPUs in order to develop an attack. They may try… |
| &nbsp;&nbsp;↳ [AML.T0008.001 Consumer Hardware](https://atlas.mitre.org/techniques/AML.T0008.001) | 0 | Adversaries may acquire consumer hardware to conduct their attacks. Owning the hardware provides the adversary with complete control of the environment. These devices can… |
| &nbsp;&nbsp;↳ [AML.T0008.002 Domains](https://atlas.mitre.org/techniques/AML.T0008.002) | 0 | Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purch… |
| &nbsp;&nbsp;↳ [AML.T0008.003 Physical Countermeasures](https://atlas.mitre.org/techniques/AML.T0008.003) | 0 | Adversaries may acquire or manufacture physical countermeasures to aid or support their attack. These components may be used to disrupt or degrade the model, such as adve… |
| &nbsp;&nbsp;↳ [AML.T0008.004 Serverless](https://atlas.mitre.org/techniques/AML.T0008.004) | 0 | Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during… |
| &nbsp;&nbsp;↳ [AML.T0008.005 AI Service Proxies](https://atlas.mitre.org/techniques/AML.T0008.005) | 0 | Adversaries may utilize commercial proxy services that resell access to AI services such as frontier model APIs. This infrastructure can be used to conduct large-scale ca… |
| **[AML.T0016 Obtain Capabilities](https://atlas.mitre.org/techniques/AML.T0016)** | 0 | Adversaries may search for and obtain software capabilities for use in their operations. Capabilities may be specific to AI-based attacks Adversarial AI Attack Implementations or generic software tool… |
| &nbsp;&nbsp;↳ [AML.T0016.000 Adversarial AI Attack Implementations](https://atlas.mitre.org/techniques/AML.T0016.000) | 0 | Adversaries may search for existing open source implementations of AI attacks. The research community often publishes their code for reproducibility and to further future… |
| &nbsp;&nbsp;↳ [AML.T0016.001 Software Tools](https://atlas.mitre.org/techniques/AML.T0016.001) | 0 | Adversaries may search for and obtain software tools to support their operations. Software designed for legitimate use may be repurposed by an adversary for malicious int… |
| &nbsp;&nbsp;↳ [AML.T0016.002 Generative AI](https://atlas.mitre.org/techniques/AML.T0016.002) | 0 | Adversaries may search for and obtain generative AI models or tools, such as large language models (LLMs), to assist them in various steps of their operation. Generative… |
| **[AML.T0017 Develop Capabilities](https://atlas.mitre.org/techniques/AML.T0017)** | 0 | Adversaries may develop their own capabilities to support operations. This process encompasses identifying requirements, building solutions, and deploying capabilities. Capabilities used to support at… |
| &nbsp;&nbsp;↳ [AML.T0017.000 Adversarial AI Attacks](https://atlas.mitre.org/techniques/AML.T0017.000) | 0 | Adversaries may develop their own adversarial attacks. They may leverage existing libraries as a starting point (Adversarial AI Attack Implementations). They may implemen… |
| **[AML.T0019 Publish Poisoned Datasets](https://atlas.mitre.org/techniques/AML.T0019)** | 3 | Adversaries may Poison Training Data and publish it to a public location. The poisoned dataset may be a novel dataset or a poisoned variant of an existing open source dataset. This data may be introdu… |
| **[AML.T0020 Poison Training Data](https://atlas.mitre.org/techniques/AML.T0020)** | 6 | Adversaries may attempt to poison datasets used by an AI model by modifying the underlying data or its labels. This allows the adversary to embed vulnerabilities in AI models trained on the data that… |
| **[AML.T0021 Establish Accounts](https://atlas.mitre.org/techniques/AML.T0021)** | 0 | Adversaries may create accounts with various services for use in targeting, to gain access to resources needed in AI Attack Staging, or for victim impersonation. |
| **[AML.T0058 Publish Poisoned Models](https://atlas.mitre.org/techniques/AML.T0058)** | 1 | Adversaries may publish a poisoned model to a public location such as a model registry or code repository. The poisoned model may be a novel model or a poisoned variant of an existing open-source mode… |
| **[AML.T0060 Publish Hallucinated Entities](https://atlas.mitre.org/techniques/AML.T0060)** | 0 | Adversaries may create an entity they control, such as a software package, website, or email address to a source hallucinated by an LLM. The hallucinations may take the form of package names commands,… |
| **[AML.T0065 LLM Prompt Crafting](https://atlas.mitre.org/techniques/AML.T0065)** | 0 | Adversaries may use their acquired knowledge of the target generative AI system to craft prompts that bypass its defenses and allow malicious instructions to be executed. The adversary may iterate on… |
| **[AML.T0066 Retrieval Content Crafting](https://atlas.mitre.org/techniques/AML.T0066)** | 0 | Adversaries may write content designed to be retrieved by user queries and influence a user of the system in some way. This abuses the trust the user has in the system. The crafted content can be comb… |
| **[AML.T0079 Stage Capabilities](https://atlas.mitre.org/techniques/AML.T0079)** | 0 | Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Cap… |
| **[AML.T0104 Publish Poisoned AI Agent Tool](https://atlas.mitre.org/techniques/AML.T0104)** | 0 | Adversaries may create and publish poisoned AI agent tools. Poisoned tools may contain an LLM Prompt Injection, which can lead to a variety of impacts. Tools may be published to open source version co… |

## Initial Access
<a id="initial-access"></a>

[`AML.TA0004`](https://atlas.mitre.org/tactics/AML.TA0004) · 15 techniques

The adversary is trying to gain access to the AI system. The target system could be a network, mobile device, or an edge device such as a sensor platform. The AI capabilities used by the system could be local with onboard or cloud-enabled AI capabilities. Initial Access consists of techniques that use various entry vectors to gain their initial foothold within the system.

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0010 AI Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010)** | 3 | Adversaries may gain initial access to a system by compromising the unique portions of the AI supply chain. This could include Hardware, Data and its annotations, parts of the AI AI Software stack, or… |
| &nbsp;&nbsp;↳ [AML.T0010.000 Hardware](https://atlas.mitre.org/techniques/AML.T0010.000) | 0 | Adversaries may target AI systems by disrupting or manipulating the hardware supply chain. AI models often run on specialized hardware such as GPUs, TPUs, or embedded dev… |
| &nbsp;&nbsp;↳ [AML.T0010.001 AI Software](https://atlas.mitre.org/techniques/AML.T0010.001) | 2 | Adversaries may target software packages that are commonly used in AI-enabled systems or are part of the AI DevOps lifecycle. This can include deep learning frameworks us… |
| &nbsp;&nbsp;↳ [AML.T0010.002 Data](https://atlas.mitre.org/techniques/AML.T0010.002) | 4 | Data is a key vector of supply chain compromise for adversaries. Every AI project will require some form of data. Many rely on large open source datasets that are publicl… |
| &nbsp;&nbsp;↳ [AML.T0010.003 Model](https://atlas.mitre.org/techniques/AML.T0010.003) | 5 | AI-enabled systems often rely on open sourced models in various ways. Most commonly, the victim organization may be using these models for fine tuning. These models will… |
| &nbsp;&nbsp;↳ [AML.T0010.004 Container Registry](https://atlas.mitre.org/techniques/AML.T0010.004) | 0 | An adversary may compromise a victim's container registry by pushing a manipulated container image and overwriting an existing container name and/or tag. Users of the con… |
| &nbsp;&nbsp;↳ [AML.T0010.005 AI Agent Tool](https://atlas.mitre.org/techniques/AML.T0010.005) | 0 | Adversaries may target AI agent tools as a means to compromise a victim's AI supply chain. Tools add capabilities to AI agents, allowing them to interact with other servi… |
| **[AML.T0012 Valid Accounts](https://atlas.mitre.org/techniques/AML.T0012)** | 0 | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Credentials may take the form of usernames and passwords of individual user accounts or API keys… |
| **[AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015)** | 6 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. This techniq… |
| **[AML.T0049 Exploit Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0049)** | 0 | Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness… |
| **[AML.T0052 Phishing](https://atlas.mitre.org/techniques/AML.T0052)** | 2 | Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spe… |
| &nbsp;&nbsp;↳ [AML.T0052.000 Spearphishing via Social Engineering LLM](https://atlas.mitre.org/techniques/AML.T0052.000) | 2 | Adversaries may turn LLMs into targeted social engineers. LLMs are capable of interacting with users via text conversations. They can be instructed by an adversary to see… |
| &nbsp;&nbsp;↳ [AML.T0052.001 Deepfake-Assisted Phishing](https://atlas.mitre.org/techniques/AML.T0052.001) | 0 | Adversaries may use deepfakes (AI-generated synthetic images, audio, or video) in phishing campaigns to impersonate trusted individuals, executives, or organizations. The… |
| **[AML.T0078 Drive-by Compromise](https://atlas.mitre.org/techniques/AML.T0078)** | 0 | Adversaries may gain access to an AI system through a user visiting a website over the normal course of browsing, or an AI agent retrieving information from the web on behalf of a user. Websites can c… |
| **[AML.T0093 Prompt Infiltration via Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0093)** | 0 | An adversary may introduce malicious prompts into the victim's system via a public-facing application with the intention of it being ingested by an AI at some point in the future and ultimately having… |

## AI Model Access
<a id="ai-model-access"></a>

[`AML.TA0000`](https://atlas.mitre.org/tactics/AML.TA0000) · 4 techniques

The adversary is attempting to gain some level of access to an AI model. AI Model Access enables techniques that use various types of access to the AI model that can be used by the adversary to gain information, develop attacks, and as a means to input data to the model. The level of access can range from the full knowledge of the internals of the model to access to the physical environment where…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0040 AI Model Inference API Access](https://atlas.mitre.org/techniques/AML.T0040)** | 2 | Adversaries may gain access to a model via legitimate access to the inference API. Inference API access can be a source of information to the adversary (Discover AI Model Ontology, Discover AI Model F… |
| **[AML.T0041 Physical Environment Access](https://atlas.mitre.org/techniques/AML.T0041)** | 1 | In addition to the attacks that take place purely in the digital domain, adversaries may also exploit the physical environment for their attacks. If the model is interacting with data collected from t… |
| **[AML.T0044 Full AI Model Access](https://atlas.mitre.org/techniques/AML.T0044)** | 2 | Adversaries may gain full "white-box" access to an AI model. This means the adversary has complete knowledge of the model architecture, its parameters, and class ontology. They may exfiltrate the mode… |
| **[AML.T0047 AI-Enabled Product or Service](https://atlas.mitre.org/techniques/AML.T0047)** | 1 | Adversaries may use a product or service that uses artificial intelligence under the hood to gain access to the underlying AI model. This type of indirect model access may reveal details of the AI mod… |

## Execution
<a id="execution"></a>

[`AML.TA0005`](https://atlas.mitre.org/tactics/AML.TA0005) · 13 techniques

The adversary is trying to run malicious code embedded in AI artifacts or software. Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0011 User Execution](https://atlas.mitre.org/techniques/AML.T0011)** | 5 | An adversary may rely upon specific actions by a user in order to gain execution. Users may inadvertently execute unsafe code introduced via AI Supply Chain Compromise. Users may be subjected to socia… |
| &nbsp;&nbsp;↳ [AML.T0011.000 Unsafe AI Artifacts](https://atlas.mitre.org/techniques/AML.T0011.000) | 6 | Adversaries may develop unsafe AI artifacts that when executed have a deleterious effect. The adversary can use this technique to establish persistent access to systems.… |
| &nbsp;&nbsp;↳ [AML.T0011.001 Malicious Package](https://atlas.mitre.org/techniques/AML.T0011.001) | 5 | Adversaries may develop malicious software packages that when imported by a user have a deleterious effect. Malicious packages may behave as expected to the user. They ma… |
| &nbsp;&nbsp;↳ [AML.T0011.002 Poisoned AI Agent Tool](https://atlas.mitre.org/techniques/AML.T0011.002) | 0 | A victim may invoke a poisoned tool when interacting with their AI agent. A poisoned tool may execute an LLM Prompt Injection or perform AI Agent Tool Invocation. Poisone… |
| &nbsp;&nbsp;↳ [AML.T0011.003 Malicious Link](https://atlas.mitre.org/techniques/AML.T0011.003) | 0 | An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that w… |
| **[AML.T0050 Command and Scripting Interpreter](https://atlas.mitre.org/techniques/AML.T0050)** | 0 | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common featu… |
| **[AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)** | 6 | An adversary may craft malicious prompts as inputs to an LLM that cause the LLM to act in unintended ways. These "prompt injections" are often designed to cause the model to ignore aspects of its orig… |
| &nbsp;&nbsp;↳ [AML.T0051.000 Direct](https://atlas.mitre.org/techniques/AML.T0051.000) | 2 | An adversary may inject prompts directly as a user of the LLM. This type of injection may be used by the adversary to gain a foothold in the system or to misuse the LLM i… |
| &nbsp;&nbsp;↳ [AML.T0051.001 Indirect](https://atlas.mitre.org/techniques/AML.T0051.001) | 2 | An adversary may inject prompts indirectly via separate data channel ingested by the LLM such as include text or multimedia pulled from databases or websites. These malic… |
| &nbsp;&nbsp;↳ [AML.T0051.002 Triggered](https://atlas.mitre.org/techniques/AML.T0051.002) | 2 | An adversary may trigger a prompt injection via a user action or event that occurs within the victim's environment. Triggered prompt injections often target AI agents, wh… |
| **[AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053)** | 11 | Adversaries may use their access to an AI agent to invoke tools the agent has access to. LLMs are often connected to other services or resources via tools to increase their capabilities. Tools may inc… |
| **[AML.T0100 AI Agent Clickbait](https://atlas.mitre.org/techniques/AML.T0100)** | 0 | Adversaries may craft deceptive web content designed to bait Computer-Using AI agents or AI web browsers into taking unintended actions, such as clicking buttons, copying code, or navigating to specif… |
| **[AML.T0103 Deploy AI Agent](https://atlas.mitre.org/techniques/AML.T0103)** | 0 | Adversaries may launch AI agents in the victim's environment to execute actions on their behalf. AI agents may have access to a wide range of tools and data sources, as well as permissions to access a… |

## Persistence
<a id="persistence"></a>

[`AML.TA0006`](https://atlas.mitre.org/tactics/AML.TA0006) · 14 techniques

The adversary is trying to maintain their foothold via AI artifacts or software. Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence often involve leaving behind modified ML artifacts such as poisoned training data or manipulated AI models.

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0018 Manipulate AI Model](https://atlas.mitre.org/techniques/AML.T0018)** | 3 | Adversaries may directly manipulate an AI model to change its behavior or introduce malicious code. Manipulating a model gives the adversary a persistent change in the system. This can include poisoni… |
| &nbsp;&nbsp;↳ [AML.T0018.000 Poison AI Model](https://atlas.mitre.org/techniques/AML.T0018.000) | 5 | Adversaries may manipulate an AI model's weights to change it's behavior or performance, resulting in a poisoned model. Adversaries may poison a model by directly manipul… |
| &nbsp;&nbsp;↳ [AML.T0018.001 Modify AI Model Architecture](https://atlas.mitre.org/techniques/AML.T0018.001) | 3 | Adversaries may directly modify an AI model's architecture to re-define it's behavior. This can include adding or removing layers as well as adding pre or post-processing… |
| &nbsp;&nbsp;↳ [AML.T0018.002 Embed Malware](https://atlas.mitre.org/techniques/AML.T0018.002) | 1 | Adversaries may embed malicious code into AI Model files. AI models may be packaged as a combination of instructions and weights. Some formats such as pickle files are un… |
| **[AML.T0020 Poison Training Data](https://atlas.mitre.org/techniques/AML.T0020)** | 6 | Adversaries may attempt to poison datasets used by an AI model by modifying the underlying data or its labels. This allows the adversary to embed vulnerabilities in AI models trained on the data that… |
| **[AML.T0061 LLM Prompt Self-Replication](https://atlas.mitre.org/techniques/AML.T0061)** | 3 | An adversary may use a carefully crafted LLM Prompt Injection designed to cause the LLM to replicate the prompt as part of its output. This allows the prompt to propagate to other LLMs and persist on… |
| **[AML.T0070 RAG Poisoning](https://atlas.mitre.org/techniques/AML.T0070)** | 0 | Adversaries may inject malicious content into data indexed by a retrieval augmented generation (RAG) system to contaminate a future thread through RAG-based search results. This may be accomplished by… |
| **[AML.T0080 AI Agent Context Poisoning](https://atlas.mitre.org/techniques/AML.T0080)** | 1 | Adversaries may attempt to manipulate the context used by an AI agent's large language model (LLM) to influence the responses it generates or actions it takes. This allows an adversary to persistently… |
| &nbsp;&nbsp;↳ [AML.T0080.000 Memory](https://atlas.mitre.org/techniques/AML.T0080.000) | 1 | Adversaries may manipulate the memory of a large language model (LLM) in order to persist changes to the LLM to future chat sessions. Memory is a common feature in LLMs t… |
| &nbsp;&nbsp;↳ [AML.T0080.001 Thread](https://atlas.mitre.org/techniques/AML.T0080.001) | 0 | Adversaries may introduce malicious instructions into a chat thread of a large language model (LLM) to cause behavior changes which persist for the remainder of the threa… |
| **[AML.T0081 Modify AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0081)** | 0 | Adversaries may modify the configuration files for AI agents on a system. This allows malicious changes to persist beyond the life of a single agent and affects any agents that share the configuration… |
| **[AML.T0093 Prompt Infiltration via Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0093)** | 0 | An adversary may introduce malicious prompts into the victim's system via a public-facing application with the intention of it being ingested by an AI at some point in the future and ultimately having… |
| **[AML.T0099 AI Agent Tool Data Poisoning](https://atlas.mitre.org/techniques/AML.T0099)** | 0 | Adversaries may place malicious content on a victim's system where it can be retrieved by an AI Agent Tool. This may be accomplished by placing documents in a location that will be ingested by a servi… |
| **[AML.T0110 AI Agent Tool Poisoning](https://atlas.mitre.org/techniques/AML.T0110)** | 0 | Adversaries may achieve persistence by poisoning tools used by AI agents including built-in tools or tools available to the agent via Model Context Protocol (MCP) connections. This involves compromisi… |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`AML.TA0012`](https://atlas.mitre.org/tactics/AML.TA0012) · 4 techniques

The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigur…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0012 Valid Accounts](https://atlas.mitre.org/techniques/AML.T0012)** | 0 | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access. Credentials may take the form of usernames and passwords of individual user accounts or API keys… |
| **[AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053)** | 11 | Adversaries may use their access to an AI agent to invoke tools the agent has access to. LLMs are often connected to other services or resources via tools to increase their capabilities. Tools may inc… |
| **[AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)** | 3 | Adversaries may induce a large language model (LLM) to ignore, circumvent, or override its safety/alignment behaviors and/or guardails to elicit outputs the model is intended to withhold. Once jailbro… |
| **[AML.T0105 Escape to Host](https://atlas.mitre.org/techniques/AML.T0105)** | 0 | Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the h… |

## Defense Evasion
<a id="defense-evasion"></a>

[`AML.TA0007`](https://atlas.mitre.org/tactics/AML.TA0007) · 16 techniques

The adversary is trying to avoid being detected by AI-enabled security software. Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include evading AI-enabled security software such as malware detectors.

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015)** | 6 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. This techniq… |
| **[AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)** | 3 | Adversaries may induce a large language model (LLM) to ignore, circumvent, or override its safety/alignment behaviors and/or guardails to elicit outputs the model is intended to withhold. Once jailbro… |
| **[AML.T0067 LLM Trusted Output Components Manipulation](https://atlas.mitre.org/techniques/AML.T0067)** | 0 | Adversaries may utilize prompts to a large language model (LLM) which manipulate various components of its response in order to make it appear trustworthy to the user. This helps the adversary continu… |
| &nbsp;&nbsp;↳ [AML.T0067.000 Citations](https://atlas.mitre.org/techniques/AML.T0067.000) | 0 | Adversaries may manipulate the citations provided in an AI system's response, in order to make it appear trustworthy. Variants include citing a providing the wrong citati… |
| **[AML.T0068 LLM Prompt Obfuscation](https://atlas.mitre.org/techniques/AML.T0068)** | 0 | Adversaries may hide or otherwise obfuscate prompt injections or retrieval content to avoid detection from humans, large language model (LLM) guardrails, or other detection mechanisms. For text inputs… |
| **[AML.T0071 False RAG Entry Injection](https://atlas.mitre.org/techniques/AML.T0071)** | 0 | Adversaries may introduce false entries into a victim's retrieval augmented generation (RAG) database. Content designed to be interpreted as a document by the large language model (LLM) used in the RA… |
| **[AML.T0073 Impersonation](https://atlas.mitre.org/techniques/AML.T0073)** | 0 | Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf. For example, adversaries may communicate with victims… |
| **[AML.T0074 Masquerading](https://atlas.mitre.org/techniques/AML.T0074)** | 0 | Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, l… |
| **[AML.T0076 Corrupt AI Model](https://atlas.mitre.org/techniques/AML.T0076)** | 0 | An adversary may purposefully corrupt a malicious AI model file so that it cannot be successfully deserialized in order to evade detection by a model scanner. The corrupt model may still successfully… |
| **[AML.T0081 Modify AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0081)** | 0 | Adversaries may modify the configuration files for AI agents on a system. This allows malicious changes to persist beyond the life of a single agent and affects any agents that share the configuration… |
| **[AML.T0092 Manipulate User LLM Chat History](https://atlas.mitre.org/techniques/AML.T0092)** | 0 | Adversaries may manipulate a user's large language model (LLM) chat history to cover the tracks of their malicious behavior. They may hide persistent changes they have made to the LLM's behavior, or o… |
| **[AML.T0094 Delay Execution of LLM Instructions](https://atlas.mitre.org/techniques/AML.T0094)** | 0 | Adversaries may include instructions to be followed by the AI system in response to a future event, such as a specific keyword or the next interaction, in order to evade detection or bypass controls p… |
| **[AML.T0097 Virtualization/Sandbox Evasion](https://atlas.mitre.org/techniques/AML.T0097)** | 0 | Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indi… |
| **[AML.T0107 Exploitation for Defense Evasion](https://atlas.mitre.org/techniques/AML.T0107)** | 0 | Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a vulnerability occurs when an adversary takes advantage of a programming error in a program,… |
| **[AML.T0109 AI Supply Chain Rug Pull](https://atlas.mitre.org/techniques/AML.T0109)** | 0 | Adversaries may publish legitimate AI components or software, gain user adoption, then push an update with a malicious variant, leading to AI Supply Chain Compromise. More scrutiny is often placed on… |
| **[AML.T0111 AI Supply Chain Reputation Inflation](https://atlas.mitre.org/techniques/AML.T0111)** | 0 | AI Supply Chain Reputation Inflation is the process of building or leveraging genuinely credible-looking trust signals to increase the perceived legitimacy of AI supply chain components, with the goal… |

## Credential Access
<a id="credential-access"></a>

[`AML.TA0013`](https://atlas.mitre.org/tactics/AML.TA0013) · 6 techniques

The adversary is trying to steal account names and passwords. Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achi…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0055 Unsecured Credentials](https://atlas.mitre.org/techniques/AML.T0055)** | 0 | Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (… |
| **[AML.T0082 RAG Credential Harvesting](https://atlas.mitre.org/techniques/AML.T0082)** | 2 | Adversaries may attempt to use their access to a large language model (LLM) on the victim's system to collect credentials. Credentials may be stored in internal documents which can inadvertently be in… |
| **[AML.T0083 Credentials from AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0083)** | 0 | Adversaries may access the credentials of other tools or services on a system from the configuration of an AI agent. AI Agents often utilize external tools or services to take actions, such as queryin… |
| **[AML.T0090 OS Credential Dumping](https://atlas.mitre.org/techniques/AML.T0090)** | 0 | Adversaries may extract credentials from OS caches, application memory, or other sources on a compromised system. Credentials are often in the form of a hash or clear text, and can include usernames a… |
| **[AML.T0098 AI Agent Tool Credential Harvesting](https://atlas.mitre.org/techniques/AML.T0098)** | 1 | Adversaries may attempt to use their access to an AI agent on the victim's system to retrieve data from available agent tools to collect credentials. Agent tools may connect to a wide range of sources… |
| **[AML.T0106 Exploitation for Credential Access](https://atlas.mitre.org/techniques/AML.T0106)** | 0 | Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a pro… |

## Discovery
<a id="discovery"></a>

[`AML.TA0008`](https://atlas.mitre.org/tactics/AML.TA0008) · 16 techniques

The adversary is trying to figure out your AI environment. Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what's around their entry point in order to discover how…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0007 Discover AI Artifacts](https://atlas.mitre.org/techniques/AML.T0007)** | 2 | Adversaries may search private sources to identify AI learning artifacts that exist on the system and gather information about them. These artifacts can include the software stack used to train and de… |
| **[AML.T0013 Discover AI Model Ontology](https://atlas.mitre.org/techniques/AML.T0013)** | 2 | Adversaries may discover the ontology of an AI model's output space, for example, the types of objects a model can detect. The adversary may discovery the ontology by repeated queries to the model, fo… |
| **[AML.T0014 Discover AI Model Family](https://atlas.mitre.org/techniques/AML.T0014)** | 3 | Adversaries may discover the general family of model. General information about the model may be revealed in documentation, or the adversary may use carefully constructed examples and analyze the mode… |
| **[AML.T0062 Discover LLM Hallucinations](https://atlas.mitre.org/techniques/AML.T0062)** | 4 | Adversaries may prompt large language models and identify hallucinated entities. They may request software packages, commands, URLs, organization names, or e-mail addresses, and identify hallucination… |
| **[AML.T0063 Discover AI Model Outputs](https://atlas.mitre.org/techniques/AML.T0063)** | 4 | Adversaries may discover model outputs, such as class scores, whose presence is not required for the system to function and are not intended for use by the end user. Model outputs may be found in logs… |
| **[AML.T0069 Discover LLM System Information](https://atlas.mitre.org/techniques/AML.T0069)** | 0 | The adversary is trying to discover something about the large language model's (LLM) system information. This may be found in a configuration file containing the system instructions or extracted via i… |
| &nbsp;&nbsp;↳ [AML.T0069.000 Special Character Sets](https://atlas.mitre.org/techniques/AML.T0069.000) | 0 | Adversaries may discover delimiters and special characters sets used by the large language model. For example, delimiters used in retrieval augmented generation applicati… |
| &nbsp;&nbsp;↳ [AML.T0069.001 System Instruction Keywords](https://atlas.mitre.org/techniques/AML.T0069.001) | 0 | Adversaries may discover keywords that have special meaning to the large language model (LLM), such as function names or object names. These can later be exploited to con… |
| &nbsp;&nbsp;↳ [AML.T0069.002 System Prompt](https://atlas.mitre.org/techniques/AML.T0069.002) | 0 | Adversaries may discover a large language model's system instructions provided by the AI system builder to learn about the system's capabilities and circumvent its guardr… |
| **[AML.T0075 Cloud Service Discovery](https://atlas.mitre.org/techniques/AML.T0075)** | 0 | Adversaries may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), sof… |
| **[AML.T0084 Discover AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0084)** | 0 | Adversaries may attempt to discover configuration information for AI agents present on the victim's system. Agent configurations can include tools or services they have access to. Adversaries may dire… |
| &nbsp;&nbsp;↳ [AML.T0084.000 Embedded Knowledge](https://atlas.mitre.org/techniques/AML.T0084.000) | 0 | Adversaries may attempt to discover the data sources a particular agent can access. The AI agent's configuration may reveal data sources or knowledge. The embedded knowle… |
| &nbsp;&nbsp;↳ [AML.T0084.001 Tool Definitions](https://atlas.mitre.org/techniques/AML.T0084.001) | 0 | Adversaries may discover the tools the AI agent has access to. By identifying which tools are available, the adversary can understand what actions may be executed through… |
| &nbsp;&nbsp;↳ [AML.T0084.002 Activation Triggers](https://atlas.mitre.org/techniques/AML.T0084.002) | 0 | Adversaries may discover keywords or other triggers (such as incoming emails, documents being added, incoming message, or other workflows) that activate an agent and may… |
| &nbsp;&nbsp;↳ [AML.T0084.003 Call Chains](https://atlas.mitre.org/techniques/AML.T0084.003) | 0 | Adversaries may extract call chains from AI agent configurations, which can reveal potentially targets for remote code execution (RCE) or other vulnerabilities. Vulnerabl… |
| **[AML.T0089 Process Discovery](https://atlas.mitre.org/techniques/AML.T0089)** | 0 | Adversaries may attempt to get information about processes running on a system. Once obtained, this information could be used to gain an understanding of common AI-related software/applications runnin… |

## Lateral Movement
<a id="lateral-movement"></a>

[`AML.TA0015`](https://atlas.mitre.org/tactics/AML.TA0015) · 5 techniques

The adversary is trying to move through your AI environment. Lateral Movement consists of techniques that adversaries may use to gain access to and control other systems or components in the environment. Adversaries may pivot towards AI Ops infrastructure such as model registries, experiment trackers, vector databases, notebooks, or training pipelines. As the adversary moves through the environmen…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0052 Phishing](https://atlas.mitre.org/techniques/AML.T0052)** | 2 | Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spe… |
| &nbsp;&nbsp;↳ [AML.T0052.000 Spearphishing via Social Engineering LLM](https://atlas.mitre.org/techniques/AML.T0052.000) | 2 | Adversaries may turn LLMs into targeted social engineers. LLMs are capable of interacting with users via text conversations. They can be instructed by an adversary to see… |
| &nbsp;&nbsp;↳ [AML.T0052.001 Deepfake-Assisted Phishing](https://atlas.mitre.org/techniques/AML.T0052.001) | 0 | Adversaries may use deepfakes (AI-generated synthetic images, audio, or video) in phishing campaigns to impersonate trusted individuals, executives, or organizations. The… |
| **[AML.T0091 Use Alternate Authentication Material](https://atlas.mitre.org/techniques/AML.T0091)** | 0 | Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal syst… |
| &nbsp;&nbsp;↳ [AML.T0091.000 Application Access Token](https://atlas.mitre.org/techniques/AML.T0091.000) | 0 | Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote syste… |

## Collection
<a id="collection"></a>

[`AML.TA0009`](https://atlas.mitre.org/tactics/AML.TA0009) · 6 techniques

The adversary is trying to gather AI artifacts and other related information relevant to their goal. Collection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the AI artifacts, or use the colle…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0035 AI Artifact Collection](https://atlas.mitre.org/techniques/AML.T0035)** | 4 | Adversaries may collect AI artifacts for Exfiltration or for use in AI Attack Staging. AI artifacts include models and datasets as well as other telemetry data produced when interacting with a model. |
| **[AML.T0036 Data from Information Repositories](https://atlas.mitre.org/techniques/AML.T0036)** | 0 | Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or infor… |
| **[AML.T0037 Data from Local System](https://atlas.mitre.org/techniques/AML.T0037)** | 0 | Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration. This can include basic… |
| **[AML.T0085 Data from AI Services](https://atlas.mitre.org/techniques/AML.T0085)** | 5 | Adversaries may use their access to a victim organization's AI-enabled services to collect proprietary or otherwise sensitive information. As organizations adopt generative AI in centralized services… |
| &nbsp;&nbsp;↳ [AML.T0085.000 RAG Databases](https://atlas.mitre.org/techniques/AML.T0085.000) | 4 | Adversaries may prompt the AI service to retrieve data from a RAG database. This can include the majority of an organization's internal documents. |
| &nbsp;&nbsp;↳ [AML.T0085.001 AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0085.001) | 5 | Adversaries may prompt the AI service to invoke various tools the agent has access to. Tools may retrieve data from different APIs or services in an organization. |

## AI Attack Staging
<a id="ai-attack-staging"></a>

[`AML.TA0001`](https://atlas.mitre.org/tactics/AML.TA0001) · 17 techniques

The adversary is leveraging their knowledge of and access to the target system to tailor the attack. AI Attack Staging consists of techniques adversaries use to prepare their attack on the target AI model. Techniques can include training proxy models, poisoning the target model, and crafting adversarial data to feed the target model. Some of these techniques can be performed in an offline manner a…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0005 Create Proxy AI Model](https://atlas.mitre.org/techniques/AML.T0005)** | 5 | Adversaries may obtain models to serve as proxies for the target model in use at the victim organization. Proxy models are used to simulate complete access to the target model in a fully offline manne… |
| &nbsp;&nbsp;↳ [AML.T0005.000 Train Proxy via Gathered AI Artifacts](https://atlas.mitre.org/techniques/AML.T0005.000) | 2 | Proxy models may be trained from AI artifacts (such as data, model architectures, and pre-trained models) that are representative of the target model gathered by the adve… |
| &nbsp;&nbsp;↳ [AML.T0005.001 Train Proxy via Replication](https://atlas.mitre.org/techniques/AML.T0005.001) | 3 | Adversaries may replicate a private model. By repeatedly querying the victim's AI Model Inference API Access, the adversary can collect the target model's inferences into… |
| &nbsp;&nbsp;↳ [AML.T0005.002 Use Pre-Trained Model](https://atlas.mitre.org/techniques/AML.T0005.002) | 1 | Adversaries may use an off-the-shelf pre-trained model as a proxy for the victim model to aid in staging the attack. |
| **[AML.T0018 Manipulate AI Model](https://atlas.mitre.org/techniques/AML.T0018)** | 3 | Adversaries may directly manipulate an AI model to change its behavior or introduce malicious code. Manipulating a model gives the adversary a persistent change in the system. This can include poisoni… |
| &nbsp;&nbsp;↳ [AML.T0018.000 Poison AI Model](https://atlas.mitre.org/techniques/AML.T0018.000) | 5 | Adversaries may manipulate an AI model's weights to change it's behavior or performance, resulting in a poisoned model. Adversaries may poison a model by directly manipul… |
| &nbsp;&nbsp;↳ [AML.T0018.001 Modify AI Model Architecture](https://atlas.mitre.org/techniques/AML.T0018.001) | 3 | Adversaries may directly modify an AI model's architecture to re-define it's behavior. This can include adding or removing layers as well as adding pre or post-processing… |
| &nbsp;&nbsp;↳ [AML.T0018.002 Embed Malware](https://atlas.mitre.org/techniques/AML.T0018.002) | 1 | Adversaries may embed malicious code into AI Model files. AI models may be packaged as a combination of instructions and weights. Some formats such as pickle files are un… |
| **[AML.T0042 Verify Attack](https://atlas.mitre.org/techniques/AML.T0042)** | 4 | Adversaries can verify the efficacy of their attack via an inference API or access to an offline copy of the target model. This gives the adversary confidence that their approach works and allows them… |
| **[AML.T0043 Craft Adversarial Data](https://atlas.mitre.org/techniques/AML.T0043)** | 8 | Adversarial data are inputs to an AI model that have been modified such that they cause the adversary's desired effect in the target model. Effects can range from misclassification, to missed detectio… |
| &nbsp;&nbsp;↳ [AML.T0043.000 White-Box Optimization](https://atlas.mitre.org/techniques/AML.T0043.000) | 6 | In White-Box Optimization, the adversary has full access to the target model and optimizes the adversarial example directly. Adversarial examples trained in this manner a… |
| &nbsp;&nbsp;↳ [AML.T0043.001 Black-Box Optimization](https://atlas.mitre.org/techniques/AML.T0043.001) | 7 | In Black-Box attacks, the adversary has black-box (i.e. AI Model Inference API Access via API access) access to the target model. With black-box attacks, the adversary ma… |
| &nbsp;&nbsp;↳ [AML.T0043.002 Black-Box Transfer](https://atlas.mitre.org/techniques/AML.T0043.002) | 4 | In Black-Box Transfer attacks, the adversary uses one or more proxy models (trained via Create Proxy AI Model or Train Proxy via Replication) they have full access to and… |
| &nbsp;&nbsp;↳ [AML.T0043.003 Manual Modification](https://atlas.mitre.org/techniques/AML.T0043.003) | 5 | Adversaries may manually modify the input data to craft adversarial data. They may use their knowledge of the target model to modify parts of the data they suspect helps… |
| &nbsp;&nbsp;↳ [AML.T0043.004 Insert Backdoor Trigger](https://atlas.mitre.org/techniques/AML.T0043.004) | 5 | The adversary may add a perceptual trigger into inference data. The trigger may be imperceptible or non-obvious to humans. This technique is used in conjunction with Pois… |
| **[AML.T0088 Generate Deepfakes](https://atlas.mitre.org/techniques/AML.T0088)** | 2 | Adversaries may use generative artificial intelligence (GenAI) to create synthetic media (i.e. imagery, video, audio, and text) that appear authentic. These "deepfakes" may mimic a real person or depi… |
| **[AML.T0102 Generate Malicious Commands](https://atlas.mitre.org/techniques/AML.T0102)** | 0 | Adversaries may use large language models (LLMs) to dynamically generate malicious commands from natural language. Dynamically generated commands may be harder detect as the attack signature is consta… |

## Command and Control
<a id="command-and-control"></a>

[`AML.TA0014`](https://atlas.mitre.org/tactics/AML.TA0014) · 3 techniques

The adversary is trying to communicate with compromised AI systems to control them. Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of st…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0072 Reverse Shell](https://atlas.mitre.org/techniques/AML.T0072)** | 0 | Adversaries may utilize a reverse shell to communicate and control the victim system. Typically, a user uses a client to connect to a remote machine which is listening for connections. With a reverse… |
| **[AML.T0096 AI Service API](https://atlas.mitre.org/techniques/AML.T0096)** | 0 | Adversaries may communicate using the API of an AI service on the victim's system. The adversary's commands to the victim system, and often the results, are embedded in the normal traffic of the AI se… |
| **[AML.T0108 AI Agent](https://atlas.mitre.org/techniques/AML.T0108)** | 0 | Adversaries may abuse AI agents present on the victim's system for command and control. AI agents are often granted access to tools that can execute shell commands, reach out to the internet, and inte… |

## Exfiltration
<a id="exfiltration"></a>

[`AML.TA0010`](https://atlas.mitre.org/tactics/AML.TA0010) · 9 techniques

The adversary is trying to steal AI artifacts or other information about the AI system. Exfiltration consists of techniques that adversaries may use to steal data from your network. Data may be stolen for its valuable intellectual property, or for use in staging future operations. Techniques for getting data out of a target network typically include transferring it over their command and control c…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0024 Exfiltration via AI Inference API](https://atlas.mitre.org/techniques/AML.T0024)** | 3 | Adversaries may exfiltrate private information via AI Model Inference API Access. AI Models have been shown leak private information about their training data (e.g. Infer Training Data Membership, Inv… |
| &nbsp;&nbsp;↳ [AML.T0024.000 Infer Training Data Membership](https://atlas.mitre.org/techniques/AML.T0024.000) | 3 | Adversaries may infer the membership of a data sample or global characteristics of the data in its training set, which raises privacy concerns. Some strategies make use o… |
| &nbsp;&nbsp;↳ [AML.T0024.001 Invert AI Model](https://atlas.mitre.org/techniques/AML.T0024.001) | 3 | AI models' training data could be reconstructed by exploiting the confidence scores that are available via an inference API. By querying the inference API strategically,… |
| &nbsp;&nbsp;↳ [AML.T0024.002 Extract AI Model](https://atlas.mitre.org/techniques/AML.T0024.002) | 3 | Adversaries may extract a functional copy of a private model. By repeatedly querying the victim's AI Model Inference API Access, the adversary can collect the target mode… |
| **[AML.T0025 Exfiltration via Cyber Means](https://atlas.mitre.org/techniques/AML.T0025)** | 1 | Adversaries may exfiltrate AI artifacts or other information relevant to their goals via traditional cyber means. See the ATT&CK Exfiltration tactic for more information. |
| **[AML.T0056 Extract LLM System Prompt](https://atlas.mitre.org/techniques/AML.T0056)** | 3 | Adversaries may attempt to extract a large language model's (LLM) system prompt. This can be done via prompt injection to induce the model to reveal its own system prompt or may be extracted from a co… |
| **[AML.T0057 LLM Data Leakage](https://atlas.mitre.org/techniques/AML.T0057)** | 4 | Adversaries may craft prompts that induce the LLM to leak sensitive information. This can include private user data or proprietary information. The leaked information may come from proprietary trainin… |
| **[AML.T0077 LLM Response Rendering](https://atlas.mitre.org/techniques/AML.T0077)** | 0 | An adversary may get a large language model (LLM) to respond with private information that is hidden from the user when the response is rendered by the user's client. The private information is then e… |
| **[AML.T0086 Exfiltration via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0086)** | 8 | AI agent tools capable of performing write operations may be invoked to exfiltrate data to an adversary. Sensitive information can be encoded into the tool's input parameters and transmitted to an adv… |

## Impact
<a id="impact"></a>

[`AML.TA0011`](https://atlas.mitre.org/tactics/AML.TA0011) · 19 techniques

The adversary is trying to manipulate, interrupt, erode confidence in, or destroy your AI systems and data. Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been…

| Technique | Mitigations | Description |
|---|--:|---|
| **[AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015)** | 6 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. This techniq… |
| **[AML.T0029 Denial of AI Service](https://atlas.mitre.org/techniques/AML.T0029)** | 3 | Adversaries may target AI-enabled systems with a flood of requests for the purpose of degrading or shutting down the service. Since many AI systems require significant amounts of specialized compute,… |
| **[AML.T0031 Erode AI Model Integrity](https://atlas.mitre.org/techniques/AML.T0031)** | 4 | Adversaries may degrade the target model's performance with adversarial data inputs to erode confidence in the system over time. This can lead to the victim organization wasting time and money both at… |
| **[AML.T0034 Cost Harvesting](https://atlas.mitre.org/techniques/AML.T0034)** | 2 | Adversaries may deliberately drive a victim's AI services beyond normal operating capacity with the intent of increasing the cost of services. This may be achieved via high-volume, low-complexity quer… |
| &nbsp;&nbsp;↳ [AML.T0034.000 Excessive Queries](https://atlas.mitre.org/techniques/AML.T0034.000) | 0 | Adversaries may send an excessive number of otherwise normal or low-complexity queries to an AI system with the goal of overwhelming its capacity and increasing operating… |
| &nbsp;&nbsp;↳ [AML.T0034.001 Resource-Intensive Queries](https://atlas.mitre.org/techniques/AML.T0034.001) | 0 | Adversaries may craft inputs specifically designed to increase the compute resources required for processing. For generative AI models, adversaries may use long input seq… |
| &nbsp;&nbsp;↳ [AML.T0034.002 Agentic Resource Consumption](https://atlas.mitre.org/techniques/AML.T0034.002) | 0 | Adversaries may coerce an agentic AI system into performing computationally expensive tool calls that waste resources and consume API budgets. They may utilize LLM Prompt… |
| **[AML.T0046 Spamming AI System with Chaff Data](https://atlas.mitre.org/techniques/AML.T0046)** | 2 | Adversaries may spam the AI system with chaff data that causes increase in the number of detections. This can cause analysts at the victim organization to waste time reviewing and correcting incorrect… |
| **[AML.T0048 External Harms](https://atlas.mitre.org/techniques/AML.T0048)** | 0 | Adversaries may abuse their access to a victim system and use its resources or capabilities to further their goals by causing harms external to that system. These harms could affect the organization (… |
| &nbsp;&nbsp;↳ [AML.T0048.000 Financial Harm](https://atlas.mitre.org/techniques/AML.T0048.000) | 0 | Financial harm involves the loss of wealth, property, or other monetary assets due to theft, fraud or forgery, or pressure to provide financial resources to the adversary… |
| &nbsp;&nbsp;↳ [AML.T0048.001 Reputational Harm](https://atlas.mitre.org/techniques/AML.T0048.001) | 0 | Reputational harm involves a degradation of public perception and trust in organizations. Examples of reputation-harming incidents include scandals or false impersonation… |
| &nbsp;&nbsp;↳ [AML.T0048.002 Societal Harm](https://atlas.mitre.org/techniques/AML.T0048.002) | 0 | Societal harms might generate harmful outcomes that reach either the general public or specific vulnerable groups such as the exposure of children to vulgar content. |
| &nbsp;&nbsp;↳ [AML.T0048.003 User Harm](https://atlas.mitre.org/techniques/AML.T0048.003) | 0 | User harms may encompass a variety of harm types including financial and reputational that are directed at or felt by individual victims of the attack rather than at the… |
| &nbsp;&nbsp;↳ [AML.T0048.004 AI Intellectual Property Theft](https://atlas.mitre.org/techniques/AML.T0048.004) | 3 | Adversaries may exfiltrate AI artifacts to steal intellectual property and cause economic harm to the victim organization. Proprietary training data is costly to collect… |
| **[AML.T0059 Erode Dataset Integrity](https://atlas.mitre.org/techniques/AML.T0059)** | 2 | Adversaries may poison or manipulate portions of a dataset to reduce its usefulness, reduce trust, and cause users to waste resources correcting errors. |
| **[AML.T0101 Data Destruction via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0101)** | 6 | Adversaries may invoke an AI agent's tool capable of performing mutative operations to perform Data Destruction. Adversaries may destroy data and files on specific systems or in large numbers on a net… |
| **[AML.T0112 Machine Compromise](https://atlas.mitre.org/techniques/AML.T0112)** | 0 | Adversaries may compromise a machine by exploiting or manipulating AI-enabled components on the system. Compromising a victim system allows the adversary to execute arbitrary code, steal credentials,… |
| &nbsp;&nbsp;↳ [AML.T0112.000 Local AI Agent](https://atlas.mitre.org/techniques/AML.T0112.000) | 0 | Adversaries may achieve full system compromise by abusing AI agents running locally on a host, such as computer-use agents or AI-driven browsers. These agents are designe… |
| &nbsp;&nbsp;↳ [AML.T0112.001 AI Artifacts](https://atlas.mitre.org/techniques/AML.T0112.001) | 0 | Adversaries may achieve full system compromise by introducing malicious AI artifacts, such as models or data, that contain embedded malware or other malicious commands. A… |

---

## ATLAS mitigations

The 35 defensive measures ATLAS maps to AI attack techniques.

| Mitigation | Techniques | Description |
|---|--:|---|
| [AML.M0024 AI Telemetry Logging](https://atlas.mitre.org/mitigations/AML.M0024) | 17 | Implement logging of inputs and outputs of deployed AI models. When deploying AI agents, implement logging of the intermediate steps of agentic actions and decisions, data access and tool us… |
| [AML.M0004 Restrict Number of AI Model Queries](https://atlas.mitre.org/mitigations/AML.M0004) | 16 | Limit the total number and rate of queries a user can perform. |
| [AML.M0005 Control Access to AI Models and Data at Rest](https://atlas.mitre.org/mitigations/AML.M0005) | 13 | Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users. |
| [AML.M0002 Passive AI Output Obfuscation](https://atlas.mitre.org/mitigations/AML.M0002) | 11 | Decreasing the fidelity of model outputs provided to the end user can reduce an adversary's ability to extract information about the model and optimize attacks for the model. |
| [AML.M0006 Use Ensemble Methods](https://atlas.mitre.org/mitigations/AML.M0006) | 11 | Use an ensemble of models for inference to increase robustness to adversarial inputs. Some attacks may effectively evade one model or model family but be ineffective against others. |
| [AML.M0019 Control Access to AI Models and Data in Production](https://atlas.mitre.org/mitigations/AML.M0019) | 11 | Require users to verify their identities before accessing a production model. Require authentication for API endpoints and monitor production model queries to ensure compliance with usage po… |
| [AML.M0015 Adversarial Input Detection](https://atlas.mitre.org/mitigations/AML.M0015) | 9 | Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially maliciou… |
| [AML.M0003 Model Hardening](https://atlas.mitre.org/mitigations/AML.M0003) | 8 | Use techniques to make AI models robust to adversarial inputs such as adversarial training or network distillation. |
| [AML.M0008 Validate AI Model](https://atlas.mitre.org/mitigations/AML.M0008) | 8 | Validate that AI models perform as intended by testing for backdoor triggers, potential for data leakage, or adversarial influence. Monitor AI model for concept drift and training data drift… |
| [AML.M0010 Input Restoration](https://atlas.mitre.org/mitigations/AML.M0010) | 8 | Preprocess all inference data to nullify or reverse potential adversarial perturbations. |
| [AML.M0013 Code Signing](https://atlas.mitre.org/mitigations/AML.M0013) | 8 | Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing. Adversaries can embed malicious code in AI software or models. Develope… |
| [AML.M0020 Generative AI Guardrails](https://atlas.mitre.org/mitigations/AML.M0020) | 8 | Guardrails are safety controls that are placed between a generative AI model and the output shared with the user to prevent undesired inputs and outputs. Guardrails can take the form of vali… |
| [AML.M0000 Limit Public Release of Information](https://atlas.mitre.org/mitigations/AML.M0000) | 7 | Limit the public release of technical information about the AI stack used in an organization's products or services. Technical knowledge of how AI is used can be leveraged by adversaries to… |
| [AML.M0021 Generative AI Guidelines](https://atlas.mitre.org/mitigations/AML.M0021) | 7 | Guidelines are safety controls that are placed between user-provided input and a generative AI model to help direct the model to produce desired outputs and prevent undesired outputs. Guidel… |
| [AML.M0022 Generative AI Model Alignment](https://atlas.mitre.org/mitigations/AML.M0022) | 7 | When training or fine-tuning a generative AI model it is important to utilize techniques that improve model alignment with safety, security, and content policies. The fine-tuning process can… |
| [AML.M0023 AI Bill of Materials](https://atlas.mitre.org/mitigations/AML.M0023) | 7 | An AI Bill of Materials (AI BOM) contains a full listing of artifacts and resources that were used in building the AI. The AI BOM can help mitigate supply chain risks and enable rapid respon… |
| [AML.M0026 Privileged AI Agent Permissions Configuration](https://atlas.mitre.org/mitigations/AML.M0026) | 7 | AI agents may be granted elevated privileges above that of a normal user to enable desired workflows. When deploying a privileged AI agent, or an agent that interacts with multiple users, it… |
| [AML.M0027 Single-User AI Agent Permissions Configuration](https://atlas.mitre.org/mitigations/AML.M0027) | 7 | When deploying an AI agent that acts as a representative of a user and performs actions on their behalf, it is important to implement robust policies and controls on permissions and lifecycl… |
| [AML.M0001 Limit Model Artifact Release](https://atlas.mitre.org/mitigations/AML.M0001) | 6 | Limit public release of technical project details including data, algorithms, model architectures, and model checkpoints that are used in production, or that are representative of those used… |
| [AML.M0014 Verify AI Artifacts](https://atlas.mitre.org/mitigations/AML.M0014) | 6 | Verify the cryptographic checksum of all AI artifacts to verify that the file was not modified by an attacker. |
| [AML.M0017 AI Model Distribution Methods](https://atlas.mitre.org/mitigations/AML.M0017) | 6 | Deploying AI models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. Also con… |
| [AML.M0032 Segmentation of AI Agent Components](https://atlas.mitre.org/mitigations/AML.M0032) | 6 | Define security boundaries around agentic tools and data sources with methods such as API access, container isolation, code execution sandboxing, and rate limiting of tool invocation. When s… |
| [AML.M0033 Input and Output Validation for AI Agent Components](https://atlas.mitre.org/mitigations/AML.M0033) | 6 | Implement validation on inputs and outputs for the tools and data sources used by AI agents. Validation includes enforcing a common data format, schema validation, checks for sensitive or pr… |
| [AML.M0018 User Training](https://atlas.mitre.org/mitigations/AML.M0018) | 5 | Educate AI model developers to on AI supply chain risks and potentially malicious AI artifacts. Educate users on how to identify deepfakes and phishing attempts. |
| [AML.M0025 Maintain AI Dataset Provenance](https://atlas.mitre.org/mitigations/AML.M0025) | 5 | Maintain a detailed history of datasets used for AI applications. The history should include information about the dataset's source as well as a complete record of any modifications. |
| [AML.M0028 AI Agent Tools Permissions Configuration](https://atlas.mitre.org/mitigations/AML.M0028) | 5 | When deploying tools that will be shared across multiple AI agents, it is important to implement robust policies and controls on permissions for the tools. These controls include applying th… |
| [AML.M0007 Sanitize Training Data](https://atlas.mitre.org/mitigations/AML.M0007) | 4 | Detect and remove or remediate poisoned training data. Training data should be sanitized prior to model training and recurrently for an active learning model. Implement a filter to limit ing… |
| [AML.M0012 Encrypt Sensitive Information](https://atlas.mitre.org/mitigations/AML.M0012) | 4 | Encrypt sensitive data such as AI models to protect against adversaries attempting to access sensitive data. |
| [AML.M0034 Deepfake Detection](https://atlas.mitre.org/mitigations/AML.M0034) | 4 | Apply deepfake detection algorithms against any untrusted or user-provided data, especially in impactful applications such as biometric verification, to block generated content. Detectors ma… |
| [AML.M0009 Use Multi-Modal Sensors](https://atlas.mitre.org/mitigations/AML.M0009) | 3 | Incorporate multiple sensors to integrate varying perspectives and modalities to avoid a single point of failure susceptible to physical attacks. |
| [AML.M0011 Restrict Library Loading](https://atlas.mitre.org/mitigations/AML.M0011) | 3 | Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vuln… |
| [AML.M0016 Vulnerability Scanning](https://atlas.mitre.org/mitigations/AML.M0016) | 3 | Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. File formats such as pickle files that are commonly used to store AI models can con… |
| [AML.M0029 Human In-the-Loop for AI Agent Actions](https://atlas.mitre.org/mitigations/AML.M0029) | 3 | Systems should require the user or another human stakeholder to approve AI agent actions before the agent takes them. The human approver may be technical staff or business unit SMEs dependin… |
| [AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data](https://atlas.mitre.org/mitigations/AML.M0030) | 3 | Untrusted data can contain prompt injections that invoke an AI agent's tools, potentially causing confidentiality, integrity or availability violations. It is recommended that tool invocatio… |
| [AML.M0031 Memory Hardening](https://atlas.mitre.org/mitigations/AML.M0031) | 2 | Memory Hardening involves developing trust boundaries and secure processes for how an AI agent stores and accesses memory and context. This may be implemented using a combination of strategi… |

---

*Source: [MITRE ATLAS](https://atlas.mitre.org/) via [mitre-atlas/atlas-navigator-data](https://github.com/mitre-atlas/atlas-navigator-data) STIX export. ATLAS™ and ATT&CK® are trademarks of The MITRE Corporation. Independent reference summary — consult the upstream project for authoritative content.*
