# MITRE ATLAS Reference: Adversarial Threats to AI Systems

> Teams that build, red-team, and defend machine-learning and AI-enabled systems use [MITRE ATLAS™](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) as a shared catalog of how those systems are attacked, laid out the way ATT&CK is. The library's ATLAS data follows the ATLAS 2026.10 release: <!-- atlas-counts:start (written by scripts/build_atlas.py; do not edit) -->221 techniques (129 parent + 92 sub-techniques), 44 mitigations, and 16 tactics<!-- atlas-counts:end -->. Check each technique's evidence and maturity; inclusion does not by itself establish observation in a real incident.

ATLAS deliberately mirrors the ATT&CK structure and reuses its tactic names where behavior is the same, then adds the two tactics unique to attacking AI:

| ATLAS-specific tactic | What the adversary is doing |
|---|---|
| AI Model Access | Obtaining some level of access to the model itself (API, inference endpoint, weights, or the physical environment), which is a prerequisite for most AI attacks |
| AI Attack Adaptation | Adapting capabilities or observations to a target or operational objective, before initial access or during an operation |

<!-- atlas-summary:start (written by scripts/build_atlas.py from data/ai/; do not edit) -->

| | |
|---|---|
| Release | [ATLAS 2026.10](https://github.com/mitre-atlas/atlas-data/blob/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml) (data format 6.1.0), dated 2026-10-28 |
| Tactics | 16 |
| Techniques | 221 (129 parent, 92 sub-techniques) |
| Mitigations | 44 |
| Case studies in the release | 77 |
| Retired technique IDs | 8, listed with their successors under [Retired technique IDs](#retired-technique-ids) |
| Navigator layers | [ATLAS matrix](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/ai/atlas-matrix.json), [case-study frequency](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/ai/atlas-case-study-frequency.json) |
| Datasets | [techniques](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/ai/atlas_techniques.jsonl), [tactics](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/ai/atlas_tactics.jsonl), [mitigations](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/ai/atlas_mitigations.jsonl), [retired IDs](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/ai/atlas_superseded_by.jsonl) |

<!-- atlas-summary:end -->

Related in this library: [AI Security Reference](AI_SECURITY_REFERENCE.md) (OWASP LLM Top 10, prompt injection, guardrails), [AI & MCP Security](AI_MCP_SECURITY_REFERENCE.md), [AI Offensive Security](AI_OFFENSIVE_SECURITY_REFERENCE.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security engineers, threat modelers, and red teams working on AI and ML systems

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Length</th><td>

Lookup page: 10,128 words, 79% in tables; look entries up from Start at or the search (about 44 min end to end at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to map an attack on an AI/ML system to a named technique ID, you are threat-modeling an LLM, RAG, or AI-agent deployment, or you want the mitigations ATLAS pairs with a given AI attack technique

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[The ATLAS matrix](#the-atlas-matrix) for the 16-tactic overview, [Execution](#execution) for prompt injection and agent-tool techniques, [ATLAS mitigations](#atlas-mitigations) for the defensive side

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (matching learning path, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Matching learning path</th><td>

[Adversarial AI Attacks](/disciplines/adversarial-ai-attacks.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<details class="tsw-meta-which"><summary>Which page should I read? This page is one of 7 on AI security.</summary>

| Page | Read it for |
|---|---|
| ATLAS Reference (AI threats) (this page) | The MITRE ATLAS matrix of techniques and mitigations for attacks on AI systems. |
| [AI Security Reference](/AI_SECURITY_REFERENCE.md) | Securing LLM applications: the OWASP LLM Top 10, prompt injection, adversarial ML, and guardrails. |
| [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md) | The Model Context Protocol: its threat model and hardening for MCP servers and agents. |
| [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md) | AI-assisted attack tooling and the defensive playbook against it. |
| [AI Architecture Reference](/AI_ARCHITECTURE_REFERENCE.md) | Designing ML and LLM systems end to end, with the controls that make the architecture defensible. |
| [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) | The infrastructure behind AI: model registries, unsafe model files, pipelines, and inference servers. |
| [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md) | An illustrative agent-swarm intrusion kill chain mapped to ATT&CK and ATLAS. |

</details>

<!-- meta:end -->

---

## Agentic AI & AI Agent Swarms

Autonomous agents can exchange discoveries, tasks, and results, including through shared artifacts that persist across otherwise independent runs. Shared-artifact communication does not by itself establish autonomous attack orchestration, which requires centralized control over distributed execution. A swarm threat model should distinguish adversary-operated agents from attacks against a defender's agents, including unsafe artifacts, compromised dependencies, and induced resource consumption. The [Agentic AI Attack Reference](/AGENTIC_AI_ATTACK_REFERENCE.md) offers a curated practitioner view, not an official MITRE mapping or evidence that every listed behavior occurs in every intrusion.

Version boundary: The counts above, the tables from [The ATLAS matrix](#the-atlas-matrix) through [Retired technique IDs](#retired-technique-ids), and the library's ATLAS data files are written by `scripts/build_atlas.py` from the [ATLAS 2026.10 release file](https://github.com/mitre-atlas/atlas-data/blob/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml), pinned by commit and SHA-256, and CI rebuilds them on every change. Each table description is the first sentence of the ATLAS definition. The agentic supplement in this section is practitioner curation; its technique and mitigation names were checked against the same release. IDs that ATLAS has retired, such as AML.T0019 (now AML.T0115.000), appear only in the retired-ID table; do not cite them as current.

| ATLAS technique | Behavior to distinguish |
|---|---|
| AML.T0118 Autonomous AI Agent Communication | Autonomous agents exchange operational information with other agents or subagents; communication alone does not establish malicious intent. |
| AML.T0118.000 Communication via Shared Artifacts | Agents exchange information through persistent shared artifacts, including across runs that do not overlap in time. |
| AML.T0124 Autonomous Attack Orchestration | Centralized autonomous control assigns, sequences, and coordinates distributed attack execution; shared notes alone are insufficient evidence. |
| AML.T0034.002 Cost Harvesting: Agentic Resource Consumption | Adversaries induce costly tool calls, delegation, or repeated execution to consume resources; high usage alone is not proof of an attack. |
| AML.T0011.000 User Execution: Unsafe AI Artifacts | Loading or processing an unsafe AI artifact can execute code or alter agent behavior through supported runtime features, without necessarily exploiting a software vulnerability. |
| AML.T0002 Acquire Public AI Artifacts | Adversaries acquire public AI artifacts to support attack preparation; legitimate acquisition is not itself a compromise. |
| AML.T0010 Supply Chain Compromise | Adversaries compromise AI supply-chain components to obtain access; this is distinct from simply acquiring a public artifact. |

Defensive application (practitioner curation): Scope short-lived identities per agent and environment, enforce default-deny egress outside the model, and prohibit secrets shared across environments. Bound tool calls, retries, delegation, and spend; use pre-authorized, act-on-signals runbooks that can pause agents, revoke credentials, and isolate execution at machine tempo while preserving evidence. These choices draw on the same release's AML.M0032 (Segmentation of AI Agent Components), AML.M0037 (AI Agent Authority Expansion Controls), and AML.M0038 (AI Agent Scope Drift Detection); they are not a claim of complete mitigation coverage. See the [AI & LLM Security learning path](/disciplines/ai-llm-security.md) for a bounded practice exercise.

## ATT&CK v20.0 AI techniques and related ATLAS techniques

ATT&CK v20.0 added Enterprise techniques for prompt injection, AI-enabled exfiltration, AI result poisoning and attacks on autonomous defenses, next to the CAPTCHA and app-specific password techniques added in the same release. The pinned ATLAS 2026.10 data carries no ATT&CK reference to any of them, so the table below is the library's own crosswalk, not a MITRE mapping: a pairing says the two techniques describe related behavior from different sides (the enterprise being attacked, the AI system being attacked), not that one maps to the other. The table is written by `scripts/generate_mitre_pages.py` from `data/attack/technique_enrichment.jsonl`, and each technique page repeats its pairings under Related ATLAS techniques.

<!-- attack-crosswalk:start (written by scripts/generate_mitre_pages.py from data/attack/technique_enrichment.jsonl; do not edit) -->

| ATT&CK v20.0 technique | Related ATLAS 2026.10 techniques (library pairing) | Why the library pairs them |
|---|---|---|
| [T1608.007 AI Result Poisoning](/mitre/techniques/T1608-007.md) | [AML.T0066 Retrieval Content Crafting](/mitre/atlas/AML-T0066.md), [AML.T0070 RAG Poisoning](/mitre/atlas/AML-T0070.md) | The retrieval side of the same idea: content crafted to be retrieved by an AI system, and poisoning of a retrieval-augmented generation corpus. |
| [T1685.007 Impair Autonomous Defenses](/mitre/techniques/T1685-007.md) | [AML.T0015 Evade AI Model](/mitre/atlas/AML-T0015.md), [AML.T0051.001 LLM Prompt Injection: Indirect](/mitre/atlas/AML-T0051-001.md) | ATLAS describes the defender's model as the victim: evading an AI model, here by prompt injection carried in the sample it reads. |
| [T1696 Anti-Automation Evasion](/mitre/techniques/T1696.md) | None | ATLAS techniques describe attacks on AI systems; evading a bot check with automation has no ATLAS counterpart. |
| [T1696.001 Automate CAPTCHA Completion](/mitre/techniques/T1696-001.md) | None | No ATLAS counterpart: the solver is a tool used against a web control, not an attack on an AI system. |
| [T1696.002 Avoid CAPTCHA](/mitre/techniques/T1696-002.md) | None | No ATLAS counterpart: mimicking a human visitor targets a web control, not an AI system. |
| [T1697 Steal Application Specific Passwords](/mitre/techniques/T1697.md) | None | No ATLAS counterpart: the target is an account credential, not an AI system. |
| [T1698 Indirect Prompt Injection](/mitre/techniques/T1698.md) | [AML.T0051.001 LLM Prompt Injection: Indirect](/mitre/atlas/AML-T0051-001.md), [AML.T0080 AI Agent Context Poisoning](/mitre/atlas/AML-T0080.md) | The same behavior seen from the AI system's side: prompt injection delivered through retrieved content, and poisoning of the context an agent works from. |
| [T1699 Direct Prompt Injection](/mitre/techniques/T1699.md) | [AML.T0051.000 LLM Prompt Injection: Direct](/mitre/atlas/AML-T0051-000.md), [AML.T0054 LLM Jailbreak](/mitre/atlas/AML-T0054.md) | ATLAS's view of the same act: a prompt injected straight into the model, and jailbreaking it past its safety controls. |
| [T1700 AI-Enabled Exfiltration](/mitre/techniques/T1700.md) | [AML.T0086 Exfiltration via AI Agent Tool Invocation](/mitre/atlas/AML-T0086.md), [AML.T0136 Exfiltration via AI User Interface](/mitre/atlas/AML-T0136.md) | ATLAS's exfiltration techniques for the same path: data sent out through an agent's tool calls, or through the AI user interface itself. |

<!-- attack-crosswalk:end -->

---

<!-- atlas-data begin (written by scripts/build_atlas.py from data/ai/; do not edit) -->

## The ATLAS matrix

The 16 tactics in the order ATLAS 2026.10 lays them out, with the number of techniques and sub-techniques filed under each (a technique can sit under more than one).

| # | Tactic | Techniques | Description |
|---|---|--:|---|
| 1 | [Reconnaissance](https://atlas.mitre.org/tactics/AML.TA0002) | 18 | The adversary is trying to gather information about the AI system they can use to plan future operations. |
| 2 | [Resource Development](https://atlas.mitre.org/tactics/AML.TA0003) | 35 | The adversary is trying to establish resources they can use to support operations. |
| 3 | [AI Attack Adaptation](https://atlas.mitre.org/tactics/AML.TA0001) | 25 | The adversary is adapting capabilities, methods, knowledge, or objectives into attack-ready outputs for a target or current operational conditions. |
| 4 | [Initial Access](https://atlas.mitre.org/tactics/AML.TA0004) | 18 | The adversary is trying to gain access to the AI system. |
| 5 | [AI Model Access](https://atlas.mitre.org/tactics/AML.TA0000) | 4 | The adversary is attempting to gain some level of access to an AI model. |
| 6 | [Execution](https://atlas.mitre.org/tactics/AML.TA0005) | 13 | The adversary is trying to run malicious code embedded in AI artifacts or software. |
| 7 | [Persistence](https://atlas.mitre.org/tactics/AML.TA0006) | 22 | The adversary is trying to maintain their foothold via AI artifacts or software. |
| 8 | [Privilege Escalation](https://atlas.mitre.org/tactics/AML.TA0012) | 4 | The adversary is trying to gain higher-level permissions. |
| 9 | [Defense Evasion](https://atlas.mitre.org/tactics/AML.TA0007) | 22 | The adversary is trying to avoid being detected by AI-enabled security software. |
| 10 | [Credential Access](https://atlas.mitre.org/tactics/AML.TA0013) | 7 | The adversary is trying to steal account names and passwords. |
| 11 | [Discovery](https://atlas.mitre.org/tactics/AML.TA0008) | 18 | The adversary is trying to figure out your AI environment. |
| 12 | [Lateral Movement](https://atlas.mitre.org/tactics/AML.TA0015) | 10 | The adversary is trying to move through your AI environment. |
| 13 | [Collection](https://atlas.mitre.org/tactics/AML.TA0009) | 17 | The adversary is trying to gather AI artifacts and other related information relevant to their goal. |
| 14 | [Command and Control](https://atlas.mitre.org/tactics/AML.TA0014) | 5 | The adversary is trying to communicate with compromised AI systems to control them. |
| 15 | [Exfiltration](https://atlas.mitre.org/tactics/AML.TA0010) | 5 | The adversary is trying to steal AI artifacts or other information about the AI system. |
| 16 | [Impact](https://atlas.mitre.org/tactics/AML.TA0011) | 20 | The adversary is trying to manipulate, interrupt, erode confidence in, or destroy your AI systems and data. |

---

## Reconnaissance
<a id="reconnaissance"></a>

[`AML.TA0002`](https://atlas.mitre.org/tactics/AML.TA0002), 18 techniques

The adversary is trying to gather information about the AI system they can use to plan future operations. Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organizations' AI capabilities and research efforts. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to obtain relevant AI artifacts, targeting AI capabilities used by the victim, tailoring attacks to the particular models used by the victim, or to drive and lead further Reconnaissance efforts.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0000 Search Open Technical Databases](https://atlas.mitre.org/techniques/AML.T0000) | 2 | Adversaries may search for publicly available research and technical documentation to learn how and where AI is used within a victim organization. |
| &nbsp;&nbsp;↳ [AML.T0000.000 Journals and Conference Proceedings](https://atlas.mitre.org/techniques/AML.T0000.000) | 0 | Many of the publications accepted at premier artificial intelligence conferences and journals come from commercial labs. |
| &nbsp;&nbsp;↳ [AML.T0000.001 Pre-Print Repositories](https://atlas.mitre.org/techniques/AML.T0000.001) | 0 | Pre-Print repositories, such as arXiv, contain the latest academic research papers that haven't been peer reviewed. |
| &nbsp;&nbsp;↳ [AML.T0000.002 Technical Blogs](https://atlas.mitre.org/techniques/AML.T0000.002) | 0 | Research labs at academic institutions and company R&amp;D divisions often have blogs that highlight their use of artificial intelligence and its application to the organization's unique problems. |
| &nbsp;&nbsp;↳ [AML.T0000.003 Scan Databases](https://atlas.mitre.org/techniques/AML.T0000.003) | 1 | Adversaries may search public internet-scan services to identify a victim's exposed AI infrastructure. |
| [AML.T0001 Search Open AI Vulnerability Analysis](https://atlas.mitre.org/techniques/AML.T0001) | 1 | Much like the Search Open Technical Databases, there is often ample research available on the vulnerabilities of common AI models. |
| [AML.T0003 Search Victim-Owned Websites](https://atlas.mitre.org/techniques/AML.T0003) | 1 | Adversaries may search websites owned by the victim for information that can be used during targeting. |
| [AML.T0004 Search Application Repositories](https://atlas.mitre.org/techniques/AML.T0004) | 1 | Adversaries may search open application repositories during targeting. |
| [AML.T0006 Active Scanning](https://atlas.mitre.org/techniques/AML.T0006) | 3 | Adversaries may actively scan for publicly reachable AI systems and resources for targeting. |
| &nbsp;&nbsp;↳ [AML.T0006.000 Enumerate Hosted AI Resources](https://atlas.mitre.org/techniques/AML.T0006.000) | 1 | Adversaries may directly probe an agentic or SaaS platform to enumerate the resources a specific victim has deployed on it. |
| &nbsp;&nbsp;↳ [AML.T0006.001 Query Platform Metadata APIs](https://atlas.mitre.org/techniques/AML.T0006.001) | 1 | Adversaries may query documented or undocumented APIs in agentic SaaS hosting platforms to uncover agentic targets. |
| &nbsp;&nbsp;↳ [AML.T0006.002 Scan for Exposed AI Infrastructure](https://atlas.mitre.org/techniques/AML.T0006.002) | 1 | Adversaries may scan network ports and services to identify deployed AI backends, model-serving endpoints, and AI agent infrastructure reachable over the internet. |
| &nbsp;&nbsp;↳ [AML.T0006.003 Probe AI Agent Trigger Channels](https://atlas.mitre.org/techniques/AML.T0006.003) | 1 | Adversaries may send crafted inputs to potential public triggers, such as email addresses, webhooks, or messaging channels, to elicit a response that indicates an invocation of agentic activity. |
| [AML.T0064 Gather RAG-Indexed Targets](https://atlas.mitre.org/techniques/AML.T0064) | 1 | Adversaries may identify data sources used in retrieval augmented generation (RAG) systems for targeting purposes. |
| [AML.T0087 Gather Victim Identity Information](https://atlas.mitre.org/techniques/AML.T0087) | 0 | Adversaries may gather information about the victim's identity that can be used during targeting. |
| [AML.T0095 Search Open Websites/Domains](https://atlas.mitre.org/techniques/AML.T0095) | 2 | Adversaries may search public websites and/or domains for information about victims and AI targets that can be used during targeting and to discover opportunities for successful attacks. |
| &nbsp;&nbsp;↳ [AML.T0095.000 Code Repositories](https://atlas.mitre.org/techniques/AML.T0095.000) | 1 | Adversaries may search public code repositories for information about a victim or victim system that can be used during targeting. |
| [AML.T0116 Autonomous Reconnaissance](https://atlas.mitre.org/techniques/AML.T0116) | 6 | Adversaries may use autonomous AI agents to conduct Reconnaissance activities. |

## Resource Development
<a id="resource-development"></a>

[`AML.TA0003`](https://atlas.mitre.org/tactics/AML.TA0003), 35 techniques

The adversary is trying to establish resources they can use to support operations. Resource Development consists of techniques that involve adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include AI artifacts, infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as AI Attack Adaptation.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0002 Acquire Public AI Artifacts](https://atlas.mitre.org/techniques/AML.T0002) | 1 | Adversaries may search public sources, including cloud storage, public-facing services, and software or data repositories, to identify AI artifacts. |
| &nbsp;&nbsp;↳ [AML.T0002.000 Datasets](https://atlas.mitre.org/techniques/AML.T0002.000) | 1 | Adversaries may collect public datasets to use in their operations. |
| &nbsp;&nbsp;↳ [AML.T0002.001 Models](https://atlas.mitre.org/techniques/AML.T0002.001) | 1 | Adversaries may acquire public models to use in their operations. |
| &nbsp;&nbsp;↳ [AML.T0002.002 AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0002.002) | 0 | Adversaries may acquire publicly accessible AI agent configuration files to understand agent capabilities, gain unauthorized access to tools and data sources, or identify credentials for further attacks. |
| [AML.T0005 Replicate AI Model Behavior](https://atlas.mitre.org/techniques/AML.T0005) | 6 | Adversaries may replicate an AI model's behavior or selected capabilities by training or adapting another model to approximate the target's responses, decision regions, or other characteristics. |
| &nbsp;&nbsp;↳ [AML.T0005.000 Replicate Behavior from Gathered AI Artifacts](https://atlas.mitre.org/techniques/AML.T0005.000) | 2 | Adversaries may replicate AI model behavior by training or fine-tuning another model from gathered AI artifacts, such as representative datasets, published architectures, training objectives, documented hyperparameters, or pretrained components. |
| &nbsp;&nbsp;↳ [AML.T0005.001 Replicate Behavior from Model Outputs](https://atlas.mitre.org/techniques/AML.T0005.001) | 4 | Adversaries may replicate an AI model's behavior or selected capabilities by training or adapting another model using outputs or other sources of supervision obtained from the target. |
| &nbsp;&nbsp;↳ [AML.T0005.002 Adapt Existing Model to Replicate Behavior](https://atlas.mitre.org/techniques/AML.T0005.002) | 1 | Adversaries may select an existing AI model whose behavior resembles a target and adapt it to more closely reproduce the capabilities or responses of interest. |
| [AML.T0008 Acquire Infrastructure](https://atlas.mitre.org/techniques/AML.T0008) | 1 | Adversaries may buy, lease, or rent infrastructure for use throughout their operation. |
| &nbsp;&nbsp;↳ [AML.T0008.000 AI Development Workspaces](https://atlas.mitre.org/techniques/AML.T0008.000) | 0 | Developing and staging AI attacks often requires expensive compute resources. |
| &nbsp;&nbsp;↳ [AML.T0008.001 Consumer Hardware](https://atlas.mitre.org/techniques/AML.T0008.001) | 0 | Adversaries may acquire consumer hardware to conduct their attacks. |
| &nbsp;&nbsp;↳ [AML.T0008.002 Domains](https://atlas.mitre.org/techniques/AML.T0008.002) | 0 | Adversaries may acquire domains that can be used during targeting. |
| &nbsp;&nbsp;↳ [AML.T0008.003 Physical Countermeasures](https://atlas.mitre.org/techniques/AML.T0008.003) | 0 | Adversaries may acquire or manufacture physical countermeasures to aid or support their attack. |
| &nbsp;&nbsp;↳ [AML.T0008.004 Serverless](https://atlas.mitre.org/techniques/AML.T0008.004) | 0 | Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. |
| &nbsp;&nbsp;↳ [AML.T0008.005 AI Service Proxies](https://atlas.mitre.org/techniques/AML.T0008.005) | 0 | Adversaries may acquire proxy infrastructure that mediates access to AI services. |
| [AML.T0016 Obtain Capabilities](https://atlas.mitre.org/techniques/AML.T0016) | 1 | Adversaries may search for and obtain software capabilities for use in their operations. |
| &nbsp;&nbsp;↳ [AML.T0016.000 Adversarial AI Attack Implementations](https://atlas.mitre.org/techniques/AML.T0016.000) | 0 | Adversaries may search for existing open source implementations of AI attacks. |
| &nbsp;&nbsp;↳ [AML.T0016.001 Software Tools](https://atlas.mitre.org/techniques/AML.T0016.001) | 0 | Adversaries may search for and obtain software tools to support their operations. |
| &nbsp;&nbsp;↳ [AML.T0016.002 Generative AI](https://atlas.mitre.org/techniques/AML.T0016.002) | 2 | Adversaries may search for and obtain generative AI models or tools, such as large language models (LLMs), to assist them in various steps of their operation. |
| &nbsp;&nbsp;↳ [AML.T0016.003 Exploits](https://atlas.mitre.org/techniques/AML.T0016.003) | 0 | Adversaries may search for and obtain exploits to support their operations. |
| &nbsp;&nbsp;↳ [AML.T0016.004 AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0016.004) | 0 | Adversaries may search for and obtain tools that extend the capabilities of an AI agent. |
| [AML.T0017 Develop Capabilities](https://atlas.mitre.org/techniques/AML.T0017) | 0 | Adversaries may develop their own capabilities to support operations. |
| &nbsp;&nbsp;↳ [AML.T0017.000 Adversarial AI Attacks](https://atlas.mitre.org/techniques/AML.T0017.000) | 0 | Adversaries may develop their own adversarial attacks. |
| &nbsp;&nbsp;↳ [AML.T0017.001 Autonomous Exploit Development](https://atlas.mitre.org/techniques/AML.T0017.001) | 2 | An autonomous AI agent may identify a software vulnerability and develop or materially adapt an exploit capability with limited human direction. |
| &nbsp;&nbsp;↳ [AML.T0017.002 AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0017.002) | 0 | Adversaries may develop or materially adapt tools, integrations, or tool servers designed to extend the capabilities of an AI agent. |
| &nbsp;&nbsp;↳ [AML.T0017.003 Malware](https://atlas.mitre.org/techniques/AML.T0017.003) | 0 | Adversaries may develop malware to support their operations. |
| [AML.T0021 Establish Accounts](https://atlas.mitre.org/techniques/AML.T0021) | 3 | Adversaries may create accounts with various services for use in targeting, to gain access to resources needed to further their operations, or for victim impersonation. |
| [AML.T0060 Publish Hallucinated Entities](https://atlas.mitre.org/techniques/AML.T0060) | 0 | Adversaries may create an entity they control, such as a software package, website, or email address corresponding to a source hallucinated by an LLM. |
| [AML.T0079 Stage Capabilities](https://atlas.mitre.org/techniques/AML.T0079) | 1 | Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. |
| [AML.T0115 Publish Poisoned AI Artifacts](https://atlas.mitre.org/techniques/AML.T0115) | 3 | Adversaries may create or modify AI artifacts and publish them through public or shared distribution channels to facilitate compromise of downstream AI systems. |
| &nbsp;&nbsp;↳ [AML.T0115.000 Datasets](https://atlas.mitre.org/techniques/AML.T0115.000) | 2 | Adversaries may publish poisoned datasets intended for training or fine-tuning AI models. |
| &nbsp;&nbsp;↳ [AML.T0115.001 Models](https://atlas.mitre.org/techniques/AML.T0115.001) | 3 | Adversaries may publish poisoned AI models through model registries, code repositories, or other model distribution channels. |
| &nbsp;&nbsp;↳ [AML.T0115.002 AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0115.002) | 2 | Adversaries may create and publish poisoned AI agent tools. |
| [AML.T0128 Compromise Infrastructure](https://atlas.mitre.org/techniques/AML.T0128) | 1 | Adversaries may compromise third-party infrastructure and repurpose it to support attacks against AI systems. |
| [AML.T0139 Compromise Accounts](https://atlas.mitre.org/techniques/AML.T0139) | 0 | Adversaries may compromise existing accounts with services that can support targeting or subsequent operations. |

## AI Attack Adaptation
<a id="ai-attack-adaptation"></a>
<a id="ai-attack-staging"></a>

[`AML.TA0001`](https://atlas.mitre.org/tactics/AML.TA0001), 25 techniques

The adversary is adapting capabilities, methods, knowledge, or objectives into attack-ready outputs for a target or current operational conditions. AI Attack Adaptation consists of techniques adversaries use to transform reusable capabilities, general attack methods, target knowledge, high-level objectives, and operational observations into target- or context-specific attack-ready outputs. Adaptation may target an AI system directly, or it may use an AI capability to materially shape malicious content for attacks against AI components, software, infrastructure, people, or other systems. Adapted outputs may include proxy or manipulated models, adversarial data, crafted prompts or retrieval content, deepfakes, or generated malicious commands or code. Outputs can also include actions for an autonomous agent such as agent tasking, high-level objectives, action sequences, and tool instructions. AI Attack Adaptation may occur before Initial Access is achieved and repeatedly throughout an operation. Adversaries may use knowledge obtained through Reconnaissance or Discovery, access obtained through AI Model Access, and capabilities established through Resource Development. Resource Development creates or obtains reusable capabilities whereas AI Attack Adaptation applies or modifies those capabilities for a target, objective, or current operational condition.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0005 Replicate AI Model Behavior](https://atlas.mitre.org/techniques/AML.T0005) | 6 | Adversaries may replicate an AI model's behavior or selected capabilities by training or adapting another model to approximate the target's responses, decision regions, or other characteristics. |
| &nbsp;&nbsp;↳ [AML.T0005.000 Replicate Behavior from Gathered AI Artifacts](https://atlas.mitre.org/techniques/AML.T0005.000) | 2 | Adversaries may replicate AI model behavior by training or fine-tuning another model from gathered AI artifacts, such as representative datasets, published architectures, training objectives, documented hyperparameters, or pretrained components. |
| &nbsp;&nbsp;↳ [AML.T0005.001 Replicate Behavior from Model Outputs](https://atlas.mitre.org/techniques/AML.T0005.001) | 4 | Adversaries may replicate an AI model's behavior or selected capabilities by training or adapting another model using outputs or other sources of supervision obtained from the target. |
| &nbsp;&nbsp;↳ [AML.T0005.002 Adapt Existing Model to Replicate Behavior](https://atlas.mitre.org/techniques/AML.T0005.002) | 1 | Adversaries may select an existing AI model whose behavior resembles a target and adapt it to more closely reproduce the capabilities or responses of interest. |
| [AML.T0018 Manipulate AI Model](https://atlas.mitre.org/techniques/AML.T0018) | 4 | Adversaries may manipulate an AI model artifact or its bundled components to change AI system behavior, introduce malicious code, or establish persistent malicious functionality. |
| &nbsp;&nbsp;↳ [AML.T0018.000 Poison AI Model](https://atlas.mitre.org/techniques/AML.T0018.000) | 8 | Adversaries may manipulate an AI model's weights to change it's behavior or performance, resulting in a poisoned model. |
| &nbsp;&nbsp;↳ [AML.T0018.001 Modify AI Model Architecture](https://atlas.mitre.org/techniques/AML.T0018.001) | 5 | Adversaries may directly modify an AI model's architecture to re-define it's behavior. |
| &nbsp;&nbsp;↳ [AML.T0018.002 Embed Malware](https://atlas.mitre.org/techniques/AML.T0018.002) | 2 | Adversaries may embed malicious code into AI Model files. |
| &nbsp;&nbsp;↳ [AML.T0018.003 Modify Prompt Construction Logic](https://atlas.mitre.org/techniques/AML.T0018.003) | 2 | Adversaries may modify templates, role delimiters, embedded system instructions, tokenizer settings, tool-call formatting, or other artifact-bundled logic that constructs the context sent to an AI model. |
| [AML.T0042 Verify Attack](https://atlas.mitre.org/techniques/AML.T0042) | 5 | Adversaries can verify the efficacy of their attack via an inference API or access to an offline copy of the target model. |
| [AML.T0043 Craft Adversarial Data](https://atlas.mitre.org/techniques/AML.T0043) | 8 | Adversarial data are inputs to an AI model that have been modified such that they cause the adversary's desired effect in the target model. |
| &nbsp;&nbsp;↳ [AML.T0043.000 White-Box Optimization](https://atlas.mitre.org/techniques/AML.T0043.000) | 6 | In White-Box Optimization, the adversary has full access to the target model and optimizes the adversarial example directly. |
| &nbsp;&nbsp;↳ [AML.T0043.001 Black-Box Optimization](https://atlas.mitre.org/techniques/AML.T0043.001) | 8 | In Black-Box attacks, the adversary has black-box (i.e. AI Model Inference API Access via API access) access to the target model. |
| &nbsp;&nbsp;↳ [AML.T0043.002 Black-Box Transfer](https://atlas.mitre.org/techniques/AML.T0043.002) | 4 | In Black-Box Transfer attacks, the adversary uses one or more proxy models (trained via Replicate AI Model Behavior or Replicate Behavior from Model Outputs) they have full access to and are representative of the target model. |
| &nbsp;&nbsp;↳ [AML.T0043.003 Manual Modification](https://atlas.mitre.org/techniques/AML.T0043.003) | 5 | Adversaries may manually modify the input data to craft adversarial data. |
| &nbsp;&nbsp;↳ [AML.T0043.004 Insert Backdoor Trigger](https://atlas.mitre.org/techniques/AML.T0043.004) | 5 | The adversary may add a perceptual trigger into inference data. |
| [AML.T0065 LLM Prompt Crafting](https://atlas.mitre.org/techniques/AML.T0065) | 0 | Adversaries may use their acquired knowledge of the target generative AI system to craft prompts that bypass its defenses and allow malicious instructions to be executed. |
| [AML.T0066 Retrieval Content Crafting](https://atlas.mitre.org/techniques/AML.T0066) | 0 | Adversaries may write content designed to be retrieved by user queries and influence a user of the system in some way. |
| [AML.T0088 Generate Deepfakes](https://atlas.mitre.org/techniques/AML.T0088) | 2 | Adversaries may use generative artificial intelligence (GenAI) to create synthetic media (i.e. imagery, video, audio, and text) that appear authentic. |
| [AML.T0102 Generate Malicious Commands](https://atlas.mitre.org/techniques/AML.T0102) | 2 | Adversaries may use large language models (LLMs) to dynamically generate malicious commands from natural language. |
| [AML.T0117 Autonomous Attack-Path Adaptation](https://atlas.mitre.org/techniques/AML.T0117) | 4 | Adversaries may use an AI agent to autonomously construct and repeatedly revise an attack path toward an adversary-defined objective. |
| [AML.T0118 Autonomous AI Agent Communication](https://atlas.mitre.org/techniques/AML.T0118) | 6 | Autonomous AI agents may exchange operational information with other AI agents, sub-agents, or independent agent runs. |
| &nbsp;&nbsp;↳ [AML.T0118.000 Communication via Shared Artifacts](https://atlas.mitre.org/techniques/AML.T0118.000) | 6 | Autonomous AI agents may communicate by creating or modifying artifacts in a shared resource that persists outside their individual execution contexts. |
| &nbsp;&nbsp;↳ [AML.T0118.001 Direct Agent Communication](https://atlas.mitre.org/techniques/AML.T0118.001) | 5 | Autonomous AI agents may communicate directly through agent-to-agent, sub-agent, or orchestrator interfaces. |
| [AML.T0124 Autonomous Attack Orchestration](https://atlas.mitre.org/techniques/AML.T0124) | 7 | Adversaries may use autonomous AI systems as an operational control layer to manage multiple distinct autonomous agents or sub-agents toward a common adversary-defined objective. |

## Initial Access
<a id="initial-access"></a>

[`AML.TA0004`](https://atlas.mitre.org/tactics/AML.TA0004), 18 techniques

The adversary is trying to gain access to the AI system. The target system could be a network, mobile device, or an edge device such as a sensor platform. The AI capabilities used by the system could be local with onboard or cloud-enabled AI capabilities. Initial Access consists of techniques that use various entry vectors to gain their initial foothold within the system.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0010 Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010) | 4 | Adversaries may manipulate products, components, or their development and delivery mechanisms before they reach downstream consumers to compromise data or systems. |
| &nbsp;&nbsp;↳ [AML.T0010.000 Hardware](https://atlas.mitre.org/techniques/AML.T0010.000) | 1 | Adversaries may target AI systems by disrupting or manipulating the hardware supply chain. |
| &nbsp;&nbsp;↳ [AML.T0010.001 Software](https://atlas.mitre.org/techniques/AML.T0010.001) | 5 | Adversaries may target software packages that are commonly used in AI-enabled systems or are part of the AI DevOps lifecycle. |
| &nbsp;&nbsp;↳ [AML.T0010.002 Data Repository](https://atlas.mitre.org/techniques/AML.T0010.002) | 7 | Adversaries may abuse data repositories or other dataset distribution services to introduce compromised data into downstream AI workflows. |
| &nbsp;&nbsp;↳ [AML.T0010.003 Model Repository](https://atlas.mitre.org/techniques/AML.T0010.003) | 8 | Adversaries may abuse model repositories or other model distribution services to introduce compromised models into downstream AI systems. |
| &nbsp;&nbsp;↳ [AML.T0010.004 Container Registry](https://atlas.mitre.org/techniques/AML.T0010.004) | 3 | An adversary may compromise a victim's container registry by pushing a manipulated container image and overwriting an existing container name and/or tag. |
| &nbsp;&nbsp;↳ [AML.T0010.005 AI Agent Tool](https://atlas.mitre.org/techniques/AML.T0010.005) | 3 | Adversaries may target AI agent tools as a means to compromise a victim's AI supply chain. |
| [AML.T0012 Valid Accounts](https://atlas.mitre.org/techniques/AML.T0012) | 3 | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access. |
| [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015) | 8 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. |
| [AML.T0049 Exploit Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0049) | 2 | Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. |
| [AML.T0052 Phishing](https://atlas.mitre.org/techniques/AML.T0052) | 2 | Adversaries may send phishing messages to gain access to victim systems. |
| &nbsp;&nbsp;↳ [AML.T0052.000 Spearphishing via Social Engineering LLM](https://atlas.mitre.org/techniques/AML.T0052.000) | 2 | Adversaries may use large language models (LLMs) or LLM-based AI agents to conduct targeted social engineering through electronically delivered messages and conversations. |
| &nbsp;&nbsp;↳ [AML.T0052.001 Deepfake-Assisted Phishing](https://atlas.mitre.org/techniques/AML.T0052.001) | 2 | Adversaries may use deepfakes (AI-generated synthetic images, audio, or video) in phishing campaigns to impersonate trusted individuals, executives, or organizations. |
| [AML.T0078 Drive-by Compromise](https://atlas.mitre.org/techniques/AML.T0078) | 1 | Adversaries may gain access to an AI system through a user visiting a website over the normal course of browsing, or an AI agent retrieving information from the web on behalf of a user. |
| [AML.T0093 Prompt Infiltration via Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0093) | 1 | An adversary may introduce malicious prompts into the victim's system via a public-facing application with the intention of it being ingested by an AI at some point in the future and ultimately having a downstream effect. |
| [AML.T0119 Exploit Automated Artifact Processing Pipeline](https://atlas.mitre.org/techniques/AML.T0119) | 3 | Adversaries may submit, publish, or modify an artifact in a way that triggers an automated processing pipeline. |
| [AML.T0131 Crafted AI Assistant Links](https://atlas.mitre.org/techniques/AML.T0131) | 0 | Adversaries may craft links that open an AI assistant or agent with attacker-controlled input already supplied, so that opening the link initiates an interaction the adversary defines rather than one the target composed. |
| [AML.T0132 Misconfigured or Publicly Exposed AI Services](https://atlas.mitre.org/techniques/AML.T0132) | 1 | AI agents and LLM platforms are deployed across diverse architectures, including standalone servers, SaaS platforms, and low-code builders. |

## AI Model Access
<a id="ai-model-access"></a>

[`AML.TA0000`](https://atlas.mitre.org/tactics/AML.TA0000), 4 techniques

The adversary is attempting to gain some level of access to an AI model. AI Model Access enables techniques that use various types of access to the AI model that can be used by the adversary to gain information, develop attacks, and as a means to input data to the model. The level of access can range from the full knowledge of the internals of the model to access to the physical environment where data is collected for use in the AI model. The adversary may use varying levels of model access during the course of their attack, from staging the attack to impacting the target system. Access to an AI model may require access to the system housing the model, the model may be publicly accessible via an API, or it may be accessed indirectly via interaction with a product or service that utilizes AI as part of its processes.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0040 AI Model Inference API Access](https://atlas.mitre.org/techniques/AML.T0040) | 3 | Adversaries may gain access to a model via legitimate access to the inference API. |
| [AML.T0041 Physical Environment Access](https://atlas.mitre.org/techniques/AML.T0041) | 1 | In addition to the attacks that take place purely in the digital domain, adversaries may also exploit the physical environment for their attacks. |
| [AML.T0044 Full AI Model Access](https://atlas.mitre.org/techniques/AML.T0044) | 2 | Adversaries may gain full "white-box" access to an AI model. |
| [AML.T0047 AI-Enabled Product or Service](https://atlas.mitre.org/techniques/AML.T0047) | 1 | Adversaries may use a product or service that uses artificial intelligence under the hood to gain access to the underlying AI model. |

## Execution
<a id="execution"></a>

[`AML.TA0005`](https://atlas.mitre.org/tactics/AML.TA0005), 13 techniques

The adversary is trying to run malicious code embedded in AI artifacts or software. Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0011 User Execution](https://atlas.mitre.org/techniques/AML.T0011) | 4 | An adversary may rely upon a user to load, execute, interpret, or otherwise use a malicious or unsafe artifact. |
| &nbsp;&nbsp;↳ [AML.T0011.000 Unsafe AI Artifacts](https://atlas.mitre.org/techniques/AML.T0011.000) | 5 | Adversaries may develop new AI artifacts or manipulate existing AI artifacts that have a deleterious effect when loaded, executed, interpreted, or used for inference by a victim. |
| &nbsp;&nbsp;↳ [AML.T0011.001 Malicious Package](https://atlas.mitre.org/techniques/AML.T0011.001) | 4 | Adversaries may develop malicious software packages that when imported by a user have a deleterious effect. |
| &nbsp;&nbsp;↳ [AML.T0011.002 Poisoned AI Agent Tool](https://atlas.mitre.org/techniques/AML.T0011.002) | 0 | A victim may invoke a poisoned tool when interacting with an AI agent. |
| &nbsp;&nbsp;↳ [AML.T0011.003 Malicious Link](https://atlas.mitre.org/techniques/AML.T0011.003) | 0 | An adversary may rely upon a user clicking a malicious link in order to gain execution. |
| [AML.T0050 Command and Scripting Interpreter](https://atlas.mitre.org/techniques/AML.T0050) | 1 | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. |
| [AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051) | 8 | An adversary may craft malicious prompts as inputs to an LLM that cause the LLM to act in unintended ways. |
| &nbsp;&nbsp;↳ [AML.T0051.000 Direct](https://atlas.mitre.org/techniques/AML.T0051.000) | 3 | An adversary may inject prompts directly as a user of the LLM. |
| &nbsp;&nbsp;↳ [AML.T0051.001 Indirect](https://atlas.mitre.org/techniques/AML.T0051.001) | 3 | An adversary may inject prompts indirectly via a separate data channel that the LLM or AI agent ingests, such as text or multimedia pulled from documents, emails, databases or websites. |
| &nbsp;&nbsp;↳ [AML.T0051.002 Triggered](https://atlas.mitre.org/techniques/AML.T0051.002) | 3 | An adversary may trigger a prompt injection via a user action or event that occurs within the victim's environment. |
| [AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053) | 13 | Adversaries may use their access to an AI agent to invoke tools the agent has access to. |
| [AML.T0100 AI Agent Clickbait](https://atlas.mitre.org/techniques/AML.T0100) | 2 | Adversaries may craft deceptive content designed to bait computer-using AI agents or AI web browsers and tools into taking unintended actions, such as clicking buttons, copying code, or navigating to specific web pages. |
| [AML.T0103 Deploy AI Agent](https://atlas.mitre.org/techniques/AML.T0103) | 1 | Adversaries may launch AI agents in the victim's environment to execute actions on their behalf. |

## Persistence
<a id="persistence"></a>

[`AML.TA0006`](https://atlas.mitre.org/tactics/AML.TA0006), 22 techniques

The adversary is trying to maintain their foothold via AI artifacts or software. Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence often involve leaving behind modified ML artifacts such as poisoned training data or manipulated AI models.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0018 Manipulate AI Model](https://atlas.mitre.org/techniques/AML.T0018) | 4 | Adversaries may manipulate an AI model artifact or its bundled components to change AI system behavior, introduce malicious code, or establish persistent malicious functionality. |
| &nbsp;&nbsp;↳ [AML.T0018.000 Poison AI Model](https://atlas.mitre.org/techniques/AML.T0018.000) | 8 | Adversaries may manipulate an AI model's weights to change it's behavior or performance, resulting in a poisoned model. |
| &nbsp;&nbsp;↳ [AML.T0018.001 Modify AI Model Architecture](https://atlas.mitre.org/techniques/AML.T0018.001) | 5 | Adversaries may directly modify an AI model's architecture to re-define it's behavior. |
| &nbsp;&nbsp;↳ [AML.T0018.002 Embed Malware](https://atlas.mitre.org/techniques/AML.T0018.002) | 2 | Adversaries may embed malicious code into AI Model files. |
| &nbsp;&nbsp;↳ [AML.T0018.003 Modify Prompt Construction Logic](https://atlas.mitre.org/techniques/AML.T0018.003) | 2 | Adversaries may modify templates, role delimiters, embedded system instructions, tokenizer settings, tool-call formatting, or other artifact-bundled logic that constructs the context sent to an AI model. |
| [AML.T0020 Training Data Poisoning](https://atlas.mitre.org/techniques/AML.T0020) | 8 | Adversaries may manipulate data used for training or fine-tuning an AI model to influence the resulting model's behavior. |
| [AML.T0061 LLM Prompt Self-Replication](https://atlas.mitre.org/techniques/AML.T0061) | 3 | Adversaries may introduce a prompt designed to replicate itself in a large language model's (LLM) output. |
| [AML.T0070 RAG Poisoning](https://atlas.mitre.org/techniques/AML.T0070) | 2 | Adversaries may inject malicious content into data indexed by a retrieval augmented generation (RAG) system to contaminate a future thread through RAG-based search results. |
| [AML.T0080 AI Agent Context Poisoning](https://atlas.mitre.org/techniques/AML.T0080) | 3 | Adversaries may attempt to manipulate the context used by an AI agent's large language model (LLM) to influence the responses it generates or actions it takes. |
| &nbsp;&nbsp;↳ [AML.T0080.000 Memory](https://atlas.mitre.org/techniques/AML.T0080.000) | 3 | Adversaries may manipulate the memory of a large language model (LLM) in order to persist changes to the LLM across future chat sessions. |
| &nbsp;&nbsp;↳ [AML.T0080.001 Thread](https://atlas.mitre.org/techniques/AML.T0080.001) | 2 | Adversaries may introduce malicious instructions into a chat thread of a large language model (LLM) to cause behavior changes which persist for the remainder of the thread. |
| [AML.T0081 Modify AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0081) | 1 | Adversaries may modify the configuration files for AI agents on a system. |
| [AML.T0093 Prompt Infiltration via Public-Facing Application](https://atlas.mitre.org/techniques/AML.T0093) | 1 | An adversary may introduce malicious prompts into the victim's system via a public-facing application with the intention of it being ingested by an AI at some point in the future and ultimately having a downstream effect. |
| [AML.T0099 AI Agent Tool Data Poisoning](https://atlas.mitre.org/techniques/AML.T0099) | 1 | Adversaries may manipulate data in a victim-controlled, trusted, or connected data source that is accessible through an AI agent tool. |
| [AML.T0110 AI Agent Tool Poisoning](https://atlas.mitre.org/techniques/AML.T0110) | 0 | Adversaries may poison tools used by AI agents by introducing or modifying malicious content or behavior in a tool's model-visible definition, executable implementation, or runtime responses. |
| &nbsp;&nbsp;↳ [AML.T0110.000 Definition and Instructions](https://atlas.mitre.org/techniques/AML.T0110.000) | 1 | Adversaries may poison the model-visible definition or operational instructions of an AI agent tool to manipulate how an agent interprets, selects, or invokes the tool. |
| &nbsp;&nbsp;↳ [AML.T0110.001 Implementation](https://atlas.mitre.org/techniques/AML.T0110.001) | 0 | Adversaries may poison the executable implementation of an AI agent tool so that normal tool invocation produces unauthorized behavior or hidden side effects. |
| &nbsp;&nbsp;↳ [AML.T0110.002 Runtime Response](https://atlas.mitre.org/techniques/AML.T0110.002) | 1 | Adversaries may poison the runtime response channel of a malicious or compromised AI agent tool by deliberately returning content intended to influence the model's subsequent reasoning, decisions, or actions. |
| [AML.T0121 AI Agent Environment Reconstruction](https://atlas.mitre.org/techniques/AML.T0121) | 6 | An autonomous AI agent may reconstruct the environment needed to continue an existing operation after its execution environment is lost, reset, replaced, denied, or made unusable. |
| [AML.T0125 Create Account](https://atlas.mitre.org/techniques/AML.T0125) | 1 | Adversaries may create an account to maintain access to an AI system or its supporting infrastructure. |
| [AML.T0142 Event Triggered Execution](https://atlas.mitre.org/techniques/AML.T0142) | 2 | Adversaries may establish persistence by creating or modifying event handlers, startup hooks, or associated configuration so that subsequent system or application activity automatically executes adversary-controlled code or commands. |
| [AML.T0145 Poison AI Agent Learning Environment](https://atlas.mitre.org/techniques/AML.T0145) | 6 | Adversaries may manipulate an environment in which an AI agent interacts so that observations, feedback, rewards, actions, or resulting interactions are incorporated into model training to cause persistent changes to the behavior of an AI system. |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`AML.TA0012`](https://atlas.mitre.org/tactics/AML.TA0012), 4 techniques

The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: - SYSTEM/root level - local administrator - user account with admin-like access - user accounts with access to a specific system or permission to perform a specific function These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0012 Valid Accounts](https://atlas.mitre.org/techniques/AML.T0012) | 3 | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access. |
| [AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053) | 13 | Adversaries may use their access to an AI agent to invoke tools the agent has access to. |
| [AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054) | 5 | Adversaries may induce a large language model (LLM) to ignore, circumvent, or override its safety/alignment behaviors and/or guardrails to elicit outputs the model is intended to withhold. |
| [AML.T0105 Escape to Host](https://atlas.mitre.org/techniques/AML.T0105) | 0 | Adversaries may break out of a container or virtualized environment to gain access to the underlying host. |

## Defense Evasion
<a id="defense-evasion"></a>

[`AML.TA0007`](https://atlas.mitre.org/tactics/AML.TA0007), 22 techniques

The adversary is trying to avoid being detected by AI-enabled security software. Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include evading AI-enabled security software such as malware detectors.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015) | 8 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. |
| [AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054) | 5 | Adversaries may induce a large language model (LLM) to ignore, circumvent, or override its safety/alignment behaviors and/or guardrails to elicit outputs the model is intended to withhold. |
| [AML.T0067 LLM Trusted Output Components Manipulation](https://atlas.mitre.org/techniques/AML.T0067) | 1 | Adversaries may utilize prompts to a large language model (LLM) which manipulate various components of its response in order to make it appear trustworthy to the user. |
| &nbsp;&nbsp;↳ [AML.T0067.000 Citations](https://atlas.mitre.org/techniques/AML.T0067.000) | 1 | Adversaries may manipulate the citations provided in an AI system's response, in order to make it appear trustworthy. |
| [AML.T0068 LLM Prompt Obfuscation](https://atlas.mitre.org/techniques/AML.T0068) | 2 | Adversaries may hide or otherwise obfuscate prompt injections or retrieval content to avoid detection from humans, large language model (LLM) guardrails, or other detection mechanisms. |
| [AML.T0071 False RAG Entry Injection](https://atlas.mitre.org/techniques/AML.T0071) | 1 | Adversaries may introduce false entries into a victim's retrieval augmented generation (RAG) database. |
| [AML.T0073 Impersonation](https://atlas.mitre.org/techniques/AML.T0073) | 1 | Adversaries may impersonate an existing person or organization, trusted AI agent, or present a fabricated persona as a trustworthy or independent party, to persuade a target to act on their behalf. |
| [AML.T0074 Masquerading](https://atlas.mitre.org/techniques/AML.T0074) | 2 | Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. |
| [AML.T0076 Corrupt AI Model](https://atlas.mitre.org/techniques/AML.T0076) | 0 | An adversary may purposefully corrupt a malicious AI model file so that it cannot be successfully deserialized in order to evade detection by a model scanner. |
| [AML.T0081 Modify AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0081) | 1 | Adversaries may modify the configuration files for AI agents on a system. |
| [AML.T0092 Manipulate User LLM Chat History](https://atlas.mitre.org/techniques/AML.T0092) | 0 | Adversaries may manipulate a user's large language model (LLM) chat history to cover the tracks of their malicious behavior. |
| [AML.T0094 Delay Execution of LLM Instructions](https://atlas.mitre.org/techniques/AML.T0094) | 1 | Adversaries may include instructions to be followed by the AI system in response to a future event, such as a specific keyword or the next interaction, in order to evade detection or bypass controls placed on the AI system. |
| [AML.T0097 Virtualization/Sandbox Evasion](https://atlas.mitre.org/techniques/AML.T0097) | 0 | Adversaries may employ various means to detect and avoid virtualization and analysis environments. |
| [AML.T0107 Exploitation for Defense Evasion](https://atlas.mitre.org/techniques/AML.T0107) | 2 | Adversaries may exploit a system or application vulnerability to bypass security features. |
| [AML.T0109 AI Supply Chain Rug Pull](https://atlas.mitre.org/techniques/AML.T0109) | 2 | Adversaries may publish legitimate AI components or software, gain user adoption, then push an update with a malicious variant, leading to Supply Chain Compromise. |
| [AML.T0111 AI Supply Chain Reputation Inflation](https://atlas.mitre.org/techniques/AML.T0111) | 0 | AI Supply Chain Reputation Inflation is the process of building or leveraging genuinely credible-looking trust signals to increase the perceived legitimacy of AI supply chain components, with the goal of driving adoption of malicious or compromised assets. |
| [AML.T0123 Obfuscated Files or Information](https://atlas.mitre.org/techniques/AML.T0123) | 0 | Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. |
| [AML.T0129 Triggers in Multimodal Inputs](https://atlas.mitre.org/techniques/AML.T0129) | 2 | Adversaries may place instructions or triggers in one part of a multimodal input to influence the model while staying unnoticed by human reviewers and by defenses that do not inspect all input modalities. |
| [AML.T0134 AI Targeted Cloaking](https://atlas.mitre.org/techniques/AML.T0134) | 0 | Adversaries may selectively deliver malicious or manipulated content to AI systems, while presenting different benign content to human users, web crawlers, or security detection mechanisms. |
| [AML.T0138 Indicator Removal](https://atlas.mitre.org/techniques/AML.T0138) | 0 | Adversaries may delete, alter, or falsify records and artifacts to conceal their activity, impede investigation, or make unauthorized actions appear legitimate. |
| [AML.T0140 Centralized AI Service Request Routing](https://atlas.mitre.org/techniques/AML.T0140) | 1 | Adversaries may distribute coordinated AI service requests across multiple pathways to impede detection, conceal the coordinated nature of the requests, and evade AI provider enforcement. |
| [AML.T0141 AI Service Request Metadata Sanitization](https://atlas.mitre.org/techniques/AML.T0141) | 0 | Adversaries may remove or replace identifying information in request metadata before submitting requests to an AI service to impede attribution and correlation of coordinated activity. |

## Credential Access
<a id="credential-access"></a>

[`AML.TA0013`](https://atlas.mitre.org/tactics/AML.TA0013), 7 techniques

The adversary is trying to steal account names and passwords. Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0055 Unsecured Credentials](https://atlas.mitre.org/techniques/AML.T0055) | 0 | Adversaries may search compromised systems to find and obtain insecurely stored credentials. |
| [AML.T0082 RAG Credential Harvesting](https://atlas.mitre.org/techniques/AML.T0082) | 3 | Adversaries may attempt to use their access to a large language model (LLM) on the victim's system to collect credentials. |
| [AML.T0083 Credentials from AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0083) | 0 | Adversaries may access the credentials of other tools or services on a system from the configuration of an AI agent. |
| [AML.T0090 OS Credential Dumping](https://atlas.mitre.org/techniques/AML.T0090) | 1 | Adversaries may extract credentials from OS caches, application memory, or other sources on a compromised system. |
| [AML.T0098 AI Agent Tool Credential Harvesting](https://atlas.mitre.org/techniques/AML.T0098) | 1 | Adversaries may attempt to use their access to an AI agent on the victim's system to retrieve data from available agent tools to collect credentials. |
| [AML.T0106 Exploitation for Credential Access](https://atlas.mitre.org/techniques/AML.T0106) | 2 | Adversaries may exploit software vulnerabilities in an attempt to collect credentials. |
| [AML.T0113 Steal Web Session Cookie](https://atlas.mitre.org/techniques/AML.T0113) | 0 | Adversaries may steal web application or service session cookies used to authenticate users to AI-enabled systems, AI services, or supporting enterprise applications. |

## Discovery
<a id="discovery"></a>

[`AML.TA0008`](https://atlas.mitre.org/tactics/AML.TA0008), 18 techniques

The adversary is trying to figure out your AI environment. Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what's around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0007 Discover AI Artifacts](https://atlas.mitre.org/techniques/AML.T0007) | 2 | Adversaries may search private sources to identify AI learning artifacts that exist on the system and gather information about them. |
| [AML.T0013 Discover AI Model Ontology](https://atlas.mitre.org/techniques/AML.T0013) | 2 | Adversaries may discover the ontology of an AI model's output space, for example, the types of objects a model can detect. |
| [AML.T0014 Discover AI Model Family](https://atlas.mitre.org/techniques/AML.T0014) | 3 | Adversaries may discover the general family of a model. |
| [AML.T0062 Discover LLM Hallucinations](https://atlas.mitre.org/techniques/AML.T0062) | 4 | Adversaries may prompt large language models and identify hallucinated entities. |
| [AML.T0063 Discover AI Model Outputs](https://atlas.mitre.org/techniques/AML.T0063) | 4 | Adversaries may discover what information an AI model or service exposes through its outputs. |
| [AML.T0069 Discover LLM System Information](https://atlas.mitre.org/techniques/AML.T0069) | 4 | The adversary is trying to discover something about the large language model's (LLM) system information. |
| &nbsp;&nbsp;↳ [AML.T0069.000 Special Character Sets](https://atlas.mitre.org/techniques/AML.T0069.000) | 3 | Adversaries may discover delimiters and special characters sets used by the large language model. |
| &nbsp;&nbsp;↳ [AML.T0069.001 System Instruction Keywords](https://atlas.mitre.org/techniques/AML.T0069.001) | 2 | Adversaries may discover keywords that have special meaning to the large language model (LLM), such as function names or object names. |
| &nbsp;&nbsp;↳ [AML.T0069.002 System Prompt](https://atlas.mitre.org/techniques/AML.T0069.002) | 3 | Adversaries may discover a large language model's system instructions provided by the AI system builder to learn about the system's capabilities and circumvent its guardrails. |
| [AML.T0075 Enterprise Resource Discovery](https://atlas.mitre.org/techniques/AML.T0075) | 0 | Adversaries may discover resources available within an enterprise environment and information needed to identify or access them. |
| [AML.T0084 Discover AI Agent Configuration](https://atlas.mitre.org/techniques/AML.T0084) | 2 | Adversaries may attempt to discover configuration information for AI agents present on the victim's system. |
| &nbsp;&nbsp;↳ [AML.T0084.000 Embedded Knowledge](https://atlas.mitre.org/techniques/AML.T0084.000) | 0 | Adversaries may attempt to discover the data sources a particular agent can access. |
| &nbsp;&nbsp;↳ [AML.T0084.001 Tool Definitions](https://atlas.mitre.org/techniques/AML.T0084.001) | 1 | Adversaries may discover the tools the AI agent has access to. |
| &nbsp;&nbsp;↳ [AML.T0084.002 Activation Triggers](https://atlas.mitre.org/techniques/AML.T0084.002) | 1 | Adversaries may discover keywords or other triggers (such as incoming emails, documents being added, incoming message, or other workflows) that activate an agent and may cause it to run additional actions. |
| &nbsp;&nbsp;↳ [AML.T0084.003 Call Chains](https://atlas.mitre.org/techniques/AML.T0084.003) | 1 | Adversaries may extract call chains from AI agent configurations, which can reveal potentially targets for remote code execution (RCE) or other vulnerabilities. |
| [AML.T0089 Enterprise Environment Discovery](https://atlas.mitre.org/techniques/AML.T0089) | 0 | Adversaries may discover configurations, conditions, relationships, activity, and other characteristics of an enterprise environment. |
| [AML.T0133 Discover AI Agent Runtime Capabilities](https://atlas.mitre.org/techniques/AML.T0133) | 1 | Adversaries may interact with an AI agent at runtime to reveal the capabilities available to it, without requiring access to its underlying configuration. |
| [AML.T0144 Recover AI Model Internals](https://atlas.mitre.org/techniques/AML.T0144) | 1 | Adversaries may infer or recover non-public AI model internals through analysis of model behavior or exposed information. |

## Lateral Movement
<a id="lateral-movement"></a>

[`AML.TA0015`](https://atlas.mitre.org/tactics/AML.TA0015), 10 techniques

The adversary is trying to move through your AI environment. Lateral Movement consists of techniques that adversaries may use to gain access to and control other systems or components in the environment. Adversaries may pivot towards AI Ops infrastructure such as model registries, experiment trackers, vector databases, notebooks, or training pipelines. As the adversary moves through the environment, they may discover means of accessing additional AI-related tools, services, or applications. AI agents may also be a valuable target as they commonly have more permissions than standard user accounts on the system.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0012 Valid Accounts](https://atlas.mitre.org/techniques/AML.T0012) | 3 | Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access. |
| [AML.T0052 Phishing](https://atlas.mitre.org/techniques/AML.T0052) | 2 | Adversaries may send phishing messages to gain access to victim systems. |
| &nbsp;&nbsp;↳ [AML.T0052.000 Spearphishing via Social Engineering LLM](https://atlas.mitre.org/techniques/AML.T0052.000) | 2 | Adversaries may use large language models (LLMs) or LLM-based AI agents to conduct targeted social engineering through electronically delivered messages and conversations. |
| &nbsp;&nbsp;↳ [AML.T0052.001 Deepfake-Assisted Phishing](https://atlas.mitre.org/techniques/AML.T0052.001) | 2 | Adversaries may use deepfakes (AI-generated synthetic images, audio, or video) in phishing campaigns to impersonate trusted individuals, executives, or organizations. |
| [AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053) | 13 | Adversaries may use their access to an AI agent to invoke tools the agent has access to. |
| [AML.T0091 Use Alternate Authentication Material](https://atlas.mitre.org/techniques/AML.T0091) | 1 | Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. |
| &nbsp;&nbsp;↳ [AML.T0091.000 Application Access Token](https://atlas.mitre.org/techniques/AML.T0091.000) | 2 | Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. |
| &nbsp;&nbsp;↳ [AML.T0091.001 Web Session Cookie](https://atlas.mitre.org/techniques/AML.T0091.001) | 0 | Adversaries may use stolen web session cookies to authenticate to AI-enabled applications and supporting services as another user. |
| [AML.T0122 Exploitation of Remote Services](https://atlas.mitre.org/techniques/AML.T0122) | 4 | Adversaries may exploit a software or design weakness in a service reachable from their current environment to gain unauthorized access to another system, component, network, or trust boundary. |
| [AML.T0143 LLM Prompt Propagation](https://atlas.mitre.org/techniques/AML.T0143) | 6 | Adversaries may cause malicious instructions already introduced into an AI-enabled environment to be transferred onward to additional storage locations, agents, applications, or resources where they can influence subsequent AI activity. |

## Collection
<a id="collection"></a>

[`AML.TA0009`](https://atlas.mitre.org/tactics/AML.TA0009), 17 techniques

The adversary is trying to gather AI artifacts and other related information relevant to their goal. Collection consists of techniques adversaries may use to gather information and identify sources from which relevant information can be collected to further their objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the AI artifacts, or use the collected information to stage future operations. Common target sources include software repositories, container registries, model repositories, and object stores.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0035 AI Artifact Collection](https://atlas.mitre.org/techniques/AML.T0035) | 4 | Adversaries may collect AI artifacts for Exfiltration or for use in AI Attack Adaptation. |
| [AML.T0036 Data from Information Repositories](https://atlas.mitre.org/techniques/AML.T0036) | 0 | Adversaries may leverage information repositories to mine valuable information. |
| [AML.T0037 Data from Local System](https://atlas.mitre.org/techniques/AML.T0037) | 0 | Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration. |
| [AML.T0085 Data from AI Services](https://atlas.mitre.org/techniques/AML.T0085) | 6 | Adversaries may use their access to victim AI-enabled services to collect proprietary or otherwise sensitive information available to the system. |
| &nbsp;&nbsp;↳ [AML.T0085.000 RAG Databases](https://atlas.mitre.org/techniques/AML.T0085.000) | 6 | Adversaries may collect sensitive information from data sources that an AI service accesses to retrieve context for its responses. |
| &nbsp;&nbsp;↳ [AML.T0085.001 AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0085.001) | 6 | Adversaries may collect sensitive information through tools available to an AI agent. |
| &nbsp;&nbsp;↳ [AML.T0085.002 Conversation Context and Memory](https://atlas.mitre.org/techniques/AML.T0085.002) | 5 | Adversaries may collect sensitive information from an AI service's current or stored interactions and memory. |
| &nbsp;&nbsp;↳ [AML.T0085.003 System Instructions](https://atlas.mitre.org/techniques/AML.T0085.003) | 5 | Adversaries may collect non-public instructions used to configure the behavior of an AI model or agent. |
| [AML.T0126 Automated Collection](https://atlas.mitre.org/techniques/AML.T0126) | 2 | Adversaries may use automated techniques to collect data from AI systems and supporting enterprise environments. |
| [AML.T0127 Data Staged](https://atlas.mitre.org/techniques/AML.T0127) | 1 | Adversaries may stage collected data in a central location before exfiltration. |
| [AML.T0135 Outputs from AI Models](https://atlas.mitre.org/techniques/AML.T0135) | 1 | Adversaries may gather, retain, and organize outputs from an AI model or service as material for subsequent adversarial operations. |
| [AML.T0137 Training Data Information from AI Models](https://atlas.mitre.org/techniques/AML.T0137) | 2 | Adversaries may obtain sensitive information about the data used to train or fine-tune an AI model by analyzing its outputs or behavior. |
| &nbsp;&nbsp;↳ [AML.T0137.000 Infer Membership](https://atlas.mitre.org/techniques/AML.T0137.000) | 7 | Adversaries may infer whether a particular data sample was included in an AI model's training dataset. |
| &nbsp;&nbsp;↳ [AML.T0137.001 Infer Properties](https://atlas.mitre.org/techniques/AML.T0137.001) | 2 | Adversaries may infer sensitive global properties of the data used to train an AI model. |
| &nbsp;&nbsp;↳ [AML.T0137.002 Invert AI Model](https://atlas.mitre.org/techniques/AML.T0137.002) | 7 | Adversaries may infer sensitive aggregate attributes or reconstruct representative examples of data used to train or fine-tune a target AI model by analyzing its behavior, outputs, or exposed representations. |
| &nbsp;&nbsp;↳ [AML.T0137.003 Extract Memorized Data](https://atlas.mitre.org/techniques/AML.T0137.003) | 4 | Adversaries may elicit and recover sensitive content memorized by a generative AI model during training or fine-tuning. |
| [AML.T0144 Recover AI Model Internals](https://atlas.mitre.org/techniques/AML.T0144) | 1 | Adversaries may infer or recover non-public AI model internals through analysis of model behavior or exposed information. |

## Command and Control
<a id="command-and-control"></a>

[`AML.TA0014`](https://atlas.mitre.org/tactics/AML.TA0014), 5 techniques

The adversary is trying to communicate with compromised AI systems to control them. Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim's network structure and defenses.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0072 Cyber Communication Channel](https://atlas.mitre.org/techniques/AML.T0072) | 1 | Adversaries may establish or use cyber communication channels for command and control. |
| [AML.T0096 AI Service API](https://atlas.mitre.org/techniques/AML.T0096) | 1 | Adversaries may communicate using the API of an AI service on the victim's system. |
| [AML.T0108 AI Agent](https://atlas.mitre.org/techniques/AML.T0108) | 2 | Adversaries may abuse AI agents present on the victim's system for command and control. |
| [AML.T0114 AI Service Web Interface](https://atlas.mitre.org/techniques/AML.T0114) | 1 | Adversaries may communicate with compromised systems by abusing the web interface of an AI service as an intermediary command-and-control relay. |
| [AML.T0120 AI Artifact Repository](https://atlas.mitre.org/techniques/AML.T0120) | 2 | Adversaries may repurpose AI artifact repositories as asynchronous command-and-control channels. |

## Exfiltration
<a id="exfiltration"></a>

[`AML.TA0010`](https://atlas.mitre.org/tactics/AML.TA0010), 5 techniques

The adversary is trying to steal AI artifacts or other information about the AI system. Exfiltration consists of techniques that adversaries may use to steal data from your network. Data may be stolen for its valuable intellectual property, or for use in staging future operations. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0024 Exfiltration via AI Inference API](https://atlas.mitre.org/techniques/AML.T0024) | 4 | Adversaries may exfiltrate information from a victim-controlled AI model or service through responses returned by its inference API. |
| [AML.T0025 Exfiltration via Cyber Means](https://atlas.mitre.org/techniques/AML.T0025) | 1 | Adversaries may exfiltrate AI artifacts or other information relevant to their goals via traditional cyber means. |
| [AML.T0077 LLM Response Rendering](https://atlas.mitre.org/techniques/AML.T0077) | 1 | Adversaries may induce a large language model (LLM) to respond with private information structured in a reference to external content that, when rendered by the user's client, makes a request to an adversary-controlled server, exfiltrating the data. |
| [AML.T0086 Exfiltration via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0086) | 9 | AI agent tools capable of performing write operations may be invoked to exfiltrate data to an adversary. |
| [AML.T0136 Exfiltration via AI User Interface](https://atlas.mitre.org/techniques/AML.T0136) | 0 | Adversaries exfiltrate information through an AI system's user-facing outputs. |

## Impact
<a id="impact"></a>

[`AML.TA0011`](https://atlas.mitre.org/tactics/AML.TA0011), 20 techniques

The adversary is trying to manipulate, interrupt, erode confidence in, or destroy your AI systems and data. Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been altered to benefit the adversaries' goals. These techniques might be used by adversaries to follow through on their end goal or to provide cover for a confidentiality breach.

| Technique | Mitigations | Description |
|---|--:|---|
| [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015) | 8 | Adversaries can Craft Adversarial Data that prevents an AI model from correctly identifying the contents of the data or Generate Deepfakes that fools an AI model expecting authentic data. |
| [AML.T0029 Denial of AI Service](https://atlas.mitre.org/techniques/AML.T0029) | 5 | Adversaries may target AI-enabled systems with a flood of requests for the purpose of degrading or shutting down the service. |
| [AML.T0031 Erode AI Model Integrity](https://atlas.mitre.org/techniques/AML.T0031) | 4 | Adversaries may degrade the target model's performance with adversarial data inputs to erode confidence in the system over time. |
| [AML.T0034 Cost Harvesting](https://atlas.mitre.org/techniques/AML.T0034) | 4 | Adversaries may deliberately drive a victim's AI services beyond normal operating capacity with the intent of increasing the cost of services. |
| &nbsp;&nbsp;↳ [AML.T0034.000 Excessive Queries](https://atlas.mitre.org/techniques/AML.T0034.000) | 1 | Adversaries may send an excessive number of otherwise normal or low-complexity queries to an AI system with the goal of overwhelming its capacity and increasing operating costs. |
| &nbsp;&nbsp;↳ [AML.T0034.001 Resource-Intensive Queries](https://atlas.mitre.org/techniques/AML.T0034.001) | 2 | Adversaries may craft inputs specifically designed to increase the compute resources required for processing. |
| &nbsp;&nbsp;↳ [AML.T0034.002 Agentic Resource Consumption](https://atlas.mitre.org/techniques/AML.T0034.002) | 2 | Adversaries may coerce an agentic AI system into performing computationally expensive tool calls that waste resources and consume API budgets. |
| [AML.T0046 Spamming AI System with Chaff Data](https://atlas.mitre.org/techniques/AML.T0046) | 2 | Adversaries may spam the AI system with chaff data that causes increase in the number of detections. |
| [AML.T0048 External Harms](https://atlas.mitre.org/techniques/AML.T0048) | 0 | Adversaries may abuse their access to a victim system and use its resources or capabilities to further their goals by causing harms external to that system. |
| &nbsp;&nbsp;↳ [AML.T0048.000 Financial Harm](https://atlas.mitre.org/techniques/AML.T0048.000) | 0 | Financial harm involves the loss of wealth, property, or other monetary assets due to theft, fraud or forgery, or pressure to provide financial resources to the adversary. |
| &nbsp;&nbsp;↳ [AML.T0048.001 Reputational Harm](https://atlas.mitre.org/techniques/AML.T0048.001) | 0 | Reputational harm involves a degradation of public perception and trust in organizations. |
| &nbsp;&nbsp;↳ [AML.T0048.002 Societal Harm](https://atlas.mitre.org/techniques/AML.T0048.002) | 0 | Societal harms might generate harmful outcomes that reach either the general public or specific vulnerable groups such as the exposure of children to vulgar content. |
| &nbsp;&nbsp;↳ [AML.T0048.003 User Harm](https://atlas.mitre.org/techniques/AML.T0048.003) | 0 | User harms may encompass a variety of harm types including financial and reputational that are directed at or felt by individual victims of the attack rather than at the organization level. |
| &nbsp;&nbsp;↳ [AML.T0048.004 AI Intellectual Property Theft](https://atlas.mitre.org/techniques/AML.T0048.004) | 3 | Adversaries may appropriate AI-related intellectual property in a manner that causes economic or competitive harm to the victim organization. |
| [AML.T0059 Erode Dataset Integrity](https://atlas.mitre.org/techniques/AML.T0059) | 2 | Adversaries may poison or manipulate portions of a dataset to reduce its usefulness, reduce trust, and cause users to waste resources correcting errors. |
| [AML.T0101 Data Destruction via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0101) | 6 | Adversaries may invoke an AI agent's tool capable of performing mutative operations to perform Data Destruction. |
| [AML.T0112 Machine Compromise](https://atlas.mitre.org/techniques/AML.T0112) | 0 | Adversaries may compromise a machine by exploiting or manipulating AI-enabled components on the system. |
| &nbsp;&nbsp;↳ [AML.T0112.000 Local AI Agent](https://atlas.mitre.org/techniques/AML.T0112.000) | 2 | Adversaries may achieve full system compromise by abusing AI agents running locally on a host, such as computer-use agents or AI-driven browsers. |
| &nbsp;&nbsp;↳ [AML.T0112.001 AI Artifacts](https://atlas.mitre.org/techniques/AML.T0112.001) | 1 | Adversaries may achieve full system compromise by introducing malicious AI artifacts, such as models or data, that contain embedded malware or other malicious commands. |
| [AML.T0130 AI Agent Response Biasing](https://atlas.mitre.org/techniques/AML.T0130) | 1 | Adversaries may manipulate an AI assistant so that it favors adversary-chosen sources, or content in its responses. |

---

## ATLAS mitigations

ATLAS 2026.10 lists 44 mitigations, ordered here by the number of techniques each one addresses, then by ID.

| Mitigation | Techniques | Description |
|---|--:|---|
| [AML.M0020 Generative AI Guardrails](https://atlas.mitre.org/mitigations/AML.M0020) | 35 | Guardrails are safety controls placed between users, tools, and generative AI models to evaluate prompts, retrieved context, model outputs, and agent actions before they are accepted, executed, or shown to a user. |
| [AML.M0035 AI Red Team](https://atlas.mitre.org/mitigations/AML.M0035) | 34 | Establish an AI red team responsible for conducting recurring, authorized, and threat-informed red-teaming exercises to identify and remediate vulnerabilities in AI-enabled systems before deployment and throughout operation. |
| [AML.M0005 Control Access to AI Models and Data at Rest](https://atlas.mitre.org/mitigations/AML.M0005) | 22 | Establish access controls on internal model registries and limit internal access to production models. |
| [AML.M0042 Threat Intelligence Program](https://atlas.mitre.org/mitigations/AML.M0042) | 22 | A Threat Intelligence Program enables organizations to proactively collect, analyze, and share information on threats to AI and cyber systems by leveraging internal observations and external reporting. |
| [AML.M0019 Control Access to AI Models and Data in Production](https://atlas.mitre.org/mitigations/AML.M0019) | 20 | Require users to verify their identities before accessing a production model. |
| [AML.M0024 AI Telemetry Logging and Monitoring](https://atlas.mitre.org/mitigations/AML.M0024) | 20 | Implement logging and monitoring across the AI lifecycle to detect suspicious activity and support investigation. |
| [AML.M0039 AI Honeypots](https://atlas.mitre.org/mitigations/AML.M0039) | 19 | Deploy monitored decoy AI services, agents, credentials, or other resources that resemble legitimate, active assets in the external or internal environment, but serve no real business or operational functions. |
| [AML.M0008 Validate AI Model](https://atlas.mitre.org/mitigations/AML.M0008) | 18 | Evaluate AI models against defined functional requirements before deployment and throughout their operational lifecycle. |
| [AML.M0000 Limit Public Release of Information](https://atlas.mitre.org/mitigations/AML.M0000) | 17 | Limit the public release of technical information about the AI stack used in an organization's products or services. |
| [AML.M0004 Limit AI Service Query Volume and Rate](https://atlas.mitre.org/mitigations/AML.M0004) | 15 | Limit the number and rate of requests that users can submit to an AI service. |
| [AML.M0014 Verify AI Artifacts](https://atlas.mitre.org/mitigations/AML.M0014) | 13 | Verify the integrity and authenticity of AI artifacts before importing, loading, or deploying them. |
| [AML.M0022 Generative AI Model Alignment](https://atlas.mitre.org/mitigations/AML.M0022) | 13 | Generative AI Model Alignment is the process of training or fine-tuning a generative model to guide its output toward a set of human values, goals, or ethical principles. |
| [AML.M0032 Segmentation of AI Agent Components](https://atlas.mitre.org/mitigations/AML.M0032) | 13 | Define enforceable security boundaries around AI agent tools, data sources, identities, and execution environments. |
| [AML.M0026 Manage AI Agent Service Access](https://atlas.mitre.org/mitigations/AML.M0026) | 12 | Limit service AI agents--agents using independently assigned service or workload permissions--to explicitly authorized workflows. |
| [AML.M0027 Manage User-Delegated AI Agent Access](https://atlas.mitre.org/mitigations/AML.M0027) | 12 | Limit user-delegated AI agents to explicitly authorized tasks and permissions. |
| [AML.M0028 Enforce Access Controls for AI Agent Tools](https://atlas.mitre.org/mitigations/AML.M0028) | 12 | Limit AI agent tool access to each caller's authorized, task-required operations and resources, including when tools are shared across agents, users, or tenants. |
| [AML.M0040 Adaptive AI Response Degradation](https://atlas.mitre.org/mitigations/AML.M0040) | 12 | Reduce the utility of AI model outputs for unauthorized model replication, knowledge distillation, or inference about training data by dynamically modifying responses when suspected extraction activity or privacy attacks are detected. |
| [AML.M0016 Vulnerability Scanning](https://atlas.mitre.org/mitigations/AML.M0016) | 11 | Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. |
| [AML.M0002 Predictive AI Output Obfuscation](https://atlas.mitre.org/mitigations/AML.M0002) | 10 | Reduce the fidelity and amount of information returned by predictive AI inference endpoints to make model discovery, extraction, replication, and black-box adversarial-example optimization more difficult. |
| [AML.M0013 Code Signing](https://atlas.mitre.org/mitigations/AML.M0013) | 10 | Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing. |
| [AML.M0043 AI Agent External Resource Lifecycle Management](https://atlas.mitre.org/mitigations/AML.M0043) | 10 | Organizations should control external resources created or acquired by AI agents during execution by treating those resources as attributable, lifecycle-managed assets. |
| [AML.M0001 Limit Model Artifact Release](https://atlas.mitre.org/mitigations/AML.M0001) | 9 | Limit public release of technical project details including data, algorithms, model architectures, and model checkpoints that are used in production, or that are representative of those used in production. |
| [AML.M0006 Predictive AI Ensembles](https://atlas.mitre.org/mitigations/AML.M0006) | 9 | Use an ensemble of diverse predictive AI models to reduce reliance on a single model or model family and improve robustness against adversarial examples. |
| [AML.M0015 Predictive AI Adversarial Input Detection](https://atlas.mitre.org/mitigations/AML.M0015) | 9 | Detect and block digital or physical adversarial examples submitted to predictive AI models. |
| [AML.M0023 Maintain an AI Bill of Materials](https://atlas.mitre.org/mitigations/AML.M0023) | 9 | Create and maintain an AI Bill of Materials (AI BOM) that identifies the components and dependencies used to build, evaluate, and operate an AI-enabled system. |
| [AML.M0003 Predictive AI Model Hardening](https://atlas.mitre.org/mitigations/AML.M0003) | 8 | Design and train predictive AI models to maintain intended performance when presented with adversarial examples. |
| [AML.M0010 Predictive AI Input Restoration](https://atlas.mitre.org/mitigations/AML.M0010) | 8 | Preprocess predictive AI inference inputs to remove, reduce, or disrupt adversarial perturbations before the inputs are evaluated by the model. |
| [AML.M0011 Restrict Library Loading](https://atlas.mitre.org/mitigations/AML.M0011) | 8 | Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. |
| [AML.M0021 Generative AI Guidelines](https://atlas.mitre.org/mitigations/AML.M0021) | 8 | Guidelines are instructions, policies, and behavioral constraints provided to a generative AI model to direct it toward desired outputs and away from unsafe, unreliable, or policy-violating behavior. |
| [AML.M0007 Sanitize Training Data](https://atlas.mitre.org/mitigations/AML.M0007) | 7 | Detect, quarantine, and remove or remediate poisoned data before it is used to train an AI model. |
| [AML.M0033 Input and Output Validation for AI Agent Components](https://atlas.mitre.org/mitigations/AML.M0033) | 7 | Implement validation on inputs and outputs for the tools and data sources used by AI agents. |
| [AML.M0038 AI Agent Scope Drift Detection](https://atlas.mitre.org/mitigations/AML.M0038) | 7 | Continuously evaluate whether an AI Agent's planned actions remain consistent with its current authorized objective throughout execution. |
| [AML.M0017 AI Model Distribution Methods](https://atlas.mitre.org/mitigations/AML.M0017) | 6 | Deploying AI models to edge devices can increase the attack surface of the system. |
| [AML.M0018 User Training](https://atlas.mitre.org/mitigations/AML.M0018) | 6 | Educate AI model developers to on AI supply chain risks and potentially malicious AI artifacts. |
| [AML.M0025 Maintain AI Dataset Provenance](https://atlas.mitre.org/mitigations/AML.M0025) | 6 | Maintain a detailed history of datasets used for AI applications. |
| [AML.M0034 Deepfake Detection](https://atlas.mitre.org/mitigations/AML.M0034) | 5 | Apply deepfake detection algorithms against any untrusted or user-provided data, especially in impactful applications such as biometric verification, to block generated content. |
| [AML.M0036 Limit AI Workload Resource Consumption](https://atlas.mitre.org/mitigations/AML.M0036) | 5 | Limit the resources that an AI request, inference job, or agent workflow can consume. |
| [AML.M0037 AI Agent Authority Expansion Controls](https://atlas.mitre.org/mitigations/AML.M0037) | 5 | Limit an AI agent's ability to autonomously acquire additional authorities that expand its effective permissions during execution. |
| [AML.M0041 Privacy-Preserving AI Training and Inference](https://atlas.mitre.org/mitigations/AML.M0041) | 5 | Use privacy-preserving mechanisms throughout model training and inference to limit disclosure of sensitive training or inference data. |
| [AML.M0012 Encrypt Sensitive Information](https://atlas.mitre.org/mitigations/AML.M0012) | 4 | Encrypt sensitive data such as AI models to protect against adversaries attempting to access sensitive data. |
| [AML.M0029 Human In-the-Loop for AI Agent Actions](https://atlas.mitre.org/mitigations/AML.M0029) | 4 | Systems should require the user or another human stakeholder to approve AI agent actions before the agent takes them. |
| [AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data](https://atlas.mitre.org/mitigations/AML.M0030) | 4 | Untrusted data can contain prompt injections that invoke an AI agent's tools, potentially causing confidentiality, integrity or availability violations. |
| [AML.M0009 Predictive AI Multi-Sensor Fusion](https://atlas.mitre.org/mitigations/AML.M0009) | 3 | Use independent physical sensors (ideally across multiple modalities or from several perspectives) to avoid relying on a single sensor that may be manipulated, obstructed, or disrupted by an adversary. |
| [AML.M0031 Memory Hardening](https://atlas.mitre.org/mitigations/AML.M0031) | 2 | Memory Hardening protects persistent state used by AI agents, including saved preferences, episodic or semantic memories, conversation summaries, stored chat history, and agent-managed experience stores. |

## Retired technique IDs

Technique IDs that earlier ATLAS releases used and 2026.10 no longer has. The successor is the one the ATLAS release notes name; where they name none, the ID was dropped and no replacement should be inferred.

| Retired ID | Name in its last release | Successor | Retired in |
|---|---|---|---|
| AML.T0019 | Publish Poisoned Datasets | [AML.T0115.000 Publish Poisoned AI Artifacts: Datasets](https://atlas.mitre.org/techniques/AML.T0115.000) | ATLAS 2026.07 |
| AML.T0024.000 | Exfiltration via AI Inference API: Infer Training Data Membership | [AML.T0137.000 Training Data Information from AI Models: Infer Membership](https://atlas.mitre.org/techniques/AML.T0137.000) | ATLAS 2026.10 |
| AML.T0024.001 | Exfiltration via AI Inference API: Invert AI Model | [AML.T0137.002 Training Data Information from AI Models: Invert AI Model](https://atlas.mitre.org/techniques/AML.T0137.002) | ATLAS 2026.10 |
| AML.T0024.002 | Exfiltration via AI Inference API: Extract AI Model | None named | ATLAS 2026.10 |
| AML.T0056 | Extract LLM System Prompt | [AML.T0085.003 Data from AI Services: System Instructions](https://atlas.mitre.org/techniques/AML.T0085.003) | ATLAS 2026.10 |
| AML.T0057 | LLM Data Leakage | [AML.T0085.002 Data from AI Services: Conversation Context and Memory](https://atlas.mitre.org/techniques/AML.T0085.002) | ATLAS 2026.10 |
| AML.T0058 | Publish Poisoned Models | [AML.T0115.001 Publish Poisoned AI Artifacts: Models](https://atlas.mitre.org/techniques/AML.T0115.001) | ATLAS 2026.07 |
| AML.T0104 | Publish Poisoned AI Agent Tool | [AML.T0115.002 Publish Poisoned AI Artifacts: AI Agent Tools](https://atlas.mitre.org/techniques/AML.T0115.002) | ATLAS 2026.07 |

<!-- atlas-data end -->

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [AI and emerging tech](/hubs/ai-and-emerging-tech.md)
- Learning path: [Adversarial AI Attacks](/disciplines/adversarial-ai-attacks.md)
- [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md)
- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md)
- [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md)

<!-- related:end -->

---

*Source: [MITRE ATLAS](https://atlas.mitre.org/) via [mitre-atlas/atlas-navigator-data](https://github.com/mitre-atlas/atlas-navigator-data) STIX export. ATLAS™ and ATT&CK® are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream project for authoritative content.*
