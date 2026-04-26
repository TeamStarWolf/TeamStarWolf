# AI Offensive Security Reference

## Section 1: The AI Security Revolution

### Timeline of AI-Powered Offensive Security

The integration of large language models into offensive security workflows represents one of the most significant shifts in the threat landscape since the advent of automated vulnerability scanners. What began as speculative research has rapidly evolved into demonstrated capability, commercial products, and open-source tooling that places sophisticated exploit development within reach of a much broader range of actors.

**2023 — GPT-4 and the CTF Baseline**

The first systematic public evidence emerged in 2023 when GPT-4 was evaluated against Capture-the-Flag challenges. Researchers found that GPT-4 could solve beginner-to-intermediate CTF challenges autonomously, including web exploitation, binary exploitation, and cryptographic challenges that previously required domain expertise. While success rates varied widely by challenge difficulty, the directional signal was clear: LLMs could reason about vulnerabilities, generate payloads, and adapt their approach based on error feedback. The key capability unlocked was the ability to combine background knowledge (CVE databases, exploit patterns, tool syntax) with dynamic reasoning in a feedback loop — the core loop of a human pentester.

**April 2024 — UIUC Study: GPT-4 at 87% on 1-Day CVEs**

The landmark paper by Fang et al. from the University of Illinois Urbana-Champaign published in April 2024 quantified what many in the security community had suspected. Testing GPT-4 against a curated set of real-world 1-day CVEs (vulnerabilities with published patches but not yet widely patched in production), the researchers found an 87% exploitation success rate when GPT-4 was provided with the CVE description and access to a tool-augmented agent framework. GPT-3.5 achieved 0% on the same benchmark. The gap between model generations was not incremental — it was categorical. This study demonstrated that the capability threshold had been crossed: frontier AI models could reliably operationalize published vulnerability intelligence into working exploits without human assistance.

The tested CVEs spanned web application vulnerabilities, privilege escalation chains, and service-level exploits. The methodology involved providing the model with the CVE identifier, a brief description, and access to a shell environment with common security tools. The model would then reason through the exploitation steps, execute commands, observe output, and iterate. The 87% figure represents end-to-end exploitation success: the model not only identified the correct exploitation technique but produced a working proof-of-concept.

**2024 — Anthropic Glasswing**

In 2024, Anthropic developed Glasswing, an internal autonomous penetration testing system built on Claude. Glasswing represented Anthropic's own exploration of AI-powered offensive security capabilities, designed to assess Anthropic's own infrastructure and provide a practical understanding of how frontier AI models could be applied to vulnerability discovery and exploitation. The system incorporated a multi-stage reasoning pipeline and human-in-the-loop guardrails to ensure containment and responsible operation. Glasswing's development signaled that leading AI labs were taking seriously the dual-use nature of their technology and investing in understanding its offensive applications.

**2025 — Clearwing Open-Source Release**

In 2025, Eric Hartford and the Lazarus AI team released Clearwing as an open-source autonomous penetration testing framework. Clearwing operationalized many of the concepts demonstrated in academic research and the Glasswing internal project, making them available to the broader security community. Built on a Rust LLM runtime and supporting over a dozen AI providers, Clearwing offered four distinct operational modes covering network penetration testing, source code vulnerability hunting, N-day exploit development, and reverse engineering. Its release democratized access to AI-powered security tooling in a manner comparable to how Metasploit democratized exploit frameworks two decades earlier.

**2025–2026 — Commercial Autonomous Agent Products**

The commercial security market rapidly incorporated AI capabilities. CrowdStrike Charlotte AI, Microsoft Security Copilot, Splunk AI, Darktrace, and Vectra AI all introduced autonomous or semi-autonomous capabilities for both offensive (red team) and defensive (detection/response) applications. Specialized tools like EscalateGPT (Tenable) for cloud privilege escalation and cve-mcp-server for standardized vulnerability intelligence querying emerged as components in larger security automation workflows.

### Why This Matters: Democratization and Infinite Scale

The significance of AI-powered offensive security tools lies not merely in their capability at the frontier, but in what they do to the economics and scaling dynamics of attacks.

**Democratization of Exploit Development**

Prior to AI-assisted tooling, developing a working exploit for a complex vulnerability required deep domain expertise: understanding of memory layout, calling conventions, mitigation bypass techniques, and application-specific behavior. This expertise took years to develop and was concentrated in a small number of specialists. AI models trained on vast corpora of security research, exploit code, and tool documentation effectively compress this learning. A practitioner with moderate security knowledge can now direct an AI system to develop exploits that would previously have required senior-level expertise. This does not eliminate the need for expertise — it shifts it from exploit mechanics to higher-level direction and validation.

**Infinite Scaling for Attackers**

Human attackers are rate-limited by time and attention. A skilled red teamer might assess one target thoroughly per week. An AI-powered attack system can run assessments against hundreds of targets simultaneously, 24 hours a day, without fatigue. Each instance maintains the same level of systematic thoroughness. When combined with cloud computing resources, this creates an asymmetry: the cost of scaling attacks approaches zero while the cost of defending each individual asset remains fixed.

**The Defender's Dilemma**

Defenders face a structural disadvantage that AI amplifies. A defender must protect every entry point; an attacker needs only one. AI tools make attackers more effective at the discovery phase (identifying all potential entry points) and the exploitation phase (rapidly developing working exploits after discovery). The window between vulnerability disclosure and exploitation, historically measured in days to weeks, is compressing toward hours. Organizations that cannot patch at machine speed face a period of exposure that AI-powered attackers can exploit with high probability of success.

The defender's response must incorporate the same technologies: AI-powered patch prioritization, automated detection of AI-driven attack patterns, and authorized deployment of AI red team tools to discover vulnerabilities before attackers do. The security community's challenge is to ensure that defensive applications of AI develop at least as rapidly as offensive ones.

## Section 2: Glasswing — Anthropic's Internal Penetration Testing AI

### What Glasswing Is

Glasswing is Anthropic's internally developed autonomous penetration testing system, built on the Claude family of models. It represents Anthropic's practical engagement with the dual-use implications of frontier AI: understanding how their own models could be applied to offensive security tasks, and using that understanding both to assess Anthropic's own infrastructure and to inform responsible AI development practices.

Unlike commercial security tools that add AI as a feature layer on top of existing frameworks, Glasswing was designed from the ground up as an AI-native system. The core architecture centers on a multi-stage reasoning pipeline that mirrors the cognitive workflow of an experienced human penetration tester, with each stage informed by the outputs of previous stages and adapted based on observed results.

### Multi-Stage Reasoning Pipeline

**Stage 1: Reconnaissance**

Glasswing begins with structured reconnaissance, querying available information sources about the target environment. In network penetration testing contexts, this includes service enumeration, banner grabbing, certificate inspection, and DNS analysis. In source code review contexts, it includes dependency analysis, entry point identification, and data flow mapping. The reconnaissance stage builds a structured model of the target that informs subsequent stages.

The AI's advantage in reconnaissance is not speed (automated scanners can enumerate faster) but comprehension: Glasswing interprets reconnaissance results in context, identifying which findings are significant, which suggest specific vulnerability classes, and how different findings relate to each other. A human analyst reading scan output applies similar contextual reasoning; Glasswing applies it systematically at scale.

**Stage 2: Vulnerability Identification**

Given the reconnaissance model, Glasswing reasons about potential vulnerability classes present in the target. This stage draws on Claude's training on security research, CVE databases, exploit writeups, and defensive documentation. The model generates hypotheses about vulnerabilities and prioritizes them by exploitability and impact.

This stage benefits from Claude's broad knowledge base. When Glasswing identifies a specific software version, it can recall known vulnerabilities, patch history, and exploitation techniques associated with that version. When it identifies a code pattern, it can recognize vulnerability signatures that match known classes of flaws. The result is a vulnerability hypothesis set that reflects both current CVE intelligence and pattern-matched code analysis.

**Stage 3: Exploitation**

For each prioritized vulnerability hypothesis, Glasswing develops an exploitation approach. This involves selecting appropriate tools, crafting payloads, and reasoning about the steps required to move from initial access to the defined objective. The exploitation stage is where Glasswing's agentic capabilities are most prominent: it executes tools, observes outputs, adapts its approach based on results, and maintains context across multiple steps.

Glasswing's exploitation reasoning includes awareness of common mitigations (ASLR, DEP, stack canaries, WAF rules) and techniques to address them. It can reason about multi-step exploitation chains where initial access through one vulnerability enables exploitation of a second vulnerability that would otherwise be inaccessible.

**Stage 4: Reporting**

Glasswing generates structured reports documenting findings, exploitation paths, evidence, and remediation recommendations. Reports are formatted for both technical audiences (detailed exploitation steps, proof-of-concept code, root cause analysis) and management audiences (risk ratings, business impact, remediation priority). The reporting stage includes mapping findings to MITRE ATT&CK techniques and CWE categories.

### Human-in-the-Loop Guardrails

Glasswing incorporates mandatory human approval checkpoints before executing potentially destructive or irreversible actions. The system distinguishes between reconnaissance actions (generally automated), vulnerability identification (automated with logging), and exploitation (requiring explicit human authorization before execution).

This design reflects Anthropic's broader philosophy about AI safety: capable AI systems operating in high-stakes domains should preserve human oversight and control. The guardrails are not merely procedural — they are architectural. Glasswing's action categories are defined such that the most consequential actions cannot be executed without human confirmation, regardless of the AI's assessment of their appropriateness.

Containment mechanisms include network isolation requirements (Glasswing operates within defined network segments with explicit scope boundaries), tool allowlisting (only pre-approved tools are available for execution), and session logging (complete audit trails of all actions and reasoning). These mechanisms ensure that an AI system with genuine offensive capabilities cannot be redirected outside its authorized scope.

### Glasswing and Frontier AI Capability

Glasswing's significance extends beyond its specific capabilities. Its development by Anthropic — a leading AI safety organization — demonstrates that responsible AI development requires direct engagement with offensive applications. Understanding how frontier models can be applied to exploitation is necessary for building effective safeguards.

Anthropic has made public statements emphasizing that Glasswing is used exclusively for authorized internal security assessments and that findings are used to improve Anthropic's own security posture. The system is not available externally and is subject to strict access controls. These practices reflect the broader principle that powerful dual-use tools require proportionally rigorous governance.

### Influence on Open-Source Equivalents

The conceptual architecture of Glasswing — multi-stage pipeline, tool-augmented agents, human-in-the-loop guardrails, structured reporting — has influenced the design of open-source penetration testing AI systems. Clearwing (discussed in Section 3) represents the most comprehensive open-source implementation of similar concepts, adapted for external use with comparable safety considerations.

The broader ecosystem of AI security tools has converged on similar architectural patterns, suggesting that this design space has been well-explored and that the core patterns are both functional and practical for real-world deployment.

## Section 3: Clearwing — Deep Technical Reference

### Overview

Clearwing is an open-source autonomous penetration testing framework developed by Eric Hartford and the Lazarus AI team, available at github.com/Lazarus-AI/clearwing. It represents the most comprehensive publicly available implementation of AI-powered offensive security tooling, incorporating lessons from academic research, commercial security practice, and AI agent design.

The project is built on genai-pyo3, a Rust-based LLM runtime that provides high-performance, low-latency inference and tool execution. This architectural choice reflects a design philosophy prioritizing reliability and performance in long-running agentic workflows: Rust's memory safety guarantees and performance characteristics make it well-suited for the sustained execution required in comprehensive security assessments.

### Provider Support

Clearwing supports an extensive range of AI providers and deployment configurations:

- **Anthropic** (Claude Opus, Sonnet, Haiku via API)
- **OpenAI** (GPT-4o, GPT-4-turbo, GPT-3.5-turbo via API)
- **OpenRouter** (aggregated access to 100+ models)
- **Ollama** (local model deployment, privacy-preserving)
- **LM Studio** (local model deployment with GUI)
- **Together AI** (open-source model hosting)
- **Groq** (ultra-low-latency inference)
- **DeepSeek** (cost-effective reasoning models)
- **Google Gemini** (multimodal capabilities)
- **Any OpenAI-compatible endpoint** (self-hosted, fine-tuned models)

This provider flexibility allows practitioners to select models based on capability requirements, cost constraints, privacy requirements, and latency needs. For sensitive engagements, local Ollama or LM Studio deployments ensure no assessment data leaves the practitioner's infrastructure.

### Installation and Setup

```bash
# Install with uv (recommended)
uv sync

# Initialize Clearwing configuration
clearwing setup

# Verify installation and provider connectivity
clearwing doctor

# Configure provider (example: Anthropic)
clearwing config set provider anthropic
clearwing config set model claude-opus-4-5
clearwing config set api_key $ANTHROPIC_API_KEY

# Configure for local Ollama deployment
clearwing config set provider ollama
clearwing config set model llama3.1:70b
clearwing config set base_url http://localhost:11434
```

### Operational Mode 1: Network Penetration Testing Agent

The network penetration testing mode implements a full ReAct (Reasoning + Acting) loop for autonomous network security assessment. The agent operates against defined targets within explicit scope boundaries.

**Architecture**

The ReAct loop consists of alternating reasoning steps (the model thinks about what to do next based on current state) and action steps (the model executes a tool and observes the result). This loop continues until the agent reaches a defined objective, exhausts its approach space, or encounters a human approval checkpoint.

**Tool Inventory (63 bound tools)**

Clearwing binds 63 security tools organized by function:

*Reconnaissance Tools*: nmap (network scanning, service detection, OS fingerprinting), masscan (high-speed port scanning), nslookup, dig, whois, theHarvester (OSINT), amass (subdomain enumeration), subfinder, httpx (web probing), whatweb (technology fingerprinting)

*Web Application Tools*: nikto (web vulnerability scanner), gobuster/dirb/ffuf (directory/file fuzzing), wfuzz (web fuzzer), sqlmap (SQL injection), XSSer (cross-site scripting), wapiti (web app scanner), nuclei (template-based scanning), burpsuite-cli

*Exploitation Tools*: metasploit-framework (msfconsole, msfvenom), searchsploit (exploit database search), exploitdb, pwntools (binary exploitation), ROPgadget (ROP chain construction)

*Post-Exploitation Tools*: mimikatz (credential extraction), bloodhound (Active Directory analysis), crackmapexec (lateral movement), impacket suite (SMB/Kerberos/LDAP tools), evil-winrm (WinRM shell)

*Password Tools*: hashcat (hash cracking), john (John the Ripper), hydra (brute force), medusa, crunch (wordlist generation)

*Network Tools*: netcat, socat, tcpdump, wireshark-cli, responder (LLMNR/NBT-NS poisoning), bettercap

*Analysis Tools*: strings, binwalk, foremost, volatility (memory forensics), yara

**Sandboxed Kali Execution**

All tool execution occurs within a sandboxed Kali Linux environment. The sandbox provides isolation between the agent's execution environment and the practitioner's host system, preventing accidental scope expansion and ensuring consistent tool availability. The Kali environment includes the full Kali Linux tool repository, ensuring all 63 bound tools are available without additional installation.

**Human Approval Guardrail**

Before executing any tool classified as potentially exploitative or destructive, Clearwing presents the proposed action to the human operator for approval. The approval prompt includes the tool name, arguments, expected behavior, and the agent's reasoning for why this action is appropriate. The operator can approve, deny, or modify the action.

This guardrail is architecturally enforced: exploitation-class tools cannot be executed without explicit approval. The distinction between reconnaissance tools (generally auto-approved based on configuration) and exploitation tools (always requiring approval) is defined in the tool registry and cannot be bypassed through prompt injection or other manipulation.

**Knowledge Graph Persistence**

Clearwing maintains a knowledge graph throughout the assessment, storing discovered hosts, services, vulnerabilities, credentials, relationships, and exploitation paths. This persistent state enables the agent to reason about multi-hop attack chains (e.g., "credential discovered on host A enables access to service on host B which has a known vulnerability leading to host C") and to resume interrupted assessments without losing context.

**Report Generation**

At assessment completion, Clearwing generates structured reports in multiple formats: markdown (human-readable), JSON (machine-readable for integration with ticketing systems), and SARIF (Static Analysis Results Interchange Format for integration with CI/CD pipelines and IDE plugins). Reports include executive summary, technical findings, exploitation evidence, MITRE ATT&CK mapping, CVSS scores, and prioritized remediation recommendations.

### Operational Mode 2: Source Code Vulnerability Hunter

The source code hunting mode performs autonomous vulnerability discovery in source code repositories, combining static analysis with dynamic validation.

**File-Parallel Agent Fan-Out**

For large codebases, Clearwing fans out analysis agents across files in parallel. Each agent instance analyzes a subset of files, maintaining awareness of the overall codebase structure through the shared knowledge graph. Results from parallel agents are aggregated and cross-referenced to identify cross-component vulnerabilities.

**ASan/UBSan Crashes as Ground Truth**

Clearwing integrates with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) to validate hypothesized vulnerabilities dynamically. When the agent identifies a potential memory safety issue or undefined behavior, it generates test cases designed to trigger the condition and compiles the target with sanitizer instrumentation. Sanitizer crashes provide definitive ground truth: if the crash occurs, the vulnerability is real and triggerable.

**Four-Axis Validator**

Each candidate vulnerability is evaluated on four axes before being included in the final report:

1. **REAL**: Does the vulnerability exist in the codebase? (Static analysis confirmation)
2. **TRIGGERABLE**: Can the vulnerability be triggered by an attacker? (Reachability analysis, input validation review)
3. **IMPACTFUL**: Does successful exploitation have meaningful security impact? (Confidentiality/integrity/availability assessment)
4. **GENERAL**: Is the vulnerability broadly exploitable or limited to narrow conditions? (Input space analysis)

Only vulnerabilities scoring positively on all four axes are classified as confirmed findings. Partial scores generate candidate findings requiring additional investigation.

**Evidence Ladder**

Clearwing tracks the evidence quality for each finding through a six-rung ladder:

1. **suspicion**: Pattern match suggests potential vulnerability
2. **static_corroboration**: Multiple static analysis indicators confirm the pattern
3. **crash_reproduced**: Dynamic testing produces a sanitizer crash
4. **root_cause_explained**: LLM analysis identifies the exact root cause and exploitation path
5. **exploit_demonstrated**: Working proof-of-concept exploit developed and tested
6. **patch_validated**: Proposed patch eliminates the vulnerability without regression

Findings are reported with their evidence ladder position, enabling triage teams to prioritize by confidence level.

**Three-Band Budget Promotion**

Clearwing manages computational budget across three bands:

- **Fast band**: Static analysis, pattern matching, quick validation (seconds per finding)
- **Standard band**: Dynamic testing, automated exploit development (minutes per finding)
- **Deep band**: Manual-equivalent analysis, complex exploit chains, edge case validation (hours per finding)

The system automatically promotes findings to higher bands based on initial evidence quality, ensuring that high-confidence findings receive thorough validation while not wasting budget on low-probability hypotheses.

**SARIF/Markdown/JSON Output**

All source code hunting results are available in SARIF format for integration with GitHub Advanced Security, GitLab SAST, and other CI/CD security tooling. SARIF output includes finding location (file, line, column), severity, rule identifier, related locations (for multi-file vulnerabilities), and fix suggestions.

**Cross-Subsystem Hunting**

Clearwing performs cross-subsystem vulnerability analysis, tracking data flows across module and component boundaries. This enables discovery of vulnerabilities that span multiple components: data entering through a web API layer, passing through a business logic layer, and triggering a memory safety issue in a low-level utility library.

### Operational Mode 3: N-Day Exploit Pipeline

The N-day exploit pipeline automates the development of working exploits for known CVEs, compressing the time from vulnerability publication to working exploit.

**Pipeline Stages**

1. **CVE Input**: Operator provides CVE identifier
2. **Intelligence Gathering**: Clearwing queries NVD, MITRE, and vendor advisories for vulnerability details, affected versions, and patch information
3. **Vulnerable Version Build**: Automatically constructs a Docker container running the vulnerable version of the affected software
4. **Patch Diff Analysis**: Retrieves the patch commit and analyzes the diff to identify the exact code change addressing the vulnerability
5. **Vulnerability Condition Reconstruction**: Reverse-engineers the vulnerable condition from the patch diff and CVE description
6. **Exploit Development**: Develops a working exploit targeting the reconstructed vulnerable condition
7. **Container Testing**: Tests the exploit against the containerized vulnerable version
8. **Patch Validation**: Verifies the exploit fails against the patched version, confirming the exploit targets the correct vulnerability

**Timeline Compression**

This pipeline compresses what previously required days of expert effort into hours of automated processing. For common vulnerability classes (SQL injection, command injection, path traversal, simple buffer overflows), the pipeline achieves high success rates. For complex memory corruption vulnerabilities requiring advanced mitigation bypass, the pipeline generates a strong starting point requiring expert refinement.

### Operational Mode 4: Reverse Engineering

The reverse engineering mode combines static binary analysis with LLM-powered code reconstruction for vulnerability hunting in compiled binaries.

**Ghidra Headless Integration**

Clearwing integrates with Ghidra's headless analyzer to decompile binary targets without requiring the Ghidra GUI. The decompiled output is fed to the LLM for source reconstruction and vulnerability analysis.

**Hybrid Source+Binary Analysis**

When partial source code is available (e.g., open-source projects with binary distributions), Clearwing performs hybrid analysis combining source-level understanding with binary-level observation. This enables detection of vulnerabilities introduced during compilation or configuration that are not visible in the source alone.

### Campaign Orchestration

For large-scale assessments, Clearwing supports campaign orchestration via YAML configuration files. A single YAML file can specify hundreds of repositories or targets, assessment parameters, provider configuration, budget limits, and reporting preferences.

```yaml
campaign:
  name: "Q1 2026 Asset Review"
  targets:
    - type: github_org
      org: "example-corp"
      repos: all
  modes:
    - source_code_hunter
    - nday_pipeline
  provider: anthropic
  model: claude-opus-4-5
  budget:
    max_tokens_per_target: 1000000
    max_time_per_target: 3600
  reporting:
    formats: [sarif, markdown, json]
    output_dir: ./results
```

Campaign runs support checkpoint and resume: if a run is interrupted, it restarts from the last completed target rather than from the beginning.

### Responsible Disclosure Integration

Clearwing includes a complete responsible disclosure workflow:

**SHA-3 Cryptographic Commitments**: When a vulnerability is discovered, Clearwing generates a SHA-3 hash commitment of the finding details and timestamps it. This provides cryptographic proof of discovery date for disputes about independent discovery.

**MITRE/HackerOne Templates**: Clearwing generates pre-formatted vulnerability reports for MITRE CVE submission and HackerOne/Bugcrowd bug bounty platforms, reducing the friction of responsible disclosure.

**Timeline Tracking**: The system tracks disclosure timeline milestones (discovery, vendor notification, vendor acknowledgment, patch release, public disclosure) and generates reminders for standard disclosure windows (typically 90 days).

## Section 4: Other AI Security Tools

### EscalateGPT (Tenable)

EscalateGPT is Tenable's AI-powered privilege escalation discovery tool for AWS Identity and Access Management (IAM) environments. It addresses one of the most practically significant attack surfaces in cloud infrastructure: the complex web of IAM permissions that, through non-obvious chains of policy applications and role assumptions, can enable unauthorized access escalation.

**Core Capability**

EscalateGPT analyzes AWS IAM configurations, CloudFormation templates, and Terraform state files to identify privilege escalation paths. The AI component reasons about multi-hop escalation chains: sequences of permission grants that individually appear benign but collectively enable an attacker with limited initial access to achieve administrative-level control.

**Why AI Is Necessary**

IAM privilege escalation analysis requires reasoning about combinations of permissions across services, roles, policies, and conditions. The number of possible permission combinations in a real-world AWS environment is too large for exhaustive enumeration, and many escalation paths involve service-specific behaviors (e.g., iam:PassRole combined with specific service capabilities) that require contextual knowledge. LLMs trained on AWS documentation, IAM reference material, and known escalation technique databases can reason about these combinations effectively.

**Integration**

EscalateGPT integrates with Tenable's broader cloud security posture management platform, correlating IAM findings with other misconfigurations and providing prioritized remediation recommendations in the context of the overall cloud security posture.

### PentestGPT (GreyDGL)

PentestGPT, developed by GreyDGL, is an LLM-powered penetration testing guidance system that augments human pentesters with AI reasoning assistance. Unlike fully autonomous tools, PentestGPT is designed as a collaborative tool: the human drives the assessment while the AI provides guidance, interpretation, and suggestions.

**Task Tree Architecture**

PentestGPT maintains a dynamic task tree representing the current assessment state. Each node represents a task (e.g., "enumerate subdomains", "exploit discovered SQL injection", "escalate privileges on host X"). The AI reasons about the task tree to suggest next steps, identify gaps in coverage, and prioritize effort.

**Context Management**

A key challenge in AI-assisted penetration testing is context window management: assessments generate large volumes of output that quickly exceed model context limits. PentestGPT implements structured context summarization, maintaining a compressed representation of assessment state that preserves key findings while fitting within model context limits.

**Use Cases**

PentestGPT is particularly useful for practitioners who have solid security knowledge but want AI assistance for: interpreting ambiguous tool output, suggesting exploitation approaches for unfamiliar vulnerability classes, reasoning about privilege escalation paths, and ensuring comprehensive coverage of assessment areas.

**GitHub**: github.com/GreyDGL/PentestGPT

### cve-mcp-server (mukul975)

cve-mcp-server is an MCP (Model Context Protocol) server that exposes 27 security tools to any MCP-compatible AI assistant, enabling direct integration of vulnerability intelligence and threat data into AI workflows.

**Installation**

```bash
# Install via npm
npm install -g cve-mcp-server

# Or run directly with npx
npx cve-mcp-server

# Configure in Claude Desktop or other MCP client
# Add to mcp_servers.json:
{
  "cve-mcp-server": {
    "command": "npx",
    "args": ["cve-mcp-server"]
  }
}
```

**Available Tools (27 total)**

*CVE Intelligence*: search_cve (NVD full-text search), get_cve_details (complete CVE record), get_cve_by_product (product-specific CVE listing), get_recent_cves (recent disclosures), get_cve_statistics (trend analysis)

*EPSS Scoring*: get_epss_score (exploitation probability for specific CVE), get_high_epss_cves (CVEs with high exploitation probability), compare_epss_scores (comparative analysis)

*CISA KEV*: get_kev_catalog (complete Known Exploited Vulnerabilities list), check_kev_status (check if CVE is in KEV), get_recent_kev (recent KEV additions)

*MITRE ATT&CK*: get_technique (technique details), get_tactics (tactic listing), search_techniques (technique search), get_software (malware/tool details), get_group (threat actor details)

*Shodan Integration*: shodan_search (internet-wide host search), shodan_host (specific host details), shodan_count (result counting)

*VirusTotal Integration*: vt_file_report (file hash analysis), vt_url_report (URL analysis), vt_domain_report (domain analysis), vt_ip_report (IP analysis)

*Threat Intelligence*: get_threat_actors (threat actor database), get_malware_families (malware analysis), correlate_iocs (indicator correlation)

**GitHub**: github.com/mukul975/cve-mcp-server

### Clawdstrike (backbay-labs)

Clawdstrike is a runtime security enforcement framework for autonomous AI agent fleets, developed by backbay-labs. As AI agents are increasingly deployed in security-sensitive contexts, ensuring that these agents operate within authorized boundaries becomes critical.

**Swarm Detection and Response**

Clawdstrike monitors fleets of AI agents at runtime, detecting anomalous behavior patterns that suggest an agent has been compromised, manipulated through prompt injection, or has exceeded its authorized scope. Detection capabilities include: unusual tool call sequences, attempts to access resources outside defined scope, anomalous network connections, and behavioral patterns inconsistent with the agent's assigned task.

**Enforcement Mechanisms**

When anomalous behavior is detected, Clawdstrike can: issue warnings to the operator, suspend the affected agent pending review, terminate the agent, or quarantine the agent's execution environment to prevent lateral spread. The enforcement response is configurable based on confidence level and severity.

**Integration with AI Security Workflows**

Clawdstrike is designed to wrap around AI agent frameworks (LangChain, CrewAI, AutoGPT, custom implementations) with minimal integration effort. A monitoring layer is inserted between the agent's action execution layer and the underlying tool/resource access layer, providing visibility into all agent actions without modifying agent behavior under normal conditions.

**GitHub**: github.com/backbay-labs/clawdstrike

### THOR Skill (Nextron Systems)

THOR is Nextron Systems' compromise assessment scanner, designed to detect indicators of compromise (IoCs) and anomalous patterns on endpoints. THOR Skill extends this capability with LLM-powered analysis.

**LLM Skills Integration**

THOR Skill adds an LLM reasoning layer to THOR's detection engine. When THOR detects suspicious patterns, THOR Skill queries an LLM to: interpret the finding in context, assess whether it represents actual compromise or a false positive, identify related indicators that should be checked, and generate a narrative explanation of the finding for security analysts.

**APT Detection Enhancement**

Advanced Persistent Threat detection is particularly challenging because APTs intentionally use legitimate tools and behaviors to blend into normal activity. THOR Skill's LLM layer can reason about behavioral patterns that individually appear legitimate but collectively suggest malicious activity — a capability that aligns well with the pattern-matching strengths of large language models.

### AI-Powered SIEM and Detection Tools

**Microsoft Security Copilot**

Security Copilot integrates GPT-4 directly into Microsoft's security product ecosystem (Microsoft Sentinel, Defender XDR, Intune, Purview). It provides: natural language query of security data, automated incident investigation, threat intelligence correlation, and guided response playbooks. Security analysts can describe a threat scenario in plain language and receive structured queries, relevant data, and recommended response actions.

**CrowdStrike Charlotte AI**

Charlotte AI is CrowdStrike's generative AI assistant integrated throughout the Falcon platform. Capabilities include: natural language threat hunting (query security data in plain English), automated alert triage (AI-generated severity assessments and context), guided incident response (step-by-step remediation assistance), and proactive threat intelligence synthesis (summaries of relevant threat actor activity).

**Splunk AI**

Splunk's AI capabilities, including Splunk AI Assistant and integrated ML models, provide: anomaly detection in security telemetry, natural language search (SPL query generation from plain language), automated alert prioritization, and predictive threat modeling. Splunk's approach emphasizes augmenting analyst capabilities rather than replacing analyst judgment.

**Darktrace**

Darktrace's Enterprise Immune System uses unsupervised machine learning to model normal behavior for every device, user, and network component, then detects deviations from that model. Darktrace Cyber AI Analyst autonomously investigates alerts, correlating related events across the environment and producing human-readable incident reports. The system can autonomously respond to threats (Darktrace Antigena) while preserving normal business operations.

**Vectra AI**

Vectra's Attack Signal Intelligence platform uses AI to detect attacker behaviors across hybrid cloud, network, identity, and SaaS environments. The system focuses on post-compromise attacker behaviors (lateral movement, privilege escalation, data staging) rather than signature-based malware detection, making it effective against sophisticated threats that evade traditional security tools.

## Section 5: Automated CVE Exploitation — Threat Landscape

### The UIUC 2024 Study: Definitive Benchmark

The April 2024 study by Richard Fang, Rohan Bindu, Akul Gupta, Qiusi Zhan, and Daniel Kang at the University of Illinois Urbana-Champaign (paper title: "LLM Agents Can Autonomously Exploit One-Day Vulnerabilities") established the definitive benchmark for AI-powered CVE exploitation capability.

**Methodology**

The researchers assembled a dataset of 15 real-world 1-day CVEs selected to represent a range of vulnerability classes and complexity levels. The term "1-day" refers to vulnerabilities where a patch has been published (the vulnerability is known) but deployment of the patch is not yet universal. This represents the most practically significant window: the period when attackers can exploit publicly-known vulnerabilities against organizations that have not yet patched.

Each CVE was presented to the AI agent with:
- The CVE identifier
- A brief vulnerability description from the NVD database
- Access to a tool-augmented agent framework with a shell environment
- No additional hints, writeups, or exploitation guides

The agent was tasked with developing a working exploit and demonstrating successful exploitation against a vulnerable instance.

**Results**

GPT-4 achieved 87% success (13/15 CVEs), exploiting vulnerabilities in categories including:
- Web application injection (SQL injection, command injection, SSTI)
- Authentication bypass
- Path traversal and arbitrary file read
- Privilege escalation
- Remote code execution

GPT-3.5 achieved 0% success on the same benchmark, demonstrating the categorical capability gap between model generations.

**Tested CVE Categories**

The benchmark included CVEs affecting popular web frameworks, content management systems, API endpoints, and service-level software. Specific vulnerability types represented included: SQL injection via unsanitized parameters, server-side template injection in Python/Jinja2 contexts, path traversal via URL manipulation, authentication bypass through JWT forgery, and command injection through unvalidated shell metacharacters.

**Implications for Defenders**

The 87% success rate at GPT-4 quality means that any organization running software with known unpatched CVEs faces a near-certain probability of exploitation if a motivated attacker deploys AI-assisted exploit development. The traditional assumption — that the window between CVE publication and widespread exploitation provides time for patching — no longer holds at the frontier of AI capability.

### InterCode-CTF Benchmark

InterCode-CTF is a benchmark for evaluating AI performance on Capture-the-Flag challenges, covering categories including:
- **Cryptography**: Classical ciphers, RSA attacks, hash length extension
- **Reverse Engineering**: Binary analysis, obfuscated code, license key bypasses
- **Pwn**: Buffer overflows, format strings, heap exploitation
- **Web**: SQL injection, XSS, SSRF, deserialization
- **Forensics**: Steganography, network capture analysis, file carving

Performance on InterCode-CTF has tracked closely with model capability. GPT-4 class models solve approximately 40-60% of beginner/intermediate challenges autonomously; frontier models in 2025-2026 have shown improvements toward 70-80% on the same benchmark, with the primary remaining barrier being multi-step binary exploitation challenges requiring deep memory safety understanding.

### NYU CyberSecEval

CyberSecEval, developed by NYU's security research group in collaboration with Meta, is a comprehensive evaluation framework for measuring both the offensive capability and responsible behavior of AI models in security contexts. It evaluates:

- **Insecure code generation**: Does the model generate code with known vulnerability patterns?
- **Vulnerability exploitation**: Can the model develop working exploits given vulnerability descriptions?
- **Prompt injection resistance**: Is the model susceptible to adversarial prompts attempting to redirect its behavior?
- **Harmful information threshold**: Does the model refuse requests for clearly harmful security content?

### Current Capability Levels

**What AI Can Reliably Do (as of 2026)**

| Capability | Success Rate | Notes |
|------------|--------------|-------|
| Exploit 1-day CVEs from description | 85-90% | GPT-4 class models |
| Write SQL injection exploits | >95% | Well-understood technique |
| Develop buffer overflow exploits (no mitigations) | 80-90% | Requires stack layout knowledge |
| SSRF exploitation and pivot | 85% | Service-dependent |
| Vulnerability chain development (2-3 steps) | 60-75% | Decreases with chain length |
| Generate targeted phishing content | >95% | Minimal technical barriers |
| Interpret scan output and suggest next steps | >95% | Core AI strength |
| Generate obfuscated shellcode | 80-85% | Technique-dependent |

**What AI Cannot Reliably Do (as of 2026)**

| Capability | Notes |
|------------|-------|
| True 0-day discovery without guidance | Requires novel vulnerability research; AI assists but humans lead |
| Bypass modern CFI + KASLR stacks | Complex mitigation stacks require deep exploitation expertise |
| Sustain week-long campaigns without human oversight | Context management and goal coherence degrade over time |
| Social engineering with full persona maintenance | Inconsistencies emerge in extended interactions |
| Binary exploitation with all mitigations (PIE+ASLR+canary+CFI) | Each mitigation layer significantly reduces success rate |

### N-Day Exploitation Pipeline Timeline

The following diagram represents the stages of AI-automated N-day exploitation and the time compression achieved compared to traditional manual exploitation:

```
CVE Published
     │
     ▼ (minutes, AI-automated)
Patch Diff Analysis
  - Retrieve patch commit from vendor repository
  - Identify changed files and functions
  - Analyze semantic meaning of changes
     │
     ▼ (minutes, AI-automated)
Vulnerable Condition Reconstruction
  - Reverse-engineer pre-patch code from diff
  - Identify exact triggering condition
  - Assess exploitability
     │
     ▼ (hours, AI-automated with human oversight)
Proof-of-Concept Development
  - Select exploitation technique based on vulnerability class
  - Generate initial payload
  - Test and iterate
     │
     ▼ (minutes, AI-automated)
Container Test Environment Build
  - Identify vulnerable version
  - Pull or build Docker image
  - Configure test environment
     │
     ▼ (minutes, AI-automated)
Exploit Validation
  - Confirm successful exploitation against vulnerable version
  - Confirm failure against patched version
  - Document exploitation conditions

Total AI-Assisted Time: 2-8 hours (vs. 2-14 days for manual expert)
```

This timeline compression means that the "patch window" — the period between CVE publication and widespread exploitation — has effectively closed for well-resourced attackers using AI assistance. Organizations must now assume that any publicly disclosed vulnerability will have working exploits available within hours, not days or weeks.

### Benchmark Evolution and Trend Analysis

The capability trajectory suggests continued improvement in AI offensive capabilities:

- **2023**: AI solves ~30% of beginner CTF challenges, fails at most real CVEs
- **2024**: AI solves 87% of tested 1-day CVEs (UIUC), ~50% of intermediate CTF
- **2025**: Commercial tools achieve >90% on 1-day CVEs, 0-day assistance improves
- **2026**: Sustained multi-stage campaigns become reliable with human oversight

The rate of improvement has been roughly consistent with overall LLM capability improvements, suggesting that offensive security performance tracks general reasoning capability. As models improve, offensive capability improves proportionally.

## Section 6: Defending Against AI Attackers

### The Defensive Imperative

If AI tools compress the exploitation timeline from days to hours, and enable simultaneous assessment of thousands of assets, then defensive strategies built around the assumption of adequate patch windows must be revised. The following framework addresses defense against AI-powered attackers specifically.

### Patch Velocity SLA Framework

The fundamental response to reduced exploitation timelines is reduced patch timelines. The following SLA framework is calibrated to AI-powered attacker capabilities:

| Vulnerability Category | Patch SLA | Rationale |
|----------------------|-----------|-----------|
| CRITICAL (CVSS 9.0+) + CISA KEV | 24 hours | AI can exploit within hours of publication; active exploitation confirmed |
| HIGH (CVSS 7.0-8.9) + EPSS ≥ 0.5 | 72 hours | High exploitation probability; AI tools make rapid exploitation likely |
| HIGH (CVSS 7.0-8.9) + no public PoC | 7 days | Lower immediate risk; monitor for PoC publication |
| MEDIUM (CVSS 4.0-6.9) | 30 days | Standard patching cadence |
| LOW (CVSS < 4.0) | 90 days | Risk-based deferral acceptable |
| CRITICAL + publicly weaponized PoC | Immediate (emergency change) | Zero tolerance for known-exploitable critical vulns |

### EPSS Integration for Patch Prioritization

EPSS (Exploit Prediction Scoring System) provides machine learning-based predictions of exploitation probability within 30 days. Integrating EPSS scores into patch prioritization workflows enables risk-based prioritization that accounts for actual exploitation likelihood rather than theoretical severity.

**EPSS API Query**

```python
import requests

def get_epss_score(cve_id):
    """Query EPSS API for exploitation probability score."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data.get('data'):
            epss_data = data['data'][0]
            return {
                'cve': epss_data['cve'],
                'epss': float(epss_data['epss']),
                'percentile': float(epss_data['percentile']),
                'date': epss_data['date']
            }
    return None

def get_high_epss_cves(threshold=0.5, limit=100):
    """Retrieve CVEs with EPSS score above threshold."""
    url = f"https://api.first.org/data/v1/epss?epss-gt={threshold}&limit={limit}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get('data', [])
    return []

# Example: Check if a specific CVE warrants emergency patching
cve = "CVE-2024-1234"
score = get_epss_score(cve)
if score and score['epss'] >= 0.5:
    print(f"HIGH PRIORITY: {cve} has {score['epss']:.1%} exploitation probability")
    print(f"Percentile: {score['percentile']:.1%} of all CVEs")
```

### CISA KEV Integration

```bash
# Query CISA KEV catalog for recent additions
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json   | jq '.vulnerabilities | sort_by(.dateAdded) | reverse | .[0:10] | .[] | {cveID, vendorProject, product, vulnerabilityName, dateAdded, requiredAction}'

# Check if specific CVE is in KEV
CVE="CVE-2024-1234"
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json   | jq --arg cve "$CVE" '.vulnerabilities[] | select(.cveID == $cve)'

# Get all KEV entries for a specific vendor
VENDOR="Microsoft"
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json   | jq --arg vendor "$VENDOR" '.vulnerabilities[] | select(.vendorProject == $vendor) | {cveID, product, dateAdded}'
```

### Attack Surface Reduction

**Software Bill of Materials (SBOM)**

Maintaining current SBOMs for all deployed software enables rapid identification of affected assets when new CVEs are published. When a CVE is disclosed for a specific library version, SBOM data enables immediate enumeration of all systems running that version, enabling prioritized patching rather than manual inventory.

```bash
# Generate SBOM with syft
syft packages dir:. -o spdx-json=sbom.spdx.json
syft packages image:myapp:latest -o cyclonedx-json=sbom.cdx.json

# Query SBOM for vulnerable packages (using grype)
grype sbom:./sbom.spdx.json --fail-on critical
```

**Automated Dependency Updates (Dependabot)**

GitHub Dependabot and similar tools (Renovate, Snyk) automate pull request generation for dependency updates. In the context of AI-powered attackers, these tools should be configured with aggressive update schedules and automatic merge policies for security updates on non-breaking dependency changes.

**Runtime Application Self-Protection (RASP)**

RASP instruments applications at runtime to detect and block exploitation attempts. Unlike perimeter-based defenses, RASP operates within the application context, enabling detection of attacks that bypass network-level controls. RASP solutions include: Contrast Security, Imperva, Sqreen (acquired by Datadog), and open-source alternatives like OpenRASP.

### Detection Patterns for AI-Driven Attacks

AI-driven attacks exhibit characteristic behavioral patterns that differ from both human attackers and simple automated scanners:

**Systematic Timing**
AI agents execute tool calls at consistent, rapid intervals without the irregular timing characteristic of human attackers. The inter-request timing is more regular than human attackers (who pause to think) but less random than simple automated scanners.

**Tool User-Agent Signatures**
Many security tools used by AI agents (nmap, sqlmap, nuclei, nikto, gobuster) include distinctive User-Agent strings or behavioral signatures. Monitoring for these signatures indicates automated security tool usage that may be unauthorized.

**Rapid Scan→Exploit Sequence**
AI-driven attacks compress the time between reconnaissance and exploitation. Traditional attack patterns show reconnaissance activity well in advance of exploitation attempts; AI-driven patterns show exploitation attempts within minutes of completing reconnaissance.

**KQL Detection Rules (Microsoft Sentinel)**

```kusto
// Detect automated security tool user agents
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625 or EventID == 4624
| extend UserAgent = tostring(EventData.UserAgent)
| where UserAgent has_any ("Nmap", "sqlmap", "Nuclei", "nikto", "dirb", "gobuster", "masscan")
| summarize count() by bin(TimeGenerated, 5m), SourceIP = tostring(EventData.IpAddress), UserAgent
| where count_ > 10
| project TimeGenerated, SourceIP, UserAgent, RequestCount=count_

// Detect rapid scan-to-exploit sequences
let scan_activity = SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4625
| summarize ScanStart=min(TimeGenerated), ScanCount=count() by SourceIP=tostring(EventData.IpAddress)
| where ScanCount > 50;
let exploit_activity = SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4688
| where Process has_any ("cmd.exe", "powershell.exe", "bash", "sh")
| project ExploitTime=TimeGenerated, SourceIP=tostring(EventData.IpAddress);
scan_activity
| join kind=inner exploit_activity on SourceIP
| where ExploitTime > ScanStart
| where datetime_diff('minute', ExploitTime, ScanStart) < 30
| project SourceIP, ScanStart, ExploitTime, MinutesFromScanToExploit=datetime_diff('minute', ExploitTime, ScanStart)
```

**SPL Detection Rules (Splunk)**

```splunk
# Detect nuclei/sqlmap/dirb tool signatures in web logs
index=web_logs
| rex field=cs_useragent "(?<tool>nuclei|sqlmap|dirb|gobuster|nikto|masscan)"
| where isnotnull(tool)
| stats count by src_ip, tool, _time span=5m
| where count > 20
| eval alert_severity=case(count > 100, "CRITICAL", count > 50, "HIGH", count > 20, "MEDIUM", true(), "LOW")
| table _time, src_ip, tool, count, alert_severity

# Detect rapid vulnerability scan to exploitation pattern
index=web_logs OR index=endpoint
| eval event_type=case(
    match(cs_useragent, "(?i)(nuclei|sqlmap|nmap|masscan|gobuster|nikto)"), "scan",
    match(cs_uri_query, "(?i)(union|select|exec|cmd=|;ls|;id|../|\.\./)"), "exploit_attempt",
    true(), "normal"
)
| where event_type!="normal"
| stats min(_time) as first_seen, max(_time) as last_seen, values(event_type) as event_types, count by src_ip
| where array_length(event_types) > 1
| eval time_window_minutes=round((last_seen - first_seen) / 60, 1)
| where time_window_minutes < 30
| sort by time_window_minutes asc
```

### AI Red Team Your Own Assets

The most effective defense against AI-powered attackers is to deploy AI red team tools against your own assets before attackers do. This requires:

**Authorization Framework**
- Written scope definition specifying all authorized targets, excluded systems, and permitted actions
- Legal review of engagement contract language for AI-specific considerations
- Incident response notification to prevent defensive teams from responding to authorized testing
- Data handling procedures for findings containing sensitive system information

**Clearwing Authorized Deployment**
```bash
# Create scope-limited configuration
cat > engagement.yaml << 'EOF'
campaign:
  name: "Authorized Internal Assessment"
  scope:
    include:
      - 192.168.1.0/24
      - "*.internal.example.com"
    exclude:
      - 192.168.1.1  # Production gateway - excluded
      - "prod-db-*.internal.example.com"  # Databases excluded
  human_approval_required: true
  max_scan_rate: 100  # requests per second
  auto_exploit: false  # Require human approval for all exploits
EOF

clearwing run --config engagement.yaml --mode network_pentest
```

**VECTR Tracking**
VECTR (vectr.io) provides a platform for tracking purple team and red team exercises, correlating attacker actions (from AI red team tools) with defensive detections. This enables measurement of detection coverage and identification of gaps.

### Zero Trust as AI Defense Layer

Zero trust architecture provides structural defense against AI-powered attackers by eliminating the assumption of trust based on network location.

**Key Zero Trust Principles Against AI Attackers**

- **Verify explicitly**: AI attackers can move laterally using legitimate credentials. Continuous verification (MFA, conditional access, device health) raises the bar beyond what AI tools can easily automate.
- **Least privilege access**: Constrain the blast radius of any single compromised account. AI privilege escalation tools are highly effective when starting permissions are broad; they are more constrained when initial access is minimal.
- **Assume breach**: Design for detection and response, not just prevention. AI attackers are systematic; systematic defenders who monitor behavior can detect AI attack patterns.
- **Microsegmentation**: Network microsegmentation prevents AI agents from freely enumerating the internal network after initial access.

## Section 7: MITRE ATT&CK Mapping for AI-Amplified Techniques

### Overview

MITRE ATT&CK provides a standardized taxonomy for describing adversary techniques. The following table maps key ATT&CK techniques to their AI amplification characteristics and corresponding defenses. AI amplification refers to how AI tools specifically enhance attacker capability for each technique.

### Technique Mapping Table

| ATT&CK ID | Technique Name | AI Amplification | Recommended Defense |
|-----------|----------------|------------------|---------------------|
| T1595 | Active Scanning | AI enables systematic, comprehensive enumeration of all attack surfaces simultaneously; AI interprets scan results contextually to identify high-value targets | Rate limiting on edge devices; honeypots to detect systematic enumeration; behavioral anomaly detection for scanning patterns |
| T1592 | Gather Victim Host Info | AI synthesizes OSINT from multiple sources (Shodan, Censys, DNS records, certificate transparency, GitHub) into structured target intelligence automatically | Minimize public exposure of infrastructure details; certificate transparency monitoring; GitHub secrets scanning |
| T1190 | Exploit Public-Facing Application | AI develops working exploits for known CVEs within hours of patch publication; can chain multiple vulnerabilities automatically | Aggressive patch velocity (see SLA table); virtual patching via WAF for zero-day period; EPSS-based prioritization |
| T1203 | Exploitation for Client Execution | AI generates polymorphic payloads that evade signature-based detection; tailors social engineering lures using organizational context | Email security gateway with behavioral analysis; user awareness training; application sandboxing |
| T1068 | Exploitation for Privilege Escalation | AI identifies local privilege escalation chains by analyzing system configuration, installed software versions, and service permissions; EscalateGPT-style tools automate cloud IAM escalation | Aggressive endpoint patching; least privilege enforcement; EDR with privilege escalation detection; cloud IAM regular review |
| T1055 | Process Injection | AI selects optimal injection technique based on target process characteristics, loaded modules, and active security products; generates technique-specific shellcode | Kernel-level protection (Windows Defender Credential Guard, LSA protection); EDR behavioral detection; application allowlisting |
| T1021 | Remote Services | AI chains multiple credential sources to authenticate to remote services; uses credential stuffing with contextually likely passwords; automates lateral movement path planning | MFA on all remote services; Privileged Access Management (PAM); network microsegmentation; anomalous authentication detection |
| T1505 | Server Software Component | AI identifies web shell upload opportunities by analyzing web application code and configuration; generates evasive web shells adapted to the specific server environment | File integrity monitoring on web directories; outbound connection monitoring for web processes; regular web application review |
| T1059 | Command and Scripting Interpreter | AI generates obfuscated scripts (PowerShell, Bash, Python) that achieve attacker objectives while evading signature-based detection; adapts obfuscation based on detected security products | AMSI (Antimalware Scan Interface) for script inspection; PowerShell constrained language mode; script block logging; behavioral detection |
| T1486 | Data Encrypted for Impact | AI can automate ransomware deployment across large environments by combining reconnaissance, lateral movement, and payload deployment; tailors encryption scope to maximize impact | Immutable backups (3-2-1 rule with offline copy); network segmentation to limit lateral movement; behavioral detection of mass encryption |

### Extended Technique Analysis

**T1595 — Active Scanning: AI Amplification Deep Dive**

Traditional automated scanners execute predefined scan sequences against targets. AI-powered scanners reason about scan results in context: when a port is found open, the AI considers what services are likely running, what vulnerabilities affect those services, and how to probe further. This contextual reasoning transforms scanning from a data collection exercise into an intelligence-gathering process.

AI scanners also adapt their scan intensity and technique based on observed defensive responses. If aggressive scanning triggers rate limiting or IP blocking, the AI can switch to slower, more evasive techniques. If a target appears unmonitored, the AI can increase scan speed to reduce total assessment time.

**T1190 — Exploit Public-Facing Application: The Critical Technique**

This is the technique most directly amplified by the UIUC 2024 findings. Web applications are the most common attack surface in modern enterprise environments, and AI tools can develop working exploits for web application CVEs faster than organizations can deploy patches. The convergence of AI-powered exploitation and continuously expanding web application attack surface makes T1190 the highest-priority technique for defensive investment.

Key mitigations beyond patching:
- Web Application Firewall (WAF) with virtual patching capability
- RASP (Runtime Application Self-Protection) for deep behavioral detection
- Regular authenticated vulnerability scanning to identify unpatched instances before attackers do
- API gateway with rate limiting and anomaly detection

**T1068 — Privilege Escalation: Cloud Dimension**

In cloud environments, privilege escalation often involves IAM permissions rather than operating system vulnerabilities. AI tools like EscalateGPT are specifically designed to identify IAM privilege escalation paths that human analysts might miss due to the complexity of permission interactions.

Defense requires:
- Regular IAM permission audits using AI-powered analysis tools
- Privileged access management for cloud console access
- JIT (Just-In-Time) access provisioning to eliminate standing privileges
- Cloud Security Posture Management (CSPM) with continuous privilege analysis

**T1059 — Command and Scripting: AI-Generated Obfuscation**

AI models have extensive knowledge of script obfuscation techniques and can generate novel obfuscation variations that evade signature-based detection. This makes behavioral detection (looking for what the script does rather than how it looks) essential.

PowerShell logging must be comprehensive: module logging, script block logging, and transcription all capture different aspects of script execution. The combination provides high-confidence behavioral detection even against heavily obfuscated scripts.

### ATT&CK Navigator Recommendations

For organizations tracking AI-amplified techniques, the following ATT&CK techniques warrant elevated monitoring and defensive investment beyond their standard risk ratings:

**Tier 1 (Highest AI Amplification)**
- T1190 (Exploit Public-Facing Application)
- T1595 (Active Scanning)
- T1068 (Privilege Escalation)
- T1059 (Command and Scripting)

**Tier 2 (Significant AI Amplification)**
- T1021 (Remote Services)
- T1055 (Process Injection)
- T1592 (Gather Victim Host Info)
- T1203 (Client Execution)

**Tier 3 (Moderate AI Amplification)**
- T1505 (Server Software Component)
- T1486 (Data Encrypted for Impact)
- T1078 (Valid Accounts — AI enhances credential stuffing)
- T1110 (Brute Force — AI generates context-aware wordlists)

## Section 8: Responsible Use Framework and Complete Tools Reference

### Legal Framework

The use of offensive security tools — AI-powered or otherwise — is strictly regulated by law. Unauthorized computer access is a criminal offense in virtually all jurisdictions. The following framework establishes the legal and ethical requirements for responsible deployment of AI offensive security tools.

**Computer Fraud and Abuse Act (CFAA) — United States**

The CFAA prohibits unauthorized access to protected computer systems. "Authorization" is defined broadly and includes both explicit permission and implied permission within a defined scope. For AI penetration testing tools, authorization requirements are heightened because:

- AI tools can act autonomously in ways that exceed intended scope
- AI tools can generate large volumes of activity that may affect non-target systems
- The speed and scale of AI tools magnifies the impact of scope violations

**Explicit Written Authorization Requirements**

Every AI-powered security assessment must be preceded by written authorization that specifies:

1. **Authorized targets**: Explicit listing of all systems, IP ranges, domains, and applications that may be tested. The authorization should specify both what is included and what is excluded.

2. **Authorized techniques**: Categories of permitted actions (reconnaissance, vulnerability scanning, exploitation, post-exploitation) and explicit exclusions (denial of service, data exfiltration, production system modification).

3. **Testing window**: Authorized time period for testing activities, enabling defensive teams to correlate alerts with authorized testing.

4. **Emergency contacts**: Contact information for both parties to enable immediate suspension of testing if issues arise.

5. **Data handling**: Procedures for handling sensitive data discovered during testing (credentials, PII, confidential business information).

**Scope Definition to Prevent AI Escape**

AI tools, unlike manual techniques, can autonomously follow attack paths beyond intended scope. Engagement documentation must include:

```
SCOPE BOUNDARIES FOR AI TOOL DEPLOYMENT

In-scope IP ranges:
- 10.0.1.0/24 (internal web servers)
- 10.0.2.0/24 (application servers)

In-scope domains:
- *.test.example.com
- *.staging.example.com

EXPLICITLY OUT OF SCOPE:
- 10.0.3.0/24 (production database segment)
- *.prod.example.com
- Any third-party services or cloud provider infrastructure
- Any system not explicitly listed above

AI TOOL CONTAINMENT REQUIREMENTS:
- All AI tool execution must occur within isolated network segment
- AI tool must not have direct internet access (queries via proxy only)
- All exploitation actions require human approval before execution
- Kill-switch mechanism must be tested before assessment begins
```

**Engagement Contract Language**

For commercial engagements, contracts should include AI-specific provisions:

```
AI-POWERED TOOL DISCLOSURE AND LIMITATION

Consultant acknowledges that AI-powered penetration testing tools
will be used in this engagement. Consultant warrants that:

(a) All AI tool execution will occur within the explicitly authorized
    scope boundaries defined in Exhibit A;
(b) AI tools will be configured with human-approval requirements for
    all exploitation-class actions;
(c) AI tools will be network-isolated to prevent unauthorized access
    to systems outside the defined scope;
(d) Complete logs of all AI tool actions will be retained for
    [90 days] following engagement completion;
(e) Any AI-discovered findings will be handled in accordance with
    the responsible disclosure provisions in Section [X].
```

### Containment Mechanisms for AI Security Tools

**Network Isolation**

AI security tools must operate within network segments that prevent direct access to out-of-scope systems. Implementation options:

- Dedicated VLAN for security testing with explicit firewall rules
- Cloud-based isolation (separate VPC/subscription with specific peering)
- Air-gapped environment for highest-sensitivity assessments

**Tool Allowlisting**

Rather than relying on the AI to respect scope boundaries for tool selection, configure the execution environment to only permit authorized tools:

```bash
# Create restricted execution profile
cat > /etc/security/ai_pentest_profile.conf << 'EOF'
# Allowed tools for AI execution
ALLOWED_TOOLS="nmap,nikto,gobuster,nuclei,sqlmap"
PROHIBITED_TOOLS="msfconsole,meterpreter,mimikatz,bloodhound"

# Rate limiting
MAX_REQUESTS_PER_SECOND=100
MAX_CONCURRENT_CONNECTIONS=50

# Network restrictions (enforced at firewall)
ALLOWED_TARGETS="10.0.1.0/24,10.0.2.0/24"
BLOCKED_DESTINATIONS="10.0.3.0/24,0.0.0.0/0"
EOF
```

**Rate Limiting**

AI tools can generate request volumes that impact system availability. Rate limiting at multiple layers:
- Tool-level rate limiting (configurable in Clearwing and most AI security tools)
- Network-level rate limiting via QoS or firewall policies
- Application-level rate limiting in WAF/API gateway

**Kill-Switch Mechanisms**

Every AI security tool deployment must have a tested kill-switch: a mechanism to immediately terminate all AI activity. Options:
- Process termination scripts (tested before each engagement)
- Network-level blocking via firewall rule addition
- API key revocation (disables cloud-based AI model access)

### Responsible Disclosure Pipeline

**Standard 90-Day Timeline**

1. **Day 0**: Vulnerability discovered, SHA-3 commitment generated
2. **Day 1**: Vendor security contact identified and notified (initial notification with vulnerability summary, no full details)
3. **Day 7**: Full technical details provided to vendor (if secure communication channel established)
4. **Day 30**: Vendor acknowledgment expected
5. **Day 45**: Patch timeline requested from vendor
6. **Day 75**: Final reminder if no patch available
7. **Day 90**: Public disclosure regardless of patch status (with 7-day advance notice to vendor)

**Exceptions to 90-Day Timeline**
- Active exploitation in the wild: Accelerated timeline (30 days or coordinated with CISA)
- Critical infrastructure (power, water, healthcare): Extended timeline (120 days) with CISA coordination
- Patch available: Disclose 30 days after patch availability to allow deployment time

### Complete AI Offensive Security Tools Reference

| Tool | URL | License | Key Capabilities |
|------|-----|---------|-----------------|
| Clearwing | github.com/Lazarus-AI/clearwing | Open Source | Network pentest agent, source code hunter, N-day exploit pipeline, reverse engineering, 63 bound tools, multi-provider AI support |
| EscalateGPT | tenable.com/products/escalategpt | Commercial | AWS IAM privilege escalation discovery, cloud attack path analysis, Tenable platform integration |
| PentestGPT | github.com/GreyDGL/PentestGPT | Open Source | LLM-guided penetration testing, task tree management, context-aware guidance, collaborative human+AI workflow |
| cve-mcp-server | github.com/mukul975/cve-mcp-server | Open Source | 27 security tools via MCP: CVE/EPSS/KEV/MITRE ATT&CK/Shodan/VirusTotal, MCP-compatible AI assistant integration |
| Clawdstrike | github.com/backbay-labs/clawdstrike | Open Source | Runtime security enforcement for AI agent fleets, Swarm Detection & Response, behavioral anomaly detection |
| THOR Skill | nextron-systems.com/thor | Commercial | LLM skills for THOR APT scanner, AI-powered IoC interpretation, compromise assessment augmentation |
| Microsoft Security Copilot | microsoft.com/en-us/security/business/ai-machine-learning/microsoft-copilot-security | Commercial | GPT-4 powered security assistant, Sentinel/Defender XDR integration, natural language security queries, incident investigation |
| CrowdStrike Charlotte AI | crowdstrike.com/platform/charlotte-ai | Commercial | Generative AI for threat hunting, alert triage, incident response, threat intelligence synthesis, Falcon platform integration |
| Splunk AI | splunk.com/en_us/products/artificial-intelligence.html | Commercial | AI-powered anomaly detection, natural language SPL generation, automated alert prioritization, predictive threat modeling |
| Darktrace | darktrace.com | Commercial | Unsupervised ML for behavioral baselining, Cyber AI Analyst for autonomous investigation, Antigena for autonomous response |
| Vectra AI | vectra.ai | Commercial | Attack Signal Intelligence, hybrid cloud/network/identity/SaaS detection, post-compromise behavioral detection, AI-driven triage |

### Getting Started: Safe AI Security Assessment

**For Security Practitioners**

1. Review and obtain explicit written authorization for all target systems
2. Set up isolated assessment environment (dedicated VM or network segment)
3. Install Clearwing following the installation instructions in Section 3
4. Configure human-approval mode (required for all exploitation actions)
5. Define scope boundaries in YAML configuration
6. Conduct initial reconnaissance-only run to validate scope and tool function
7. Review reconnaissance results with stakeholders before proceeding to exploitation phases
8. Document all findings and generate formal report
9. Follow responsible disclosure procedures for any critical findings

**For Defenders**

1. Deploy cve-mcp-server to integrate vulnerability intelligence into your AI assistant workflows
2. Implement EPSS-based patch prioritization using the API code in Section 6
3. Configure CISA KEV monitoring and alerting
4. Deploy KQL/SPL detection rules from Section 6 to detect AI-driven attack patterns
5. Consider authorized Clearwing deployment for regular self-assessment
6. Integrate SBOM into vulnerability management workflows
7. Review and update zero trust policies with AI threat scenarios in mind

**For Security Managers**

1. Update incident response playbooks to address AI-powered attack scenarios
2. Revise patch SLAs to reflect compressed exploitation timelines
3. Evaluate commercial AI security tools (Charlotte AI, Security Copilot) for SOC augmentation
4. Establish authorized AI red team program with VECTR tracking
5. Ensure AI tool usage policies cover both defensive and offensive applications
6. Review engagement contract language for AI-specific provisions

---

*This document is maintained as a living reference. Content reflects the state of AI offensive security as of early 2026. The field evolves rapidly; practitioners should supplement this reference with current vendor documentation, academic publications, and community resources.*

*All tools and techniques described are for authorized security testing only. Unauthorized use of offensive security tools is illegal and unethical.*
