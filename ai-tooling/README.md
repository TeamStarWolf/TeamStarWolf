# AI Tooling

> In one minute: The library's practical guide to AI tools and large language models (LLMs). It has a grouped index of 46 tools and model platforms, a one-page manual for each, a nine-module learning path, and six hands-on labs that run on your own machine. The library's AI security references cover how AI systems are attacked and defended; this section covers the tools themselves, and every manual links back to those security pages.

| | |
|---|---|
| Read this when | you are learning how LLMs and AI agents work, choosing or reviewing an AI tool, setting up a local lab, or need a tool's official docs, repository and security notes in one place |
| Start at | the AI Tools and LLMs Index to find a tool, or Module 1 of the learning path if you are new to LLMs |
| Pairs with | [AI & LLM Security discipline](/disciplines/ai-llm-security.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md) |

## What is here

| Page | What it gives you |
|---|---|
| [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md) | 46 tools in 12 categories, from model platforms and local inference to agent frameworks, coding agents, evaluation, guardrails and AI red teaming, each with its license, official docs, repository and manual |
| [AI Tool Manuals](/ai-tooling/tools/README.md) | One page per tool, A to Z: what it is for, quick start, key concepts, security notes with verified CVEs and incidents, and where to learn more |
| [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md) | Nine modules from how LLMs work through prompting, RAG, agents and MCP, fine-tuning, evaluation, local models, security and governance, each with free, reputable resources |
| [AI Labs](/ai-tooling/AI_LABS.md) | Six local, defensive labs: run a model with Ollama, build a small RAG, write an MCP server, evaluate prompts, scan your own model, and add a guardrail |

## How these pages are checked

1. **Official sources first.** Commands, licenses, versions and links come from each tool's official documentation, repository or release page. Each manual records what was checked and when in its "Checked" row.
2. **Security notes cite their source.** Vulnerabilities link to NVD, the CISA Known Exploited Vulnerabilities catalog or the vendor's own advisory.
3. **Facts that could not be confirmed were left out**, not guessed.
4. **The labs were checked against current documentation** on 8 October 2026 but were not run end to end before publication. If a step fails, the tool's own docs win.
5. **Listing is not endorsement.** Read each project's license and terms before use.

AI tooling changes monthly: projects are renamed, archived and acquired. Confirm the current release before you rely on a detail.

## Related library references

- [AI Security Reference](/AI_SECURITY_REFERENCE.md): OWASP LLM Top 10, prompt injection, guardrails
- [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md): MCP threat model and hardening
- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md): AI-powered offensive tooling
- [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md): model supply chain and serving
- [MITRE ATLAS Reference](/ATLAS_REFERENCE.md) and [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md)
- [Deepfake & Synthetic-Media Defense](/DEEPFAKE_DEFENSE_REFERENCE.md)
