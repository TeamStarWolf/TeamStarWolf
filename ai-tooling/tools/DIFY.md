# Dify

> In one minute: Dify is a platform for building AI applications, such as chatbots, agents, and multi-step workflows, in a visual studio, then publishing them as web apps, APIs, or MCP servers. Teams use it as a hosted service (Dify Cloud) or self-host it with Docker Compose. A Dify deployment stores model provider keys and knowledge-base data for many users, so tenant isolation, secrets, and default settings need attention.

| | |
|---|---|
| Category | Workflow builder |
| Maintainer | LangGenius (langgenius on GitHub) |
| License / access | Source available under the Dify Open Source License (Apache 2.0 with added conditions: no multi-tenant service without written permission, and keep the console logo and copyright). Self-hosted Community edition; Dify Cloud has a free Sandbox plan |
| Official docs | [docs.dify.ai](https://docs.dify.ai/) |
| Repository | [langgenius/dify](https://github.com/langgenius/dify) |
| Checked | 8 Oct 2026, v1.17.1 (latest GitHub release) |

## What it is for

- Building chatbots and agents that reason, decide, and call tools.
- Designing multi-step workflows on a canvas with model, logic, code, and data nodes.
- Retrieval-augmented generation (RAG) over uploaded documents with knowledge bases.
- Publishing an app as a web app, an embeddable widget, an API, or an MCP server.
- Self-hosting an internal AI app platform for a team.

## Quick start

1. Check prerequisites: at least 2 CPU cores and 4 GiB RAM, Docker, and Docker Compose 2.24.0 or later. On macOS, give the Docker VM at least 2 vCPUs and 8 GiB of memory. On Windows, use WSL 2 and keep the source code in the Linux file system.
2. Clone the latest release (Linux needs `git`, `curl`, and `jq` for this command):

   ```bash
   git clone --branch "$(curl -s https://api.github.com/repos/langgenius/dify/releases/latest | jq -r .tag_name)" https://github.com/langgenius/dify.git
   ```

3. Create the environment file:

   ```bash
   cd dify/docker
   cp .env.example .env
   ```

4. Replace `SECRET_KEY` in `.env` before the first launch (the docs suggest generating one with `openssl rand -base64 42`), then start the stack and check that the containers are up:

   ```bash
   docker compose up -d
   docker compose ps
   ```

5. Open `http://localhost/install` to create the admin account, then log in at `http://localhost`.
6. Add a model provider under Integrations, create an app in Studio, test it, and publish it.

To try Dify without a server, sign up for Dify Cloud at [cloud.dify.ai](https://cloud.dify.ai).

## Key concepts

- **App types**: Workflow (single-turn tasks), Chatflow (a workflow triggered at every turn of a conversation), Chatbot, Agent, and Text Generator.
- **Studio**: the drag-and-drop interface where you build and publish apps.
- **Nodes**: workflow steps such as User Input, LLM, IF/ELSE, Iteration, Code, Template, and Output.
- **Knowledge**: knowledge bases built from your documents for retrieval.
- **Plugins and tools**: integrations that add model providers, tools, data sources, and external services.
- **Environment variables**: app-level storage for secrets such as API keys, kept out of exported app files.
- **Dify DSL**: the YAML format used to export and import apps.

## Security notes

- **Replace shipped defaults before production.** `SECRET_KEY` ships pre-filled and must be replaced. The docs also call out public development values for `DIFY_AGENT_SERVER_SECRET_KEY` and `DIFY_AGENT_API_TOKEN`. Set `INIT_PASSWORD` so only you can complete `/install` on a reachable host. See [Environment variables](https://docs.dify.ai/en/self-host/deploy/configuration/environments).
- **Change default database credentials.** [CVE-2025-56157](https://nvd.nist.gov/vuln/detail/CVE-2025-56157): Dify through 1.5.1 ships default PostgreSQL credentials in its `docker-compose.yaml`. The supplier notes PostgreSQL is not exposed by default from 1.0.1 onward; keep it that way and change the password anyway.
- **Protect provider keys inside the workspace.** [CVE-2025-67732](https://github.com/langgenius/dify/security/advisories/GHSA-phpv-94hg-fv9g): up to 1.10.1-fix.1, a console endpoint returned custom model provider API keys in plaintext to non-administrator users, who could then reuse them. Fixed in 1.11.0. Use provider keys with spending limits and rotate them after any exposure.
- **Keep the sandbox and SSRF proxy in place.** Code and Template Transform nodes run in a separate sandbox service that blocks file system access, outbound network connections, and system commands. Outbound requests go through an SSRF proxy that blocks internal and private IP ranges. Do not remove these services, and change `CODE_EXECUTION_API_KEY` (default `dify-sandbox`) together with the sandbox's matching key.
- **Lock down sign-up and CORS.** Leave `ALLOW_REGISTER` at `false` for invite-only use, and replace the `*` defaults for `WEB_API_CORS_ALLOW_ORIGINS` and `CONSOLE_CORS_ALLOW_ORIGINS` with your own domains. Keep `DEBUG` off in production because it can expose sensitive data in logs.
- **Patch for tenant isolation bugs.** Dify's [security advisories](https://github.com/langgenius/dify/security/advisories) in 2026 include cross-tenant file preview, cross-tenant API detail disclosure, and an IDOR on MCP server settings. Upgrade regularly, following each release's upgrade notes.
- **Expect prompt injection.** Documents in knowledge bases, user chat input, and tool results all reach the model. Limit what tools and credentials each published app can use.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Dify documentation](https://docs.dify.ai/): Cloud, self-hosting, API reference, and plugin development.
- [Deploy Dify with Docker Compose](https://docs.dify.ai/en/self-host/deploy/quick-start/docker-compose).
- [Key concepts](https://docs.dify.ai/en/learn/key-concepts): apps, workflows, chatflows, variables, and DSL.
- [Workflow 101, lesson 1](https://docs.dify.ai/en/learn/tutorials/workflow-101/lesson-01): an introductory tutorial series.
- [Code node](https://docs.dify.ai/en/cloud/use-dify/nodes/code): what custom code can and cannot do in the sandbox.
