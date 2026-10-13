# Flowise

> In one minute: Flowise is an open-source visual builder for AI agents, chatbots, and LLM workflows, built on Node.js. Its maintainers froze development on 29 July 2026, archived the GitHub repository on 13 August 2026, and ended official support on 31 August 2026. Existing deployments therefore receive no further official fixes, which makes the security posture of any remaining Flowise server the owner's responsibility.

| | |
|---|---|
| Category | Workflow builder |
| Maintainer | FlowiseAI (repository archived, end of life 31 Aug 2026) |
| License / access | Open source (Apache-2.0), except `packages/server/src/enterprise` and some marked files, which are under a commercial license |
| Official docs | [docs.flowiseai.com](https://docs.flowiseai.com/) |
| Repository | [FlowiseAI/Flowise](https://github.com/FlowiseAI/Flowise) (archived, read-only) |
| Checked | 8 Oct 2026, flowise@3.1.4 (final release before the archive) |

## What it is for

- Building chat assistants and AI agents in a drag-and-drop editor.
- Connecting open-source and proprietary models to data sources, vector databases, and memory.
- Giving agents tools, including custom tools and MCP servers.
- Exposing flows through an API or an embeddable chat widget.
- Studying or forking: the maintainers suggest teams that depend on Flowise fork the code and maintain it themselves.

## Quick start

These steps come from the official docs and README. The project is no longer maintained, so use them for labs or for evaluating an existing deployment, not for new production systems.

1. Install with npm (the 3.1.4 package declares Node.js 24 in its `engines` field):

   ```bash
   npm install -g flowise
   npx flowise start
   ```

2. Or run it with Docker Compose from a clone of the repository:

   ```bash
   git clone https://github.com/FlowiseAI/Flowise
   cd Flowise/docker
   cp .env.example .env
   docker compose up -d
   ```

   Stop it with `docker compose stop`.

3. Open `http://localhost:3000`.
4. Set your own JWT and session secrets in the environment before anyone else can reach the server (see the security notes).
5. Create a flow with one of the builders (Assistant, Chatflow, or Agentflow) and test it before connecting any real data.

## Key concepts

- **Assistant**: the most beginner-friendly way to create an AI agent that can use tools when needed.
- **Chatflow**: a builder for single-agent systems, chatbots, and simple LLM flows.
- **Agentflow**: the superset of Chatflow and Assistant (the docs cover Agentflow V2; V1 is being deprecated).
- **Nodes**: the building blocks of a flow, such as models, memories, vector databases, and tools.
- **Credentials**: stored API keys and secrets for connected services, protected by an encryption key.
- **Tools and MCP**: custom tools, plus MCP client and server nodes, that agents can call.
- **App-level authentication**: email and password accounts (from v3.0.1) with JWT-based sessions; the older `FLOWISE_USERNAME` and `FLOWISE_PASSWORD` method is deprecated.

## Security notes

- **Plan a migration.** The ["Future of Flowise"](https://github.com/FlowiseAI/Flowise/discussions/6727) announcement set a code freeze on 29 July 2026, archived the repository on 13 August 2026, and ended official support on 31 August 2026. No successor was named. Treat any remaining instance as unmaintained software: inventory it, restrict access, and move to a maintained platform or a fork you are able to patch.
- **Never expose Flowise to the internet.** Several published flaws give remote code execution. [CVE-2025-59528](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) (CVSS 10.0): in 3.0.5, the CustomMCP node evaluated user-supplied `mcpServerConfig` as JavaScript with full Node.js privileges, so a request to `/api/v1/node-load-method/customMCP` with an API token could run shell commands. Fixed in 3.0.6.
- **Upgrade to the final release at minimum.** July 2026 advisories rated Critical include [CVE-2026-69255](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-vmv7-4m6c-3cg5), a CSV Agent code injection, and [CVE-2026-73483](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-9gvv-qjj3-2p6g), a NodeVM sandbox escape through the puppeteer allowlist that runs commands as root in the official Docker image. Both affect 3.1.2 and earlier and are fixed in 3.1.3. Later advisories (August and September 2026) cover cross-tenant and missing-authorization flaws; check the [advisory list](https://github.com/FlowiseAI/Flowise/security/advisories) against your version, and expect that newer issues may have no official fix.
- **Replace default secrets.** The docs recommend setting your own `JWT_AUTH_TOKEN_SECRET`, `JWT_REFRESH_TOKEN_SECRET`, `EXPRESS_SESSION_SECRET`, and `TOKEN_HASH_SECRET`; otherwise defaults make token forgery and impersonation easier. See [App-level authentication](https://docs.flowiseai.com/configuration/authorization/app-level).
- **Keep provider keys out of reach.** Flowise stores model and tool credentials. Use keys scoped to the flows that need them, keep the encryption key in a secret manager (the docs suggest AWS Secrets Manager), and rotate keys if an instance was ever exposed.
- **Expect prompt injection.** Chat input, uploaded files, and retrieved documents reach the model and can steer agents that hold tools. Limit which tools and credentials each flow can use.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Flowise documentation](https://docs.flowiseai.com/): builders, integrations, and configuration for the final releases.
- [Get Started](https://docs.flowiseai.com/getting-started): npm and Docker installation.
- [Running in Production](https://docs.flowiseai.com/configuration/running-in-production): database, storage, encryption, and rate limiting.
- [The Future of Flowise](https://github.com/FlowiseAI/Flowise/discussions/6727): the end-of-life announcement and timeline.
- [Flowise security advisories](https://github.com/FlowiseAI/Flowise/security/advisories): published vulnerabilities and fixed versions.
