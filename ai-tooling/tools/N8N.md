# n8n

> In one minute: n8n is a workflow automation platform that connects apps, APIs, and AI models through a visual node editor, with the option to write JavaScript or Python where needed. Teams use it to build integrations and AI agent workflows that run on triggers such as webhooks, forms, and schedules. An n8n instance holds credentials for every connected service, so its exposure and patch level matter: one of its flaws is on the CISA Known Exploited Vulnerabilities catalog.

| | |
|---|---|
| Category | Workflow builder |
| Maintainer | n8n (n8n-io on GitHub) |
| License / access | Fair-code, source available (Sustainable Use License; files marked `.ee` need an n8n Enterprise License). Free self-hosted Community edition; paid n8n Cloud and enterprise editions |
| Official docs | [docs.n8n.io](https://docs.n8n.io/) |
| Repository | [n8n-io/n8n](https://github.com/n8n-io/n8n) |
| Checked | 8 Oct 2026, n8n@2.42.4 (released 7 Oct 2026) |

## What it is for

- Connecting SaaS apps and internal APIs without writing a full integration service.
- Building AI agent workflows that call models, tools, and other workflows.
- Running automations on triggers such as webhooks, forms, schedules, and app events.
- Adding custom logic with expressions and the Code node.
- Self-hosting automation so data stays on infrastructure you control.

## Quick start

1. Try n8n with Node.js (versions 20.19 to 24.x). npm installs are deprecated from n8n 3.0, so prefer Docker for anything lasting.

   ```bash
   npx n8n                 # run without installing
   npm install n8n -g      # or install globally, then run: n8n
   ```

2. Or run it with Docker. This single-container command is from the n8n docs, which now point to Docker Compose as the preferred setup:

   ```bash
   docker volume create n8n_data
   docker run -it --rm --name n8n -p 5678:5678 \
     -e N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true \
     -e N8N_RUNNERS_ENABLED=true \
     -v n8n_data:/home/node/.n8n \
     n8nio/n8n
   ```

   The `n8n_data` volume keeps workflows, encryption keys, and logs across restarts.

3. Open `http://localhost:5678` in a browser.
4. Build a first workflow: add a trigger node, add one or more app or AI nodes, connect them, and run a test execution.

## Key concepts

- **Workflow**: a set of connected nodes that automates a process, started by a trigger.
- **Node**: a building block that triggers a workflow, fetches or transforms data, controls flow, or connects to a service.
- **Trigger node**: a node that starts a workflow when a condition occurs, such as an incoming webhook or a schedule.
- **Credentials**: stored authentication details (passwords, API keys, OAuth secrets) that let nodes connect to services. n8n encrypts them with an encryption key.
- **Expressions**: JavaScript snippets that fill node parameters dynamically from earlier nodes or the environment.
- **Code node**: runs custom JavaScript or Python; task runners execute this code, and external mode isolates it from the main n8n process.
- **AI agent and cluster nodes**: an agent uses a language model to decide how to handle input; cluster nodes combine a root node with sub-nodes such as models and tools.

## Security notes

- **Do not expose n8n to the internet unpatched.** [CVE-2026-21858](https://nvd.nist.gov/vuln/detail/CVE-2026-21858) (CVSS 10.0): versions 1.65.0 up to 1.121.0 let an unauthenticated remote attacker read files on the server through certain form-based workflows. Fixed in 1.121.0; until you upgrade, restrict or disable public webhook and form endpoints. See the [vendor advisory](https://github.com/n8n-io/n8n/security/advisories/GHSA-v4pr-fm98-w9pg).
- **[CVE-2025-68613](https://nvd.nist.gov/vuln/detail/CVE-2025-68613)** (expression injection): authenticated users could supply workflow expressions that run in an insufficiently isolated context and execute code with the n8n process's privileges. Fixed in 1.120.4, 1.121.1, and 1.122.0. CISA added it to the Known Exploited Vulnerabilities catalog on 11 March 2026. See the [vendor advisory](https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp).
- **Treat workflow editors as code authors.** Anyone who can create or edit workflows can run code through expressions and the Code node. n8n's own short-term workaround for CVE-2025-68613 was to limit workflow editing to fully trusted users and to run n8n with restricted OS privileges and limited network access.
- **Isolate code execution.** Run task runners in external mode as separate containers, use the distroless runner image, run as a non-root user, use a read-only root filesystem, and apply an AppArmor profile that blocks reads of `/proc` files that can expose secrets. See [Harden task runners](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security/harden-task-runners).
- **Block internal network access.** From 2.12.0, setting `N8N_SSRF_PROTECTION_ENABLED=true` blocks requests from nodes such as HTTP Request to private, loopback, and link-local ranges. n8n recommends network firewalls as the primary control. See [SSRF protection](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security/enable-ssrf-protection).
- **Use the hardening checklist.** The [security overview](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security) covers SSL, SSO, MFA policies, security audits, encryption key rotation, redacting execution data, disabling the public API, blocking specific nodes, and verifying user emails. Keep the encryption key safe and back it up with the data volume.
- **Expect prompt injection in AI workflows.** Webhook payloads, emails, and documents that reach an AI agent node can carry instructions. Give agent tools only the credentials and actions the workflow needs.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [n8n documentation](https://docs.n8n.io/): building, hosting, and configuring n8n.
- [Install with npm](https://docs.n8n.io/hosting/installation/npm/): Node.js requirements and commands.
- [Choose how to use n8n](https://docs.n8n.io/choose-how-to-use-n8n): Cloud, Community, Business, and Enterprise options.
- [n8n Academy](https://learn.n8n.io/): free courses, from a quickstart to AI workflows and best practices.
- [n8n security advisories](https://github.com/n8n-io/n8n/security/advisories): published vulnerabilities and fixed versions.
