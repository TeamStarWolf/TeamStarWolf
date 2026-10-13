# Langflow

> In one minute: Langflow is an open-source, Python-based platform for building AI agents and workflows in a visual editor, then serving them through an API or as MCP servers. Teams use it to prototype chatbots, retrieval pipelines, and tool-using agents without writing much code. A Langflow server runs user-supplied Python and stores model provider keys, so an exposed instance is a high-value target: two of its flaws are on the CISA Known Exploited Vulnerabilities catalog.

| | |
|---|---|
| Category | Workflow builder |
| Maintainer | Langflow project (langflow-ai on GitHub) |
| License / access | Open source (MIT); self-hosted, plus a Langflow Desktop app |
| Official docs | [docs.langflow.org](https://docs.langflow.org/) |
| Repository | [langflow-ai/langflow](https://github.com/langflow-ai/langflow) |
| Checked | 8 Oct 2026, v1.12.5 (PyPI `langflow`) |

## What it is for

- Prototyping AI agents that call tools, such as a calculator or URL fetcher, in a drag-and-drop editor.
- Building retrieval (RAG) and chat workflows that combine models, vector stores, and data sources.
- Testing a flow interactively in the Playground before wiring it into an application.
- Running flows from application code through the Langflow API.
- Exposing flows as tools to MCP clients, or connecting flows to external MCP servers.

## Quick start

1. Choose an install method. Python 3.10 to 3.14 is required for the package install.

   Python package with `uv` (all OSes):

   ```bash
   uv venv VENV_NAME
   source VENV_NAME/bin/activate      # Linux or macOS
   VENV_NAME\Scripts\activate         # Windows
   uv pip install langflow
   uv run langflow run
   ```

   Docker, with auto-login turned off and a superuser password set:

   ```bash
   docker run -p 7860:7860 \
     -e LANGFLOW_AUTO_LOGIN=false \
     -e LANGFLOW_SUPERUSER_PASSWORD=SUPERUSER_PASSWORD \
     langflowai/langflow:latest
   ```

   Langflow Desktop is available for macOS 13 or later and Windows.

2. Open `http://127.0.0.1:7860` (package install) or `http://localhost:7860` (Docker).
3. Click **New Flow** and pick the **Simple Agent** template.
4. In the Agent component, click **Setup Provider**, add your model provider key, and choose a model.
5. Click **Playground** to test the agent, then use **Share > API access** to get code that calls `/api/v1/run/FLOW_ID`.

## Key concepts

- **Flow**: a workflow built by connecting and configuring component nodes.
- **Component**: one step in a flow, such as a model, a prompt, a tool, or a data source.
- **Playground**: a chat panel for testing a flow in real time.
- **Agent**: a component that uses a model to decide which connected tools to call.
- **Global variables**: reusable values such as credentials, encrypted in Langflow's database with its secret key. Credential-type values are masked in the editor.
- **Langflow API keys**: keys that carry the privileges of the user who created them, sent in an `x-api-key` header.
- **MCP server and client**: each project can expose its flows as MCP tools, and flows can call external MCP servers.

## Security notes

- **Never expose Langflow to the internet.** Langflow's own docs warn: "Never expose Langflow ports directly to the internet without proper security measures." Keep it on a private network or behind an authenticated reverse proxy, and restrict who can reach port 7860.
- **[CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)** (CVSS 9.8): versions before 1.3.0 lack authentication on the code validation endpoint, `/api/v1/validate/code`, so a remote, unauthenticated attacker can run arbitrary Python on the host. CISA added it to the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-3248) on 5 May 2025. Upgrade to 1.3.0 or later.
- **JADEPUFFER.** Sysdig documented [JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion), which it calls the first documented case of agentic ransomware, an extortion operation driven end to end by a large language model. Its entry point was an internet-facing Langflow instance exploited through CVE-2025-3248. On the host, the agent searched for AI provider keys (OpenAI, Anthropic, Gemini, and others) and cloud credentials, dumped Langflow's Postgres database, and added a cron beacon. It then encrypted configuration data on a separate production server and dropped databases. Sysdig advises keeping provider API keys and cloud credentials out of AI orchestration server environments.
- **Keep provider keys out of the Langflow environment.** Store only the keys a flow needs, as Credential-type global variables or in an external secret store such as Kubernetes Secrets, never in shell environment variables on an internet-reachable host. Deleting a Langflow global variable does not revoke the key at the provider, so rotate keys after any suspected exposure.
- **[CVE-2026-33017](https://nvd.nist.gov/vuln/detail/CVE-2026-33017)** (CVSS 9.8): versions before 1.9.0 let unauthenticated users call the public flow build endpoint with their own flow data, and the Python code in that data runs without a sandbox. CISA added it to the KEV catalog on 25 March 2026. Upgrade to 1.9.0 or later.
- **Harden authentication.** The application default for `LANGFLOW_AUTO_LOGIN` is `True`, which signs every visitor in as superuser. Set it to `False` (the official Docker images already do), set your own `LANGFLOW_SECRET_KEY`, set `LANGFLOW_ENABLE_SUPERUSER_CLI` to `false`, and replace the wildcard CORS defaults. See [API keys and authentication](https://docs.langflow.org/api-keys-and-authentication).
- **Limit MCP and code features to trusted users.** Langflow's [security advisories](https://github.com/langflow-ai/langflow/security/advisories) include an authenticated remote code execution through MCP servers using the stdio transport (fixed in 1.9.0). Use `LANGFLOW_MCP_SERVERS_LOCKED` to stop non-superusers from editing MCP server connections, and do not leave a project's MCP server unauthenticated outside a trusted environment.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Langflow documentation](https://docs.langflow.org/): concepts, components, deployment, and API reference.
- [Install Langflow](https://docs.langflow.org/get-started-installation): Desktop, Docker, and Python package.
- [Quickstart](https://docs.langflow.org/get-started-quickstart): build and run the Simple Agent template.
- [Use Langflow as an MCP server](https://docs.langflow.org/mcp-server): endpoints, authentication, and hardening options.
- [Global variables](https://docs.langflow.org/configuration-global-variables): how credentials are stored and encrypted.
