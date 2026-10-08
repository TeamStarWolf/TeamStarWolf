# Model Context Protocol (MCP)

> In one minute: The Model Context Protocol is an open standard for connecting AI applications to external tools and data. A host application, such as a chat app, IDE, or agent, runs an MCP client for each MCP server it uses, and servers expose tools, resources, and prompts over JSON-RPC. MCP has become a common plug-in layer for agents, which makes every server you install part of your attack surface.

| | |
|---|---|
| Category | Protocol |
| Maintainer | Model Context Protocol, a Series of LF Projects, LLC (Linux Foundation). Created by Anthropic, which donated it to the Agentic AI Foundation in December 2025. |
| License / access | Open specification. New code and spec contributions are Apache-2.0 (the project is moving from MIT); docs are CC-BY-4.0. The Python SDK is MIT. |
| Official docs | [modelcontextprotocol.io](https://modelcontextprotocol.io/specification/latest) |
| Repository | [modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol) (spec); [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) |
| Checked | 8 Oct 2026, spec version 2026-07-28; Python SDK `mcp` 2.3.0 |

## What it is for

- Expose an internal API, database, or file store once, to any MCP-capable host, instead of writing a plug-in per assistant.
- Give coding assistants and IDEs access to tickets, documentation, and CI systems.
- Share one tool server across agent frameworks; the OpenAI Agents SDK, Claude Agent SDK, and Microsoft Agent Framework all act as MCP clients.
- Offer reusable prompt templates and read-only resources alongside tools.
- Run remote, OAuth-protected tool services over Streamable HTTP.

## Quick start

1. Install the official Python SDK with its CLI extra (Python 3.10 or later). The `cli` extra adds the `mcp` command (`mcp dev`, `mcp run`).

   ```bash
   uv add "mcp[cli]"      # or: pip install "mcp[cli]"
   ```

2. Create `server.py`. In SDK v2 the server class is `MCPServer`, imported from `mcp.server`; v1 called it `FastMCP`, so older tutorials will not run unchanged.

   ```python
   from mcp.server import MCPServer

   mcp = MCPServer("Demo")


   @mcp.tool()
   def add(a: int, b: int) -> int:
       """Add two numbers."""
       return a + b


   @mcp.resource("greeting://{name}")
   def greeting(name: str) -> str:
       """Greet someone by name."""
       return f"Hello, {name}!"


   if __name__ == "__main__":
       mcp.run()
   ```

   Type hints become the tool's input schema and the docstring becomes its description. `mcp.run()` with no arguments serves over stdio. If a tool needs a credential, read it from an environment variable inside the server; never hard-code it.

3. Open the server in the MCP Inspector, call `add` with `a=1` and `b=2`, and confirm the result is `3`.

   ```bash
   uv run mcp dev server.py
   ```

4. Connect a host by giving it the launch command. Every stdio host takes the same command, placed in its own configuration file or CLI.

   ```bash
   uv run --with "mcp[cli]" mcp run /absolute/path/to/server.py
   ```

## Key concepts

- **Host, client, server**: the host is the LLM application; it runs one client per connected server; the server exposes capabilities and never talks to the model directly.
- **Tools**: functions the model decides to call. They can take actions and have side effects.
- **Resources**: data the application loads into context, such as file contents. Templates like `greeting://{name}` take parameters.
- **Prompts**: reusable message templates a user invokes by name, such as a slash command.
- **Capabilities**: what a server declares it supports when a client connects; clients only ask for declared features.
- **Transports**: the two standard transports are stdio (a local child process) and Streamable HTTP (a remote service). Messages are JSON-RPC 2.0.
- **Authorization**: HTTP servers protect access with OAuth 2.1, as described in the authorization specification.
- **Elicitation**: a server-initiated request, through the client, for more information from the user.

## Security notes

- **Tool poisoning.** The model reads tool names and descriptions as instructions, so a malicious or compromised server can hide commands in them. The specification says tool annotations are untrusted unless they come from a trusted server. Review each server's tool list (the Inspector shows it without a model in the loop), prefer clients that pin tool definitions and re-prompt when they change, and keep the server roster small.
- **Prompt injection through tool output.** Results from servers that read web pages, email, or tickets can carry instructions that steer the next tool call, including calls to a different server in the same session. The specification requires hosts to get explicit user consent before invoking a tool; keep approval on for tools with side effects.
- **Malicious packages are real.** In September 2025 the npm package `postmark-mcp` added a hidden BCC in version 1.0.16, copying every email sent through it to an attacker-controlled address ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)). Verify the publisher and exact package name, pin versions, and remember that pinning through `npx` or `uvx` fixes only the top-level package; pin container images by digest.
- **Client-side flaws.** [CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) (critical, CVSS 9.6): `mcp-remote` allowed OS command injection when it connected to an untrusted server that returned a crafted `authorization_endpoint` URL. Fixed in mcp-remote 0.1.16 ([GHSA-6xpm-ggf7-wc3p](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p)). The developer Inspector had its own remote code execution bug, [CVE-2025-49596](https://nvd.nist.gov/vuln/detail/CVE-2025-49596), fixed in 0.14.1. Keep MCP tooling current.
- **Least privilege and allowlisting.** Keep an allowlist of approved servers at pinned versions, and block everything else. Run local servers in an isolated environment such as a container, mount only the directories they need, isolate credentials, and restrict network egress.
- **Remote servers.** Follow the specification's security best practices: avoid token passthrough, validate OAuth redirect and authorization URLs, and guard against confused-deputy and SSRF attacks.
- Library references: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [MCP specification (latest)](https://modelcontextprotocol.io/specification/latest)
- [Python SDK: get started](https://py.sdk.modelcontextprotocol.io/get-started/)
- [Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Local Server Security](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security)
- [Governance and Stewardship](https://modelcontextprotocol.io/community/governance)
- [Donating MCP and establishing the Agentic AI Foundation](https://www.anthropic.com/news/donating-the-model-context-protocol-and-establishing-of-the-agentic-ai-foundation)
