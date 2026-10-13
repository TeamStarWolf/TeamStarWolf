# Anthropic Claude API

> In one minute: The Claude API is Anthropic's hosted HTTPS interface to the Claude family of large language models. Developers call it directly or through official SDKs to build chat, analysis, coding, and agent applications. Security teams care because these apps hold long-lived credentials, send business data to a third party, and can be steered by prompt injection once they are connected to tools.

| | |
|---|---|
| Category | Model platform (API) |
| Maintainer | Anthropic |
| License / access | Commercial API with usage-based billing; official SDKs are open source (Python SDK: MIT) |
| Official docs | [platform.claude.com](https://platform.claude.com/docs/en/intro) |
| Repository | [anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) |
| Checked | 8 Oct 2026, hosted service; Python SDK `anthropic` 1.12.1 (released 8 Oct 2026) |

## What it is for

- Text tasks over natural language: summarize, extract, classify, rewrite, and answer questions with the Messages API.
- Agents that call functions you define (client tools) or Anthropic-run server tools such as web search, web fetch, and code execution.
- Long-document and code analysis; the current models list a 1M-token context window.
- High-volume offline jobs through the Message Batches API.
- Connecting a model to remote Model Context Protocol (MCP) servers through the MCP connector.

## Quick start

These steps follow the official Python quick start on macOS or Linux.

1. Create a Claude Console account, then create a key under Settings > API keys.
2. Export the key. The SDK reads `ANTHROPIC_API_KEY` automatically.

   ```bash
   export ANTHROPIC_API_KEY="YOUR_API_KEY"
   ```

3. Create a project and install the SDK:

   ```bash
   mkdir claude-quickstart && cd claude-quickstart
   python3 -m venv .venv && source .venv/bin/activate
   pip install anthropic
   ```

4. Save this as `quickstart.py`:

   ```python
   import anthropic

   client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY

   message = client.messages.create(
       model="claude-opus-5-5",
       max_tokens=1000,
       messages=[
           {
               "role": "user",
               "content": "List three ways to keep an API key out of source code.",
           }
       ],
   )

   for block in message.content:
       if block.type == "text":
           print(block.text)
   ```

5. Run it with `python quickstart.py`. Model IDs change over time; check the [models overview](https://platform.claude.com/docs/en/about-claude/models/overview) for current IDs.

## Key concepts

- **Messages API**: `POST /v1/messages`. A request names a `model`, sets `max_tokens`, and sends a list of `user` and `assistant` turns. The reply is a list of content blocks.
- **Model IDs**: strings such as `claude-opus-5-5`. Each ID is a pinned snapshot. The Models API reports each model's limits and capabilities.
- **Content blocks**: typed parts of a message, such as `text`, `tool_use`, and `tool_result`.
- **Client tools and server tools**: client tools run in your application (Claude stops with `stop_reason: "tool_use"` and you send back a `tool_result`). Server tools such as `web_search`, `web_fetch`, and `code_execution` run on Anthropic infrastructure.
- **Organizations, workspaces, and keys**: an organization holds workspaces. Keys are personal, service account, or legacy workspace keys. A key not scoped to one workspace must send the `anthropic-workspace-id` header.
- **Workload Identity Federation (WIF)**: a workload exchanges a token from its identity provider at `POST /v1/oauth/token` for a short-lived Claude API token, so no static key is stored.
- **Usage tiers**: organization-level rate limits (requests, input tokens, and output tokens per minute) and a monthly spend cap that grow with usage history.

## Security notes

- **Prefer short-lived or identity-backed credentials.** The [authentication guide](https://platform.claude.com/docs/en/manage-claude/authentication) calls workspace keys legacy and recommends personal keys for individuals, service account keys for shared workloads, and WIF for production on AWS, Google Cloud, Azure, CI/CD, and Kubernetes. Set a key expiration (3 hours to 30 days, custom, or Never), keep keys in a secrets manager, and disable or delete any key you suspect has leaked. GitHub secret scanning includes patterns for Anthropic keys (see the [supported patterns list](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)).
- **Know the retention rules.** The [commercial retention policy](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data) deletes API inputs and outputs within 30 days, but content flagged for Usage Policy violations may be kept up to 2 years. Anthropic states retained data is never used for model training without your express permission. Zero data retention (ZDR) is a per-organization agreement arranged through sales and covers the Messages and Token Counting APIs.
- **Stateful features fall outside ZDR.** Per [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), the Batch API, Files API, code execution (containers kept up to 30 days), Agent Skills, and the MCP connector are not ZDR-eligible. Claude Fable and Claude Mythos models require 30-day retention. Check each feature before sending regulated data.
- **Use limits to contain abuse.** [Rate limits](https://platform.claude.com/docs/en/api/rate-limits) use a token bucket per model. Exceeding them returns HTTP 429 with a `retry-after` header and `anthropic-ratelimit-*` headers. Set lower spend and rate limits per workspace so a leaked key or runaway agent cannot drain the whole organization. A spend-cap 429 has no `retry-after`, and retries keep failing until access resumes.
- **Treat tool results as untrusted.** Anthropic's [jailbreak and prompt injection guide](https://platform.claude.com/docs/en/test-and-evaluate/strengthen-guardrails/mitigate-jailbreaks) separates direct attacks from indirect injection in web pages, emails, documents, and tool results. It recommends delivering third-party content only inside `tool_result` blocks, JSON-encoding it, stating an untrusted-content policy in the system prompt, screening tool output with a small classifier model, and giving the model least-privilege, sandboxed tools. Anthropic runs extra injection classifiers for the computer use and browser use tools.
- **Connected services widen the attack surface.** Web fetch, web search, and MCP servers bring outside content into the context and send requests to third parties. Allow only the MCP servers and tools a workflow needs, and require human confirmation for consequential actions.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Get started with Claude](https://platform.claude.com/docs/en/get-started): first API call in cURL, Python, TypeScript, and other SDKs.
- [Working with the Messages API](https://platform.claude.com/docs/en/build-with-claude/working-with-messages): multi-turn conversations, system prompts, and stop reasons.
- [Tool use with Claude](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview): client tools, server tools, and the tool-use loop.
- [Prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching): reuse long prompt prefixes to cut cost and rate-limit usage.
- [Claude cookbooks](https://github.com/anthropics/claude-cookbooks): MIT-licensed notebooks on tool use, RAG, evaluations, and agents.
- [Anthropic courses](https://github.com/anthropics/courses): API fundamentals, prompt engineering, and tool use (repository archived in Sep 2026; still readable).
