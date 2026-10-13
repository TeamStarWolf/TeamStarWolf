# Microsoft Agent Framework

> In one minute: Microsoft Agent Framework is an open-source framework for building AI agents and multi-agent workflows in Python and .NET, with a Go SDK in public preview. Microsoft calls it the direct successor to Semantic Kernel and AutoGen, created by the same teams: it combines AutoGen's simple agent abstractions with Semantic Kernel's enterprise features and adds graph-based workflows. Teams taking agents to production, on Azure or with other model providers, use it for orchestration, state, and observability.

| | |
|---|---|
| Category | Agent framework |
| Maintainer | Microsoft |
| License / access | Open source (MIT). Model access is through your chosen provider, such as Microsoft Foundry, Azure OpenAI, OpenAI, Anthropic, or Ollama. |
| Official docs | [learn.microsoft.com](https://learn.microsoft.com/en-us/agent-framework/overview/) |
| Repository | [microsoft/agent-framework](https://github.com/microsoft/agent-framework) |
| Checked | 8 Oct 2026, Python agent-framework 1.20.0, .NET 1.24.0 |

## What it is for

- Single agents that call function tools and MCP servers across several model providers.
- Graph-based workflows with explicit execution paths: sequential, concurrent, handoff, and group collaboration, with checkpointing and human-in-the-loop.
- Migrating existing Semantic Kernel or AutoGen projects, using Microsoft's migration guides. AutoGen itself is now in maintenance mode and community managed.
- Production agents with middleware and built-in OpenTelemetry tracing.
- Declarative agents defined in YAML, and hosting on Foundry infrastructure.

## Quick start

1. Install the Foundry integration and Azure Identity (Python). The `agent-framework` metapackage also exists if you want many optional integrations at once.

   ```bash
   pip install agent-framework-foundry azure-identity
   ```

2. Sign in with the Azure CLI. This sample authenticates with Microsoft Entra ID instead of an API key.

   ```bash
   az login
   ```

3. Put your Foundry project endpoint and model deployment name in environment variables.

   ```bash
   export FOUNDRY_PROJECT_ENDPOINT="https://your-account.services.ai.azure.com/api/projects/your-project"
   export FOUNDRY_MODEL="your-model-deployment"
   ```

4. Save `hello_agent.py`. This is the official first-agent sample, reading the endpoint and model from the environment as the repository README shows.

   ```python
   import asyncio
   import os

   from agent_framework import Agent
   from agent_framework.foundry import FoundryChatClient
   from azure.identity import AzureCliCredential

   async def main() -> None:
       agent = Agent(
           client=FoundryChatClient(
               project_endpoint=os.environ["FOUNDRY_PROJECT_ENDPOINT"],
               model=os.environ["FOUNDRY_MODEL"],
               credential=AzureCliCredential(),
           ),
           instructions="You are a friendly assistant. Keep your answers brief.",
       )
       print(await agent.run("What is the largest city of France?"))

   if __name__ == "__main__":
       asyncio.run(main())
   ```

5. Run it with `python hello_agent.py`. The framework does not load `.env` files automatically; call `load_dotenv()` first if you keep settings in one.

## Key concepts

- **Agent**: an LLM-backed component that processes input, calls tools and MCP servers, and returns a response.
- **Chat client**: the model connection an agent uses, for example `FoundryChatClient` or an OpenAI client.
- **Harness agent**: an opinionated agent for long, multi-step tasks, with planning, context compaction, file access, memory, tool approval, and observability built in.
- **Workflow**: functional or graph-based orchestration that connects agents and functions through explicit execution paths.
- **Agent session and context providers**: session-based state management, plus providers that supply memory to agents.
- **Middleware**: intercepts agent actions for request and response processing, exception handling, and custom pipelines.
- **Tools**: function tools, hosted and local MCP tools, code interpreter, file search, web search, and shell tools. Any agent can become a tool for another with `as_tool()`.
- **Tool approval**: a human-in-the-loop gate before a locally invoked tool's result reaches the model.

## Security notes

- Microsoft's documentation states that using third-party servers, agents, code, or non-Azure models is at your own risk. Review what data you share with them and whether it leaves your compliance and geographic boundary. You remain responsible for your own responsible-AI mitigations, such as metaprompts and content filters.
- Gate sensitive tools with tool approval. It works for tools the client invokes locally; hosted tools follow the provider's own approval behavior, so check each provider.
- The samples warn that `DefaultAzureCredential` is convenient for development but can cause credential probing and fallback risks; in production use a specific credential such as a managed identity.
- MCP integration has had real flaws. October 2026 advisories for the .NET declarative workflows package: [GHSA-9f26-7mqc-9vc4](https://github.com/microsoft/agent-framework/security/advisories/GHSA-9f26-7mqc-9vc4) (high) let an `InvokeMcpTool` action forward values marked sensitive, including environment secrets, to an external MCP server, and GHSA-q7g7-7c7x-frcq let transport headers change after a human approved a call. Both fixed in Microsoft.Agents.AI.Workflows.Declarative 1.24.0. A third, GHSA-r2mq-wgc9-vgh3, could send a hosted agent's Azure bearer token to an unintended origin.
- Treat tool output, MCP tool descriptions, and messages from remote A2A agents as untrusted input that can carry prompt injection. Keep the tool list per agent small, and run shell and computer-use tools in containers with policy controls.
- Experimental and preview tools emit an `ExperimentalWarning` the first time they run. Do not treat them as production-ready.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Agent Framework overview](https://learn.microsoft.com/en-us/agent-framework/overview/)
- [Your first agent](https://learn.microsoft.com/en-us/agent-framework/get-started/your-first-agent)
- [Tool approval](https://learn.microsoft.com/en-us/agent-framework/agents/tools/tool-approval)
- [Workflows](https://learn.microsoft.com/en-us/agent-framework/concepts/workflows/)
- [Migration guide from Semantic Kernel](https://learn.microsoft.com/en-us/agent-framework/migration-guide/from-semantic-kernel/)
- [Migration guide from AutoGen](https://learn.microsoft.com/en-us/agent-framework/migration-guide/from-autogen/)
