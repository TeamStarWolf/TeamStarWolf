# LangChain and LangGraph

> In one minute: LangChain is an open-source framework for building LLM agents from a model, tools, a prompt, and middleware. LangGraph is the lower-level runtime underneath it for long-running, stateful agents, with persistence, streaming, and human-in-the-loop control. Developers use the pair to connect language models to their own data and systems, so tool permissions and serialized state are where security work concentrates.

| | |
|---|---|
| Category | App and agent framework |
| Maintainer | LangChain |
| License / access | Open source (MIT) |
| Official docs | [docs.langchain.com](https://docs.langchain.com/oss/python/langchain/overview) |
| Repository | [langchain-ai/langchain](https://github.com/langchain-ai/langchain) and [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) |
| Checked | 8 Oct 2026, langchain 1.4.3, langchain-core 1.6.7, langgraph 1.2.14 (PyPI) |

## What it is for

- Build a tool-calling agent in a few lines with `create_agent`, and switch model providers by changing a model string.
- Connect models to many integrations (chat models, vector stores, document loaders) through separate provider packages.
- Orchestrate workflows that mix deterministic code with LLM-driven steps in one graph (LangGraph).
- Run long-lived agents that persist state, survive failures, and resume where they stopped.
- Pause an agent for human review before a sensitive tool call runs.
- Trace and debug runs with LangSmith, a separate optional product.

## Quick start

1. Install LangChain and the provider package for your model (Python 3.10 or later). Provider integrations are separate packages, for example `langchain-openai` or `langchain-anthropic`.

   ```bash
   pip install -U langchain
   pip install -U langchain-openai
   ```

2. Set the provider API key in your shell (or in a `.env` file that you load with `python-dotenv`). Do not hard-code or commit it.

   ```bash
   export OPENAI_API_KEY="your-api-key"
   ```

3. Build a basic agent. This is the official quickstart example; model strings use the `provider:model-name` format.

   ```python
   from langchain.agents import create_agent

   def get_weather(city: str) -> str:
       """Get weather for a given city."""
       return f"It's always sunny in {city}!"

   agent = create_agent(
       model="openai:gpt-5.5",
       tools=[get_weather],
       system_prompt="You are a helpful assistant",
   )

   result = agent.invoke(
       {"messages": [{"role": "user", "content": "What's the weather in San Francisco?"}]}
   )
   print(result["messages"][-1].content_blocks)
   ```

4. When you need explicit control flow, install LangGraph and build a graph. This hello-world graph uses a mock model node.

   ```bash
   pip install -U langgraph
   ```

   ```python
   from langgraph.graph import StateGraph, MessagesState, START, END

   def mock_llm(state: MessagesState):
       return {"messages": [{"role": "ai", "content": "hello world"}]}

   graph = StateGraph(MessagesState)
   graph.add_node(mock_llm)
   graph.add_edge(START, "mock_llm")
   graph.add_edge("mock_llm", END)
   graph = graph.compile()

   graph.invoke({"messages": [{"role": "user", "content": "hi!"}]})
   ```

## Key concepts

- **Agent (`create_agent`)**: LangChain's agent harness. It combines a model, tools, a system prompt, and optional middleware, and it runs on LangGraph.
- **Tool**: a Python function with a docstring and type hints that the model can choose to call.
- **Middleware**: code that runs around model and tool calls. Built-in examples include `HumanInTheLoopMiddleware` and `PIIMiddleware`.
- **Provider package**: an independent integration package (such as `langchain-openai`) that adds one model provider or service.
- **StateGraph**: LangGraph's graph of nodes (functions) and edges that read and update a shared state, such as `MessagesState`.
- **Checkpointer**: saves graph state at every step. It enables persistence, resume, and human-in-the-loop. `InMemorySaver` is for testing; production uses a database-backed saver.
- **Interrupt**: a pause point where a graph waits for human input before it continues.

## Security notes

- The official security policy centers on least privilege: assume the model can use every permission a credential grants. Use read-only credentials, scope database users to the tables the agent needs, limit file tools to one directory, and run agents in a container.
- Tool output and retrieved documents are untrusted input. A web page, email, or document can carry prompt-injection text that steers later tool calls. Gate destructive tools with `HumanInTheLoopMiddleware` (it requires a checkpointer), and treat guardrail middleware as one layer of defense, not a guarantee.
- Serialization is an attack surface. [CVE-2025-68664](https://nvd.nist.gov/vuln/detail/CVE-2025-68664) (critical): `dumps()` and `dumpd()` did not escape user dictionaries that contained the internal `lc` key, which enabled secret extraction when the data was loaded again. Fixed in langchain-core 1.2.5 and 0.3.81 ([GHSA-c67j-w6g6-q2cm](https://github.com/advisories/GHSA-c67j-w6g6-q2cm)).
- Checkpoint storage deserves the same protection as code. [CVE-2025-64439](https://nvd.nist.gov/vuln/detail/CVE-2025-64439): the default `JsonPlusSerializer` in langgraph-checkpoint could be driven to remote code execution when it deserialized "json" mode payloads. Fixed in langgraph-checkpoint 3.0.0 ([GHSA-wwqv-p2pp-99h5](https://github.com/advisories/GHSA-wwqv-p2pp-99h5)). Never load checkpoints from untrusted sources.
- Both repositories publish advisories often (SSRF, path traversal, template injection, SQL injection in checkpointers). Pin versions, update `langchain-core`, `langgraph`, and every integration package you use, and watch the GitHub advisory feeds.
- LangSmith tracing is off unless you set `LANGSMITH_TRACING=true`. Traces capture execution paths and state, so decide what data may reach the tracing backend before you enable it.
- Background reading in this library: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [LangChain quickstart](https://docs.langchain.com/oss/python/langchain/quickstart)
- [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview)
- [Human-in-the-loop middleware](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)
- [Guardrails](https://docs.langchain.com/oss/python/langchain/guardrails)
- [LangChain security policy](https://docs.langchain.com/oss/python/security-policy)
- [LangChain Academy courses](https://academy.langchain.com/)
