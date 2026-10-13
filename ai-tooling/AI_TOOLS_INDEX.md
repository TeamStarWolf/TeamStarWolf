# AI Tools and LLMs Index

> In one minute: 46 AI tools and model platforms that practitioners and builders use in 2026, grouped by what they do. Each row links the tool's official documentation and repository and a one-page manual in this library: what the tool is for, how to start, its key concepts, and its security risks. Versions and facts were checked against official sources on 8 October 2026; AI tooling changes fast, so confirm the current release before relying on a detail.

| | |
|---|---|
| Read this when | choosing an AI tool or model platform, reviewing one a team wants to adopt, or looking for the official docs, repository and security notes for a tool in one place |
| Start at | the group that matches the job, then open the tool's manual |
| Pairs with | [AI Tooling overview](/ai-tooling/README.md), [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md), [AI Labs](/ai-tooling/AI_LABS.md), [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md) |

Tools are listed for reference, not endorsed. Licenses are summarized; read each project's license before use.

## Model platforms and hubs

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Anthropic Claude API | Hosted API and SDKs for Anthropic's Claude models: messages, tool use, server tools, MCP connector | Commercial API, usage-based; SDKs open source (Python SDK MIT) | [Docs](https://platform.claude.com/docs/en/intro) | [anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) | [Manual](/ai-tooling/tools/ANTHROPIC_CLAUDE_API.md) |
| Google Gemini API | Google's hosted API and Gen AI SDK for Gemini models: multimodal input, function calling, Interactions API | Commercial API with a free tier; Python SDK Apache-2.0 | [Docs](https://ai.google.dev/gemini-api/docs) | [googleapis/python-genai](https://github.com/googleapis/python-genai) | [Manual](/ai-tooling/tools/GOOGLE_GEMINI_API.md) |
| Hugging Face Hub | Hosted hub for models, datasets, and Spaces, with huggingface_hub and transformers libraries for Python | Hosted platform, free sign-up and paid plans; libraries Apache-2.0 | [Docs](https://huggingface.co/docs/hub/index) | [huggingface/huggingface_hub](https://github.com/huggingface/huggingface_hub) | [Manual](/ai-tooling/tools/HUGGING_FACE_HUB.md) |
| Meta Llama | Meta's open-weight Llama model family (Llama 4, 3.x, 2) with gated downloads and Llama Guard tooling | Open weights under Meta Llama community licenses; gated download | [Docs](https://dev.meta.ai/llama/) | [meta-llama/llama-models](https://github.com/meta-llama/llama-models) | [Manual](/ai-tooling/tools/META_LLAMA.md) |
| Mistral AI | Mistral's hosted API and Studio console plus open-weight models for chat, OCR, audio, and moderation | Commercial API with a free mode; open-weight models under varied licenses | [Docs](https://docs.mistral.ai/) | [mistralai/client-python](https://github.com/mistralai/client-python) | [Manual](/ai-tooling/tools/MISTRAL_AI.md) |
| OpenAI API | Hosted API and SDKs for OpenAI GPT models: Responses API, function calling, speech, realtime, images | Commercial API, free usage tier in allowed regions; Python SDK Apache-2.0 | [Docs](https://developers.openai.com/api/docs) | [openai/openai-python](https://github.com/openai/openai-python) | [Manual](/ai-tooling/tools/OPENAI_API.md) |

## LLM gateways

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| LiteLLM | Open-source Python SDK and self-hosted AI gateway calling 100+ LLM providers in OpenAI format | Open source (MIT), enterprise directory separately licensed | [Docs](https://docs.litellm.ai/docs/) | [BerriAI/litellm](https://github.com/BerriAI/litellm) | [Manual](/ai-tooling/tools/LITELLM.md) |
| OpenRouter | Hosted gateway exposing hundreds of models via one OpenAI-compatible API, with routing and fallbacks | Commercial hosted service, prepaid credits, free model variants; Python SDK Apache-2.0 | [Docs](https://openrouter.ai/docs/quickstart) | [OpenRouterTeam/python-sdk](https://github.com/OpenRouterTeam/python-sdk) | [Manual](/ai-tooling/tools/OPENROUTER.md) |

## Local inference

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| llama.cpp | C/C++ engine that runs quantized GGUF models on CPUs and GPUs, with a CLI and an OpenAI-compatible server | Open source (MIT) | [Docs](https://github.com/ggml-org/llama.cpp/tree/master/docs) | [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) | [Manual](/ai-tooling/tools/LLAMA_CPP.md) |
| LM Studio | Desktop app and headless daemon for running local LLMs with chat, RAG, MCP and a local API | Proprietary app; lms CLI and SDKs MIT | [Docs](https://lmstudio.ai/docs/app) | Closed source | [Manual](/ai-tooling/tools/LM_STUDIO.md) |
| Ollama | Downloads and runs open-weight LLMs locally with a CLI and an unauthenticated HTTP API on port 11434 | Open source (MIT) | [Docs](https://docs.ollama.com/quickstart) | [ollama/ollama](https://github.com/ollama/ollama) | [Manual](/ai-tooling/tools/OLLAMA.md) |
| vLLM | High-throughput GPU inference engine and OpenAI-compatible server for self-hosted LLMs | Open source (Apache-2.0) | [Docs](https://docs.vllm.ai/en/stable/) | [vllm-project/vllm](https://github.com/vllm-project/vllm) | [Manual](/ai-tooling/tools/VLLM.md) |

## Vector databases and search

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Chroma | Open-source vector database for storing documents and embeddings and running similarity search for RAG | Open source (Apache-2.0) | [Docs](https://docs.trychroma.com/docs/overview/getting-started) | [chroma-core/chroma](https://github.com/chroma-core/chroma) | [Manual](/ai-tooling/tools/CHROMA.md) |
| FAISS | Meta's C++/Python library for fast dense-vector similarity search and clustering on CPU and GPU | Open source (MIT) | [Docs](https://faiss.ai/) | [facebookresearch/faiss](https://github.com/facebookresearch/faiss) | [Manual](/ai-tooling/tools/FAISS.md) |
| pgvector | PostgreSQL extension adding vector types, distance operators and HNSW/IVFFlat indexes | Open source (PostgreSQL License) | [Docs](https://github.com/pgvector/pgvector) | [pgvector/pgvector](https://github.com/pgvector/pgvector) | [Manual](/ai-tooling/tools/PGVECTOR.md) |
| Qdrant | Rust vector database with REST and gRPC APIs, payload filtering, API keys and JWT RBAC (auth off by default) | Open source (Apache-2.0) | [Docs](https://qdrant.tech/documentation/) | [qdrant/qdrant](https://github.com/qdrant/qdrant) | [Manual](/ai-tooling/tools/QDRANT.md) |

## Agent and app frameworks

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Claude Agent SDK | Anthropic library that runs the Claude Code agent loop and built-in tools inside your Python or TypeScript app | SDK source MIT; use under Anthropic Commercial Terms | [Docs](https://code.claude.com/docs/en/agent-sdk/overview) | [anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python) | [Manual](/ai-tooling/tools/CLAUDE_AGENT_SDK.md) |
| CrewAI | Python framework that orchestrates role-based agent crews inside stateful, event-driven Flows | Open source (MIT) | [Docs](https://docs.crewai.com/en/introduction) | [crewAIInc/crewAI](https://github.com/crewAIInc/crewAI) | [Manual](/ai-tooling/tools/CREWAI.md) |
| DSPy | Framework for programming LLMs with typed signatures and modules, then optimizing prompts against a metric | Open source (MIT) | [Docs](https://dspy.ai/) | [stanfordnlp/dspy](https://github.com/stanfordnlp/dspy) | [Manual](/ai-tooling/tools/DSPY.md) |
| LangChain and LangGraph | Framework and graph runtime for building tool-calling, stateful LLM agents with persistence and human review | Open source (MIT) | [Docs](https://docs.langchain.com/oss/python/langchain/overview) | [langchain-ai/langchain](https://github.com/langchain-ai/langchain) | [Manual](/ai-tooling/tools/LANGCHAIN_LANGGRAPH.md) |
| LlamaIndex | Python framework for RAG and agents: load, index, and query your own documents with LLMs | Open source (MIT) | [Docs](https://developers.llamaindex.ai/python/framework/) | [run-llama/llama_index](https://github.com/run-llama/llama_index) | [Manual](/ai-tooling/tools/LLAMAINDEX.md) |
| Microsoft Agent Framework | Microsoft successor to Semantic Kernel and AutoGen for agents and graph-based multi-agent workflows | Open source (MIT) | [Docs](https://learn.microsoft.com/en-us/agent-framework/overview/) | [microsoft/agent-framework](https://github.com/microsoft/agent-framework) | [Manual](/ai-tooling/tools/MICROSOFT_AGENT_FRAMEWORK.md) |
| OpenAI Agents SDK | Lightweight Python framework for agents with tools, handoffs, guardrails, sessions, and built-in tracing | Open source (MIT) | [Docs](https://openai.github.io/openai-agents-python/) | [openai/openai-agents-python](https://github.com/openai/openai-agents-python) | [Manual](/ai-tooling/tools/OPENAI_AGENTS_SDK.md) |

## Protocols

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Agent2Agent Protocol (A2A) | Open protocol for agents from different vendors to discover each other and collaborate on stateful tasks | Open source (Apache-2.0) | [Docs](https://a2a-protocol.org/latest/) | [a2aproject/A2A](https://github.com/a2aproject/A2A) | [Manual](/ai-tooling/tools/AGENT2AGENT_A2A.md) |
| Model Context Protocol (MCP) | Open protocol that connects AI hosts to external tools, resources, and prompts through MCP servers | Open spec; SDKs open source | [Docs](https://modelcontextprotocol.io/specification/latest) | [modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol) | [Manual](/ai-tooling/tools/MODEL_CONTEXT_PROTOCOL.md) |

## Coding agents

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Aider | Open-source terminal AI pair programmer that edits code in a git repo with many model providers | Open source (Apache-2.0) | [Docs](https://aider.chat/docs/) | [Aider-AI/aider](https://github.com/Aider-AI/aider) | [Manual](/ai-tooling/tools/AIDER.md) |
| Claude Code | Anthropic's agentic coding tool that reads code, edits files, and runs commands from terminal, IDE, or web | Commercial (proprietary); needs a Claude subscription, Console account, or supported cloud provider | [Docs](https://code.claude.com/docs/en/overview) | [anthropics/claude-code](https://github.com/anthropics/claude-code) | [Manual](/ai-tooling/tools/CLAUDE_CODE.md) |
| Cursor | AI code editor with an agent that plans and makes multi-file changes and runs terminal commands | Commercial, closed source; free tier (Hobby plan) | [Docs](https://cursor.com/docs) | Closed source | [Manual](/ai-tooling/tools/CURSOR.md) |
| Gemini CLI | Google's open-source terminal AI agent for coding, file tasks, and automation using Gemini models | Open source (Apache-2.0) | [Docs](https://geminicli.com/docs/) | [google-gemini/gemini-cli](https://github.com/google-gemini/gemini-cli) | [Manual](/ai-tooling/tools/GEMINI_CLI.md) |
| GitHub Copilot | GitHub's AI coding assistant: IDE suggestions and chat, agent mode, a terminal CLI, and a cloud PR agent | Commercial, free tier (Copilot Free) | [Docs](https://docs.github.com/en/copilot) | [github/copilot-cli](https://github.com/github/copilot-cli) | [Manual](/ai-tooling/tools/GITHUB_COPILOT.md) |
| OpenAI Codex CLI | OpenAI's open-source terminal coding agent that edits and runs code inside an OS-level sandbox | Open source (Apache-2.0) | [Docs](https://learn.chatgpt.com/docs) | [openai/codex](https://github.com/openai/codex) | [Manual](/ai-tooling/tools/OPENAI_CODEX_CLI.md) |

## Workflow builders

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Dify | Platform for building chatbots, agents, and AI workflows visually and publishing them as apps or APIs | Dify Open Source License (Apache 2.0 with added conditions) | [Docs](https://docs.dify.ai/) | [langgenius/dify](https://github.com/langgenius/dify) | [Manual](/ai-tooling/tools/DIFY.md) |
| Flowise | Open-source visual builder for AI agents and LLM flows; archived Aug 2026, end of life 31 Aug 2026 | Open source (Apache-2.0), enterprise files commercial | [Docs](https://docs.flowiseai.com/) | [FlowiseAI/Flowise](https://github.com/FlowiseAI/Flowise) | [Manual](/ai-tooling/tools/FLOWISE.md) |
| Langflow | Open-source visual builder for AI agents and workflows, served via API or as MCP servers | Open source (MIT) | [Docs](https://docs.langflow.org/) | [langflow-ai/langflow](https://github.com/langflow-ai/langflow) | [Manual](/ai-tooling/tools/LANGFLOW.md) |
| n8n | Fair-code workflow automation platform connecting apps, APIs, and AI agents with a visual node editor | Fair-code, source available (Sustainable Use License) | [Docs](https://docs.n8n.io/) | [n8n-io/n8n](https://github.com/n8n-io/n8n) | [Manual](/ai-tooling/tools/N8N.md) |

## Evaluation

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| DeepEval | Pytest-style framework that scores LLM, RAG, and agent outputs with LLM-judge and safety metrics | Open source (Apache-2.0) | [Docs](https://deepeval.com/docs/getting-started) | [confident-ai/deepeval](https://github.com/confident-ai/deepeval) | [Manual](/ai-tooling/tools/DEEPEVAL.md) |
| Inspect | Python framework for LLM and agent evaluations with sandboxed tools, scorers, and a log viewer | Open source (MIT) | [Docs](https://inspect.aisi.org.uk/) | [UKGovernmentBEIS/inspect_ai](https://github.com/UKGovernmentBEIS/inspect_ai) | [Manual](/ai-tooling/tools/INSPECT_AI.md) |
| promptfoo | CLI and library to evaluate prompts and models with test cases and red team LLM apps you own | Open source (MIT) | [Docs](https://www.promptfoo.dev/docs/intro/) | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | [Manual](/ai-tooling/tools/PROMPTFOO.md) |

## Observability

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Arize Phoenix | OpenTelemetry-based tracing and LLM evaluation platform you can run locally or self-host | Elastic License 2.0 (server); OTel packages Apache-2.0 | [Docs](https://arize.com/docs/phoenix) | [Arize-ai/phoenix](https://github.com/Arize-ai/phoenix) | [Manual](/ai-tooling/tools/ARIZE_PHOENIX.md) |
| Langfuse | Open source tracing, evals, and prompt management platform for LLM apps; cloud or self-hosted | Open source (MIT, except ee folders) | [Docs](https://langfuse.com/docs) | [langfuse/langfuse](https://github.com/langfuse/langfuse) | [Manual](/ai-tooling/tools/LANGFUSE.md) |

## Guardrails

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| Guardrails AI | Python framework that wraps LLM calls in validator-based input/output guards and structured output | Open source (Apache-2.0) | [Docs](https://guardrailsai.com/guardrails/docs) | [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) | [Manual](/ai-tooling/tools/GUARDRAILS_AI.md) |
| Llama Guard and Prompt Guard | Meta open-weight safety classifiers: Llama Guard 4 moderation and Prompt Guard 2 injection detection | Llama 4 Community License (open weights) | [Docs](https://dev.meta.ai/llama/llama-protections/) | [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) | [Manual](/ai-tooling/tools/LLAMA_GUARD.md) |
| NeMo Guardrails | NVIDIA library for programmable input, dialog, retrieval, execution, and output rails around LLMs | Open source (Apache-2.0) | [Docs](https://docs.nvidia.com/nemo/guardrails) | [NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | [Manual](/ai-tooling/tools/NEMO_GUARDRAILS.md) |

## AI red teaming and model scanning

| Tool | What it does | License or access | Official docs | Repository | Manual |
|---|---|---|---|---|---|
| garak | NVIDIA's CLI scanner that probes LLMs you are authorized to test for injection, leakage, toxicity | Open source (Apache-2.0) | [Docs](https://docs.garak.ai/) | [NVIDIA/garak](https://github.com/NVIDIA/garak) | [Manual](/ai-tooling/tools/GARAK.md) |
| ModelScan | Static scanner that flags unsafe code in serialized model files (H5, SavedModel and more) before loading | Open source (Apache-2.0) | [Docs](https://github.com/protectai/modelscan) | [protectai/modelscan](https://github.com/protectai/modelscan) | [Manual](/ai-tooling/tools/MODELSCAN.md) |
| PyRIT | Microsoft framework for automated red teaming of generative AI targets: attacks, converters, scorers | Open source (MIT) | [Docs](https://microsoft.github.io/PyRIT/) | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | [Manual](/ai-tooling/tools/PYRIT.md) |

## Related

- Security of AI systems: [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md)
- How these tools are attacked in practice: [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md)
