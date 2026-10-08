# AI and LLM Learning Path

> In one minute: This is a nine-module study path for practitioners and builders who want to understand large language models (LLMs) and build with them: how they work, prompting, retrieval, agents and MCP, fine-tuning, evaluation, running models locally, and the security and governance basics. Each module gives a goal, what to learn, a short list of free resources from official sources, the tool manual pages to try, and the outcome you should reach. The security and governance modules are short on purpose and point to the library's deeper AI security references.

| | |
|---|---|
| Read this when | you are new to building with LLMs; you are moving from security work into AI engineering and want the builder's view; you need a study plan for yourself or a team |
| Start at | Module 1: Foundations: how LLMs work. If you already use LLMs every day, start at Module 3: Building LLM apps and RAG |
| Pairs with | [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md), [AI Labs](/ai-tooling/AI_LABS.md), [AI & LLM Security discipline](/disciplines/ai-llm-security.md) |

> Links were opened and checked against official sources on 2026-10-08. This field changes monthly. If a page has moved or a course has changed, use the vendor's documentation index rather than an old copy.

## How to use this path

- Work through the modules in order. Modules 1 to 4 build on each other; Modules 5 to 9 can be taken in any order after that.
- Pair each module with its lab in [AI Labs](/ai-tooling/AI_LABS.md). The labs run on your own machine with free, open-weight models.
- The resources listed are free to read or watch. A few courses use a paid API for their exercises, and one standard (ISO/IEC 42001) is sold by ISO; those are marked.
- Tool names link to the library's tool manual pages, which cover install, configuration and safe use.

Path at a glance:

1. Foundations: how LLMs work
2. Prompting
3. Building LLM apps and RAG
4. Agents, tools and MCP
5. Fine-tuning and open-weight models
6. Evaluation
7. Running models locally
8. Securing AI systems
9. Governance and risk

## Module 1: Foundations: how LLMs work

**Goal:** Build a working mental model of how an LLM turns text into a prediction, and why that explains both its strengths and its failures.

**What to learn:**

- Tokens: text is split into subword pieces called tokens. Context limits, speed and price are all counted in tokens.
- Embeddings: each token becomes a vector of numbers, and the direction of that vector carries meaning. The same idea powers semantic search in Module 3.
- The transformer: attention lets each token draw information from the others. The model predicts a probability for every possible next token, and generation repeats that step one token at a time.
- Training stages: pretraining on large text collections, then fine-tuning on instructions and human preferences to make a usable assistant.
- Sampling: temperature and related settings change how the next token is picked, which is why the same prompt can return different answers.
- Built-in limits: a fixed context window, a training cutoff date, and hallucination (fluent output that is wrong).

**Resources:**

- [3Blue1Brown: Neural networks](https://www.3blue1brown.com/lessons/neural-networks): free visual lessons. Start with chapter 1, then watch [Transformers, the tech behind LLMs](https://www.3blue1brown.com/lessons/gpt) (chapter 5) and [Attention in transformers, step-by-step](https://www.3blue1brown.com/lessons/attention) (chapter 6).
- [Google Machine Learning Crash Course: Introduction to Large Language Models](https://developers.google.com/machine-learning/crash-course/llm): tokens, language models and the path to transformers, with exercises.
- [Hugging Face LLM Course, chapter 1](https://huggingface.co/learn/llm-course/chapter1/1): free course on transformer models and how to use them with the Transformers library.
- [Andrej Karpathy: Neural Networks: Zero to Hero](https://karpathy.ai/zero-to-hero.html): free video lectures that build a neural network, a language model and a GPT tokenizer from scratch in code. Best if you want the math in working Python.

**Tools to try:** [Ollama](/ai-tooling/tools/OLLAMA.md) to run a small model and watch it generate, and [Hugging Face Hub](/ai-tooling/tools/HUGGING_FACE_HUB.md) to read model cards and compare model sizes.

**You can now:** explain in plain terms how an LLM produces an answer, and why it can be confidently wrong.

## Module 2: Prompting

**Goal:** Write prompts that get consistent output you can check, instead of output that only looks good once.

**What to learn:**

- Be clear and direct: state the task, the audience, the constraints and the output format.
- Separate instructions from data with labeled sections or XML-style tags, so pasted content is not read as instructions. This improves reliability but is not a security control against prompt injection (see Module 8).
- Few-shot examples: show the model one to three examples of the output you want.
- System prompts and roles: set standing behavior once instead of repeating it in every message.
- Structured output: ask for JSON that matches a schema when code will read the answer.
- Iterate against a small set of test inputs, not against your memory of the last good answer. Module 6 turns this into a habit.

**Resources:**

- [Anthropic: Prompt engineering overview](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/overview) and [Prompting best practices](https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices): when prompting is the right fix, and the techniques for current Claude models.
- [Anthropic: Interactive prompt engineering tutorial](https://github.com/anthropics/prompt-eng-interactive-tutorial): nine chapters with exercises. It was written for Claude 3 models, and the exercises call the Claude API, which needs an API key.
- [OpenAI: Prompt engineering guide](https://developers.openai.com/api/docs/guides/prompt-engineering): message roles, formatting, few-shot learning and prompting reasoning models.
- [Google: Gemini API prompt design strategies](https://ai.google.dev/gemini-api/docs/prompting-strategies): clear instructions, examples, context, breaking tasks into steps, and model parameters.

**Tools to try:** [Anthropic Claude API](/ai-tooling/tools/ANTHROPIC_CLAUDE_API.md), [OpenAI API](/ai-tooling/tools/OPENAI_API.md), [Google Gemini API](/ai-tooling/tools/GOOGLE_GEMINI_API.md), [Mistral AI](/ai-tooling/tools/MISTRAL_AI.md), [DSPy](/ai-tooling/tools/DSPY.md) for treating prompts as code, and [Ollama](/ai-tooling/tools/OLLAMA.md) to practice for free on a local model.

**You can now:** turn a vague request into a prompt with a defined output format and a handful of test inputs that show whether it works.

## Module 3: Building LLM apps and RAG

**Goal:** Connect a model to your own documents so its answers are grounded in sources you control and can cite.

**What to learn:**

- When to use retrieval-augmented generation (RAG): the facts change often, are private, or must be cited.
- The pipeline: load documents, split them into chunks, embed the chunks, store them, retrieve the closest chunks for a question, then generate an answer with those chunks in the prompt.
- Chunking and metadata: chunk size and overlap affect what gets found; keep the source path with every chunk so answers can cite it.
- Search methods: vector search for meaning, keyword search (BM25) for exact terms such as error codes, and reranking to put the best chunks first.
- Measure retrieval and generation separately: first check that the right chunk was retrieved, then judge the answer.
- Access control: retrieval must respect who is allowed to read each document, or the app will leak it.

**Resources:**

- [Chroma: Getting started](https://docs.trychroma.com/docs/overview/getting-started): create a collection, add documents and query them in a few lines of Python.
- [LlamaIndex: Introduction to RAG](https://developers.llamaindex.ai/python/framework/understanding/rag/): the five stages of a RAG system (loading, indexing, storing, querying, evaluation).
- [Hugging Face Cookbook: Advanced RAG](https://huggingface.co/learn/cookbook/advanced_rag): a full notebook covering chunking, embeddings, a reader model and reranking.
- [Anthropic: Introducing Contextual Retrieval](https://www.anthropic.com/engineering/contextual-retrieval): how adding context to chunks before embedding, plus BM25 and reranking, reduces retrieval failures.
- [Anthropic Academy: Building with the Claude API](https://anthropic.skilljar.com/claude-with-the-anthropic-api): free course covering API basics, RAG, tool use, MCP and evals. The exercises call the Claude API, which needs an API key.

**Tools to try:** vector stores [Chroma](/ai-tooling/tools/CHROMA.md), [Qdrant](/ai-tooling/tools/QDRANT.md), [pgvector](/ai-tooling/tools/PGVECTOR.md) and [FAISS](/ai-tooling/tools/FAISS.md); frameworks [LlamaIndex](/ai-tooling/tools/LLAMAINDEX.md) and [LangChain and LangGraph](/ai-tooling/tools/LANGCHAIN_LANGGRAPH.md); model gateways [LiteLLM](/ai-tooling/tools/LITELLM.md) and [OpenRouter](/ai-tooling/tools/OPENROUTER.md); low-code builders [Dify](/ai-tooling/tools/DIFY.md), [Flowise](/ai-tooling/tools/FLOWISE.md), [Langflow](/ai-tooling/tools/LANGFLOW.md) and [n8n](/ai-tooling/tools/N8N.md).

**You can now:** build a small question-answering tool over your own notes that cites the file each answer came from. Lab 2 walks through it.

## Module 4: Agents, tools and MCP

**Goal:** Understand how a model calls tools in a loop, and how the Model Context Protocol (MCP) standardizes the connection between AI applications and tools.

**What to learn:**

- Tool calling: the model emits a structured request, your code runs the tool, and the result goes back to the model as input.
- Workflows versus agents: workflows follow code paths you define (prompt chaining, routing, parallelization, orchestrator-workers, evaluator-optimizer); agents let the model direct its own steps. Start with the simplest pattern that works.
- MCP roles: a host (the AI application) creates one MCP client per MCP server. Servers expose tools (actions), resources (data) and prompts (templates).
- MCP transports: stdio for local servers that the host launches as a child process, and Streamable HTTP for remote servers.
- Agent SDKs and coding agents: the same tool loop, packaged with file access, shell access and permission controls.
- Risk grows with autonomy: give tools the least privilege they need, require human approval for irreversible actions, and treat every tool result as untrusted input.

**Resources:**

- [Anthropic: Building effective agents](https://www.anthropic.com/engineering/building-effective-agents): workflow and agent patterns, and when to use each.
- [Hugging Face AI Agents Course](https://huggingface.co/learn/agents-course/unit0/introduction): free course on agent fundamentals with smolagents, LangGraph and LlamaIndex.
- [Model Context Protocol: What is MCP](https://modelcontextprotocol.io/docs/getting-started/intro) and the [Architecture overview](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture): official docs. The current protocol version is 2026-07-28; check the version selector when you read older tutorials.
- [Hugging Face MCP Course](https://huggingface.co/learn/mcp-course): free course from MCP fundamentals to a deployed application.
- [Anthropic Academy: Introduction to Model Context Protocol](https://anthropic.skilljar.com/introduction-to-model-context-protocol): free course on building MCP servers and clients in Python.

**Tools to try:** [Model Context Protocol](/ai-tooling/tools/MODEL_CONTEXT_PROTOCOL.md), [Agent2Agent (A2A)](/ai-tooling/tools/AGENT2AGENT_A2A.md), agent SDKs [Claude Agent SDK](/ai-tooling/tools/CLAUDE_AGENT_SDK.md), [OpenAI Agents SDK](/ai-tooling/tools/OPENAI_AGENTS_SDK.md), [Microsoft Agent Framework](/ai-tooling/tools/MICROSOFT_AGENT_FRAMEWORK.md), [CrewAI](/ai-tooling/tools/CREWAI.md) and [LangChain and LangGraph](/ai-tooling/tools/LANGCHAIN_LANGGRAPH.md); coding agents [Claude Code](/ai-tooling/tools/CLAUDE_CODE.md), [GitHub Copilot](/ai-tooling/tools/GITHUB_COPILOT.md), [OpenAI Codex CLI](/ai-tooling/tools/OPENAI_CODEX_CLI.md), [Gemini CLI](/ai-tooling/tools/GEMINI_CLI.md), [Cursor](/ai-tooling/tools/CURSOR.md) and [Aider](/ai-tooling/tools/AIDER.md).

**You can now:** build and test a small MCP server, and explain exactly what each of its tools lets a model do. Lab 3 walks through it.

## Module 5: Fine-tuning and open-weight models

**Goal:** Decide when changing a model's weights is worth it, and work with open-weight models without importing license or supply-chain risk.

**What to learn:**

- Open-weight is not the same as open source. Read the license and acceptable use terms on the model card before you build on a model.
- Prompting, RAG or fine-tuning: fine-tune for a consistent format, style or narrow skill; use RAG for facts that change; try prompting first because it is cheapest.
- Supervised fine-tuning (SFT) and chat templates: training examples must use the same chat template the model expects at inference time.
- Parameter-efficient fine-tuning: methods such as LoRA train small adapter weights instead of the whole model, which cuts memory and storage cost.
- Preference tuning: methods such as DPO train the model toward preferred answers using pairs of better and worse responses.
- Model files and supply chain: prefer safetensors files over older serialization formats that can run code when a model is loaded, scan model files from untrusted sources before loading them, and record where every set of weights came from. The library's [AI Infrastructure and MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md) reference covers unsafe model files in depth.

**Resources:**

- [Hugging Face LLM Course, chapter 11: Supervised fine-tuning](https://huggingface.co/learn/llm-course/chapter11/1): chat templates, SFT, LoRA and evaluation.
- [Hugging Face smol course](https://github.com/huggingface/smol-course): free, hands-on course on instruction tuning, evaluation and preference alignment with small models that run on modest hardware.
- [Hugging Face PEFT documentation](https://huggingface.co/docs/peft/index): parameter-efficient fine-tuning methods and a quicktour.
- [Hugging Face TRL documentation](https://huggingface.co/docs/trl/index): trainers for SFT, DPO, GRPO and reward modeling.
- [Hugging Face Hub: Model cards](https://huggingface.co/docs/hub/model-cards): what a model card should state, including intended uses, limitations, training data, evaluation results and license.

**Tools to try:** [Hugging Face Hub](/ai-tooling/tools/HUGGING_FACE_HUB.md), [Meta Llama](/ai-tooling/tools/META_LLAMA.md), [Mistral AI](/ai-tooling/tools/MISTRAL_AI.md), [ModelScan](/ai-tooling/tools/MODELSCAN.md) to scan model files for unsafe code before loading, and [Ollama](/ai-tooling/tools/OLLAMA.md) to import a GGUF or safetensors model and run it locally.

**You can now:** choose between prompting, RAG and fine-tuning for a use case, and vet an open-weight model's license and file format before you use it.

## Module 6: Evaluation

**Goal:** Measure whether an LLM feature works, and catch regressions when a prompt or model changes.

**What to learn:**

- Define success criteria first. They should be specific and measurable, such as "names the affected version in 95 percent of test cases".
- Build a test set with normal cases, edge cases and known past failures. Volume and automation beat a few hand-checked examples.
- Grading methods: code-based checks (exact match, contains, valid JSON, length), model-graded checks (another model scores the output against a rubric), and human review of a sample.
- Run evals on every prompt, model or retrieval change, the way you run unit tests.
- RAG and agent evals: score retrieval, tool choice and the final answer separately, and keep traces so you can see where a run went wrong.
- Model graders make mistakes too. Check a sample of their scores by hand, and use a different model as the grader where you can.

**Resources:**

- [Anthropic: Define success criteria and build evaluations](https://platform.claude.com/docs/en/test-and-evaluate/develop-tests): writing success criteria, eval design principles and worked examples with code-based and model-based grading.
- [promptfoo: Introduction](https://www.promptfoo.dev/docs/intro/): an open-source CLI for running prompt evals and red teaming, which runs on your machine.
- [Inspect](https://inspect.aisi.org.uk/): an open-source evaluation framework from the UK AI Security Institute and Meridian Labs, with a log viewer and support for local models.
- [Hugging Face AI Agents Course, bonus unit 2: Observability and evaluation](https://huggingface.co/learn/agents-course/bonus-unit2/introduction): tracing, cost and latency monitoring, LLM-as-a-judge, and offline benchmark tests for agents.

**Tools to try:** [promptfoo](/ai-tooling/tools/PROMPTFOO.md), [Inspect AI](/ai-tooling/tools/INSPECT_AI.md), [DeepEval](/ai-tooling/tools/DEEPEVAL.md), and tracing tools [Langfuse](/ai-tooling/tools/LANGFUSE.md) and [Arize Phoenix](/ai-tooling/tools/ARIZE_PHOENIX.md).

**You can now:** write an eval suite that runs two prompts against the same tests and shows which one passes more often. Lab 4 walks through it.

## Module 7: Running models locally

**Goal:** Run open-weight models on your own hardware for privacy, cost control and offline work.

**What to learn:**

- Size and memory: parameter count and quantization decide how much disk and memory a model needs. For example, Ollama's `llama3.2:1b` is a 1.3 GB download, while larger models need far more memory or a GPU.
- Quantization formats: GGUF files carry quantized weights plus metadata for llama.cpp-based runtimes. Lower-bit files are smaller and faster but can lose quality.
- Runtimes: Ollama and LM Studio for desktops, llama.cpp as a lightweight engine, and vLLM for high-throughput serving on Linux servers with supported accelerators.
- OpenAI-compatible endpoints: most local runtimes offer one, so the same client code can target a local or a hosted model.
- Exposure: Ollama binds to 127.0.0.1 port 11434 by default, and its local API does not require authentication. Keep it on localhost unless you put an authenticating proxy in front of it.

**Resources:**

- [Ollama: Quickstart](https://docs.ollama.com/quickstart): install, pull and run a model, and call the local API.
- [Ollama: FAQ](https://docs.ollama.com/faq): where models are stored, how to change the bind address, how to put Ollama behind a proxy, and how to turn off cloud features for local-only use.
- [llama.cpp](https://github.com/ggml-org/llama.cpp): the C/C++ inference engine behind many local runtimes, with a CLI and an OpenAI-compatible server.
- [Hugging Face Hub: GGUF](https://huggingface.co/docs/hub/gguf): what GGUF is, how to find GGUF models, and what the quantization types mean.
- [vLLM: Quickstart](https://docs.vllm.ai/en/latest/getting_started/quickstart/): installing vLLM and serving a model through an OpenAI-compatible server on Linux.

**Tools to try:** [Ollama](/ai-tooling/tools/OLLAMA.md), [LM Studio](/ai-tooling/tools/LM_STUDIO.md), [llama.cpp](/ai-tooling/tools/LLAMA_CPP.md) and [vLLM](/ai-tooling/tools/VLLM.md).

**You can now:** run a model locally, call it through a local API, and explain the tradeoff between model size, quantization and output quality. Lab 1 walks through it.

## Module 8: Securing AI systems

**Goal:** Know the main risks to LLM applications and agents, and where this library covers each one in depth.

**What to learn:**

- The OWASP Top 10 for LLM Applications (2025): prompt injection, sensitive information disclosure, supply chain, data and model poisoning, improper output handling, excessive agency, system prompt leakage, vector and embedding weaknesses, misinformation, and unbounded consumption.
- Agent risks: tools with too much privilege, actions taken without approval, and instructions hidden in content the agent reads. OWASP now publishes a separate Top 10 for agentic applications.
- MCP risks: untrusted or malicious servers, token passthrough, and compromise of local servers that run with your privileges.
- Adversary behavior against AI systems is cataloged in MITRE ATLAS; NIST AI 100-2 gives a shared vocabulary for attacks and mitigations.
- Scanners (garak, PyRIT) and guardrails (Llama Guard, NeMo Guardrails) are layers of defense, not complete fixes. Combine them with least privilege, output handling and monitoring.

**Go deeper in this library:**

- [AI and LLM Security Reference](/AI_SECURITY_REFERENCE.md): OWASP LLM Top 10, prompt injection in depth, and hardening patterns.
- [AI and MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md): the Model Context Protocol and enterprise AI security controls.
- [Agentic AI Attack Reference](/AGENTIC_AI_ATTACK_REFERENCE.md): how swarms of autonomous agents run intrusions, mapped to ATT&CK and ATLAS, with the OWASP agentic Top 10.
- [AI Infrastructure and MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md): model registries and provenance, unsafe model deserialization, data and RAG-corpus poisoning, vector stores, the ML build pipeline, and inference servers.
- [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md): how attackers use AI to write exploits at scale, and the defensive playbook.
- [Deepfake and Synthetic-Media Defense](/DEEPFAKE_DEFENSE_REFERENCE.md): voice clones and deepfaked calls used for fraud, and the process controls that stop them.
- [MITRE ATLAS Reference](/ATLAS_REFERENCE.md): the library's guide to ATLAS tactics and techniques.
- [AI Threats in 2026 case study](/case-studies/AI_THREATS_2026.md): how AI changed real attacks through 2026, with sourced cases.
- [AI & LLM Security discipline](/disciplines/ai-llm-security.md): the career and study view of this field.

**Resources:**

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/), from the [OWASP GenAI Security Project](https://genai.owasp.org/).
- [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): risks specific to systems that plan and act.
- [MITRE ATLAS](https://atlas.mitre.org/): the knowledge base of adversary tactics and techniques against AI systems.
- [NIST AI 100-2 E2025: Adversarial Machine Learning](https://csrc.nist.gov/pubs/ai/100/2/e2025/final): taxonomy and terminology of attacks and mitigations for predictive and generative AI.
- [MCP: Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices): official guidance on confused deputy, token passthrough, SSRF and local server compromise.

**Tools to try:** scanners [garak](/ai-tooling/tools/GARAK.md), [PyRIT](/ai-tooling/tools/PYRIT.md) and [promptfoo](/ai-tooling/tools/PROMPTFOO.md); guardrails [Llama Guard](/ai-tooling/tools/LLAMA_GUARD.md), [NeMo Guardrails](/ai-tooling/tools/NEMO_GUARDRAILS.md) and [Guardrails AI](/ai-tooling/tools/GUARDRAILS_AI.md); model file scanning [ModelScan](/ai-tooling/tools/MODELSCAN.md). Run scanners only against systems you own or are authorized to test.

**You can now:** name the main risks to an LLM application, find the library page that covers each, and run a first authorized scan and guardrail on a local model. Labs 5 and 6 walk through it.

## Module 9: Governance and risk

**Goal:** Place AI work inside a risk management and compliance program, so each system has an owner, a known purpose, and evidence that it was tested.

**What to learn:**

- NIST AI Risk Management Framework (AI RMF 1.0): voluntary guidance organized into four functions, Govern, Map, Measure and Manage. The Playbook suggests actions for each outcome. NIST states that AI RMF 1.0 is being revised, so check for the current version.
- NIST AI 600-1, the Generative AI Profile: applies the AI RMF to risks that are unique to or made worse by generative AI.
- ISO/IEC 42001:2023: requirements for establishing, implementing, maintaining and continually improving an AI management system.
- EU AI Act (Regulation (EU) 2024/1689): a risk-based law with four tiers, from banned practices to minimal risk. Some high-risk deadlines were moved in 2026, so read dates from a current source.
- Practical artifacts: an inventory of AI systems, an intended-use statement and risk assessment for each, model and data provenance, eval results, and an incident process that covers AI failures.

**Resources:**

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework): the framework, its status, and related NIST resources.
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/): suggested actions for each function, downloadable as PDF, CSV, Excel or JSON.
- [NIST AI 600-1: Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1): the generative AI companion to the AI RMF (PDF).
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001): the official overview page. The standard itself is sold by ISO; the overview is free to read.
- [European Commission: AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai): risk tiers and application dates, with the full legal text on [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1689/oj).

**In this library:** the [Global Cyber-Regulation and Breach-Notification Reference](/REGULATORY_LANDSCAPE_REFERENCE.md) tracks the EU AI Act alongside other regimes, with sourced dates.

**Tools to try:** no tool replaces a governance process, but eval and tracing tools produce the evidence that governance asks for: [promptfoo](/ai-tooling/tools/PROMPTFOO.md), [Inspect AI](/ai-tooling/tools/INSPECT_AI.md) and [Langfuse](/ai-tooling/tools/LANGFUSE.md).

**You can now:** map an AI use case to the four AI RMF functions and list the evidence an auditor would ask to see.

## Where to go next

- Practice each module with the hands-on exercises in [AI Labs](/ai-tooling/AI_LABS.md).
- Compare tools by category in the [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md).
- Move into AI security work through the [AI & LLM Security discipline](/disciplines/ai-llm-security.md).
