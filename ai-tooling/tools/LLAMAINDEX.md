# LlamaIndex

> In one minute: LlamaIndex is an open-source Python framework for building retrieval-augmented generation (RAG) applications and agents over your own data. It loads documents, splits and embeds them into an index, and lets a model query that index directly or through an agent tool. Teams use it to put private documents in front of an LLM, so data handling and untrusted document content are the main security concerns.

| | |
|---|---|
| Category | App framework (RAG) |
| Maintainer | LlamaIndex (run-llama) |
| License / access | Open source (MIT). The company also sells LlamaParse, a separate hosted document-parsing platform. |
| Official docs | [developers.llamaindex.ai](https://developers.llamaindex.ai/python/framework/) |
| Repository | [run-llama/llama_index](https://github.com/run-llama/llama_index) |
| Checked | 8 Oct 2026, llama-index 0.14.25 (llama-index-core 0.14.25) |

## What it is for

- Question answering over private documents such as PDFs, wikis, and tickets, grounded in retrieved passages.
- Agents that combine a document-search tool with other function tools.
- Structured data extraction from unstructured files into typed Pydantic models.
- Chat over your data with conversation history (chat engines).
- Event-driven, multi-step workflows that coordinate several LLM calls.

## Quick start

1. Install the starter bundle. It includes `llama-index-core`, the OpenAI LLM and embedding integrations, and file readers.

   ```bash
   pip install llama-index
   ```

2. Set your OpenAI API key as an environment variable. By default LlamaIndex uses OpenAI for both generation and embeddings.

   ```bash
   export OPENAI_API_KEY=XXXXX
   ```

3. Put a few text files in a folder named `data` next to your script.

4. Create `starter.py`. This is the RAG agent from the official starter tutorial: it indexes `data/` and gives an agent both a calculator tool and a document-search tool.

   ```python
   from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
   from llama_index.core.agent.workflow import FunctionAgent
   from llama_index.llms.openai import OpenAI
   import asyncio

   # Create a RAG tool using LlamaIndex
   documents = SimpleDirectoryReader("data").load_data()
   index = VectorStoreIndex.from_documents(documents)
   query_engine = index.as_query_engine()

   def multiply(a: float, b: float) -> float:
       """Useful for multiplying two numbers."""
       return a * b

   async def search_documents(query: str) -> str:
       """Useful for answering natural language questions about the documents."""
       response = await query_engine.aquery(query)
       return str(response)

   agent = FunctionAgent(
       tools=[multiply, search_documents],
       llm=OpenAI(model="gpt-4o-mini"),
       system_prompt="""You are a helpful assistant that can perform calculations
       and search through documents to answer questions.""",
   )

   async def main():
       response = await agent.run("Summarize the documents. Also, what's 7 * 8?")
       print(response)

   if __name__ == "__main__":
       asyncio.run(main())
   ```

5. Persist the index so documents are not re-embedded on every run.

   ```python
   index.storage_context.persist("storage")

   from llama_index.core import StorageContext, load_index_from_storage

   storage_context = StorageContext.from_defaults(persist_dir="storage")
   index = load_index_from_storage(storage_context)
   ```

## Key concepts

- **Document and Node**: a `Document` wraps one data source (a PDF, an API response, a database row). A `Node` is a chunk of a document and the atomic unit LlamaIndex indexes.
- **Reader (connector)**: ingests data from a source or format into documents. Hundreds of readers exist as separate integration packages.
- **Index and embeddings**: an index (most often `VectorStoreIndex`) stores vector embeddings of nodes, usually in a vector store, plus metadata.
- **Retriever**: decides how to fetch the most relevant nodes for a query. Routers pick between retrievers.
- **Query engine and chat engine**: end-to-end flows that retrieve context and ask the LLM to answer, once or over a conversation.
- **Node postprocessor and response synthesizer**: filter or re-rank retrieved nodes, then turn them into a final answer.
- **Agent and Workflow**: `FunctionAgent` runs a tool-calling loop; `Workflow` is the event-driven abstraction for orchestrating steps. A `Context` object carries chat history between runs.

## Security notes

- The project's security policy states the library is meant for trusted execution environments. If you expose it through a web API, input validation, authentication, rate limiting, and URL or file-path sanitization are your job. Prompt injection is explicitly treated as an application-layer problem.
- Every indexed document is untrusted input. A poisoned chunk returned by retrieval can carry instructions, and in an agent it can trigger tool calls. Keep retrieval tools read-only, separate them from tools with side effects, and require human approval for actions.
- Never route model output into `eval` or `exec`. [CVE-2024-3098](https://nvd.nist.gov/vuln/detail/CVE-2024-3098) (critical): prompt injection bypassed `safe_eval` in `exec_utils` and led to arbitrary code execution; a related command-injection bypass is [CVE-2024-3271](https://nvd.nist.gov/vuln/detail/CVE-2024-3271). Both fixed in llama-index-core 0.10.24. Run any feature that executes LLM-generated code in a sandbox.
- Validate file paths and URLs before they reach the library. [CVE-2025-6209](https://nvd.nist.gov/vuln/detail/CVE-2025-6209): path traversal in `encode_image` allowed reading arbitrary server files (fixed in 0.12.41). The policy lists SSRF and path traversal from untrusted inputs as out of scope for the project, so the application must filter them.
- The default setup sends document text to OpenAI for embeddings and answers. If data must stay local, use local models, for example Ollama and HuggingFace embeddings, as shown in the official local starter.
- Persisted `storage/` directories and vector stores hold your document chunks. Protect them with the same access controls as the source data.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Starter tutorial (OpenAI)](https://developers.llamaindex.ai/python/framework/getting_started/starter_example/)
- [High-level concepts](https://developers.llamaindex.ai/python/framework/getting_started/concepts/)
- [Introduction to RAG](https://developers.llamaindex.ai/python/framework/understanding/rag/)
- [Building agents](https://developers.llamaindex.ai/python/framework/understanding/agent/)
- [LlamaIndex security policy and threat model](https://github.com/run-llama/llama_index/blob/main/SECURITY.md)
