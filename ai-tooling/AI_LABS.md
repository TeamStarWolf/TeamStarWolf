# AI Labs

> In one minute: Six hands-on labs that run entirely on your own machine: run an open-weight model with Ollama, build a small RAG over Markdown with Chroma, write a minimal MCP server, evaluate prompts with promptfoo, scan your own local model with garak, and add an input and output guardrail with Llama Guard. Every lab targets only software you run yourself, and every command and API call was checked against the tool's official documentation. Each lab lists its goal, prerequisites, steps, a check, safety notes and the matching tool manual pages.

| | |
|---|---|
| Read this when | you want to practice the learning path with working code; you need a safe local setup for teaching, a workshop or a lunch-and-learn; you want a first, authorized look at how LLM scanners and guardrails behave |
| Start at | Lab 1: Run an open-weight model locally with Ollama. Every other lab builds on it |
| Pairs with | [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md), [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md) |

> Commands and code were checked against official documentation on 2026-10-08. Versions checked: Ollama Python library 0.6.3, chromadb 1.5.9, MCP Python SDK 2.3.0, MCP Inspector 2.10.1, promptfoo 0.124.0, garak 0.17.0. The labs were not run end to end before publication. If a newer release changes a command, or a step fails, the tool's own docs win.

## Before you start

Ground rules for every lab:

- Keep it local. Every lab talks to software on your own machine at `localhost` or `127.0.0.1`. None of them needs a cloud account or an API key.
- Test only what you own. Labs 5 and 6 send adversarial or unsafe test content to a model. Run them only against your own local model, never against a third-party service.
- Use fake data. The sample notes in these labs are invented. Do not load real secrets, credentials, customer data or personal data into a lab.
- Use one folder per lab, and a separate Python virtual environment where a lab asks for one.

What you need:

- A laptop or desktop running Windows 10 22H2 or newer, macOS 14 Sonoma or newer, or Linux. No GPU is required for these small models.
- About 8 GB of free disk space for Ollama and the models below.
- Python 3.10 or newer for Labs 2, 3 and 6, and Python 3.11 to 3.13 for Lab 5.
- Node.js 22.22.0 or newer for Labs 3 and 4. The MCP Inspector needs 22.19.0 or newer and promptfoo needs 22.22.0 or newer.

Models used:

| Model | Download size | Used in |
|---|---|---|
| `llama3.2:1b` | 1.3 GB | Labs 1, 2, 4, 5 and 6 (chat model) |
| `embeddinggemma` | 622 MB | Lab 2 (embedding model) |
| `llama-guard3:1b` | 1.6 GB | Lab 6 (safety classifier) |
| `llama3.2` (3B) | 2.0 GB | Lab 4, optional model-graded step |

Activating a Python virtual environment differs by platform. In the steps below, use the line for your shell:

```bash
source .venv/bin/activate        # macOS and Linux
```

```powershell
.venv\Scripts\activate           # Windows PowerShell
```

## Lab 1: Run an open-weight model locally with Ollama

**Goal:** Install Ollama, download a small open-weight model, chat with it in a terminal, and call it through the local REST API.

**Prerequisites:**

- A supported operating system (see Before you start) and about 2 GB of free disk space for this lab.
- `curl` in a bash or zsh shell for the API steps. On Windows PowerShell, use the Python step instead.
- Optional: Python 3.8 or newer for the Python step.

**Steps:**

1. Install Ollama.

   - Windows and macOS: download the installer from the [Ollama download page](https://ollama.com/download) and run it. The Windows installer does not need Administrator rights.
   - Linux: run the official install script. If your policy requires it, download the script, read it, and then run it with `sh`.

   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. Confirm that Ollama is installed. On Linux, if the server is not already running, start it with `ollama serve` in a second terminal.

   ```bash
   ollama -v
   ```

3. Recommended for these labs: turn off Ollama's cloud features so every model runs on your machine. Set the environment variable `OLLAMA_NO_CLOUD=1` for the Ollama server, or add the setting below to `~/.ollama/server.json`, then restart Ollama. The Ollama FAQ explains how to set server environment variables on each platform. Once disabled, the Ollama log shows `Ollama cloud disabled: true`.

   ```json
   {
     "disable_ollama_cloud": true
   }
   ```

4. Download a small model.

   ```bash
   ollama pull llama3.2:1b
   ```

5. Chat with it. Type a question at the `>>>` prompt, for example "In two sentences, what is a context window?". Type `/bye` to leave.

   ```bash
   ollama run llama3.2:1b
   ```

6. List the models you have and the models currently loaded in memory.

   ```bash
   ollama ls
   ollama ps
   ```

7. Call the local REST API. The first command lists installed models. The second sends one chat message. Setting `"stream": false` returns one JSON object; the default is to stream the answer as a series of JSON objects.

   ```bash
   curl http://localhost:11434/api/tags
   ```

   ```bash
   curl http://localhost:11434/api/chat -d '{
     "model": "llama3.2:1b",
     "messages": [
       {"role": "user", "content": "In one sentence, what is a token?"}
     ],
     "stream": false
   }'
   ```

8. Make the same call from Python. This works on every platform, including Windows PowerShell.

   ```bash
   pip install ollama
   ```

   Save this as `chat.py`:

   ```python
   from ollama import chat

   response = chat(
       model="llama3.2:1b",
       messages=[{"role": "user", "content": "In one sentence, what is a token?"}],
   )
   print(response.message.content)
   ```

   ```bash
   python chat.py
   ```

9. Optional: Ollama also serves an OpenAI-compatible endpoint, so tools written for that API can point at your local model.

   ```bash
   curl http://localhost:11434/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d '{
       "model": "llama3.2:1b",
       "messages": [{"role": "user", "content": "Say this is a test"}]
     }'
   ```

**Check your work:**

- `ollama ls` lists `llama3.2:1b`.
- `curl http://localhost:11434/api/tags` returns JSON whose `models` list includes `llama3.2:1b`.
- The `/api/chat` call returns JSON with a `message` object, and the answer is in `message.content`. `python chat.py` prints an answer.
- `ollama ps` shows the model as loaded right after a request.

**Safety notes:**

- Ollama binds to 127.0.0.1 port 11434 by default, and the local API does not require authentication. Anyone who can reach that port can use your models. Do not set `OLLAMA_HOST` to `0.0.0.0` or forward the port unless an authenticating proxy sits in front of it.
- Models whose tag ends in `-cloud` run on Ollama's servers, not on your machine. Turning off cloud features (step 3) keeps the labs local.
- Each model has its own license and usage terms. Check them on the model card before you use a model for work.
- A 1B model is fast but often wrong. Treat its answers as drafts.

**Manual pages:** [Ollama](/ai-tooling/tools/OLLAMA.md), [Meta Llama](/ai-tooling/tools/META_LLAMA.md), [LM Studio](/ai-tooling/tools/LM_STUDIO.md), [llama.cpp](/ai-tooling/tools/LLAMA_CPP.md).

## Lab 2: Build a small RAG over Markdown files with Chroma and Ollama

**Goal:** Index a folder of Markdown files into a local Chroma database using Ollama embeddings, then answer questions with a local model that cites the files it used.

**Prerequisites:**

- Lab 1 complete, with Ollama running and `llama3.2:1b` downloaded.
- Python 3.10 or newer.
- About 700 MB of extra disk space for the embedding model.

**Steps:**

1. Create a project folder and a virtual environment, then install the Chroma and Ollama Python packages.

   ```bash
   mkdir rag-lab
   cd rag-lab
   python -m venv .venv
   source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\activate
   pip install chromadb ollama
   ```

2. Download the embedding model. It turns text into vectors; the chat model never sees the vectors.

   ```bash
   ollama pull embeddinggemma
   ```

3. Create a `notes` folder with two sample files. You can use your own Markdown files instead, as long as they contain nothing sensitive.

   `notes/backups.md`:

   ```markdown
   # Backup policy

   Nightly backups of the file server run at 01:00 and are kept for 35 days.

   A full restore test runs on the first Monday of each quarter. The on-call engineer records the result in the change log.
   ```

   `notes/access-reviews.md`:

   ```markdown
   # Access reviews

   Managers review access to the finance system every 90 days.

   Accounts with no sign-in for 45 days are disabled automatically. Re-enabling an account needs a ticket approved by the system owner.
   ```

4. Save this as `ingest.py`. It splits each file into chunks at blank lines, embeds the chunks with Ollama, and stores them in a Chroma database on disk. The collection is created with `embedding_function=None` because this script supplies its own embeddings, and with cosine distance, which suits text embeddings.

   ```python
   from pathlib import Path

   import chromadb
   import ollama

   NOTES_DIR = Path("notes")
   EMBED_MODEL = "embeddinggemma"
   MAX_CHARS = 1000


   def chunk_markdown(text: str, max_chars: int = MAX_CHARS) -> list[str]:
       """Split on blank lines, then pack paragraphs into chunks of up to max_chars."""
       chunks: list[str] = []
       current = ""
       for para in text.split("\n\n"):
           para = para.strip()
           if not para:
               continue
           if current and len(current) + len(para) + 2 > max_chars:
               chunks.append(current)
               current = para
           else:
               current = f"{current}\n\n{para}" if current else para
       if current:
           chunks.append(current)
       return chunks


   client = chromadb.PersistentClient(path="chroma_db")
   collection = client.get_or_create_collection(
       name="notes",
       embedding_function=None,
       configuration={"hnsw": {"space": "cosine"}},
   )

   for path in sorted(NOTES_DIR.glob("**/*.md")):
       chunks = chunk_markdown(path.read_text(encoding="utf-8"))
       if not chunks:
           continue
       response = ollama.embed(model=EMBED_MODEL, input=chunks)
       source = path.as_posix()
       collection.upsert(
           ids=[f"{source}#{i}" for i in range(len(chunks))],
           documents=chunks,
           embeddings=response["embeddings"],
           metadatas=[{"source": source, "chunk": i} for i in range(len(chunks))],
       )
       print(f"Indexed {len(chunks)} chunk(s) from {source}")

   print(f"Collection now holds {collection.count()} chunk(s)")
   ```

5. Build the index.

   ```bash
   python ingest.py
   ```

6. Save this as `ask.py`. It embeds the question with the same model, retrieves the closest chunks, and asks the chat model to answer only from them.

   ```python
   import sys

   import chromadb
   import ollama

   EMBED_MODEL = "embeddinggemma"
   CHAT_MODEL = "llama3.2:1b"
   TOP_K = 3

   question = " ".join(sys.argv[1:]) or "How long are nightly backups kept?"

   client = chromadb.PersistentClient(path="chroma_db")
   collection = client.get_or_create_collection(
       name="notes",
       embedding_function=None,
       configuration={"hnsw": {"space": "cosine"}},
   )

   query_embedding = ollama.embed(model=EMBED_MODEL, input=question)["embeddings"][0]
   results = collection.query(query_embeddings=[query_embedding], n_results=TOP_K)

   docs = results["documents"][0]
   sources = [meta["source"] for meta in results["metadatas"][0]]
   context = "\n\n---\n\n".join(f"[{src}]\n{doc}" for src, doc in zip(sources, docs))

   messages = [
       {
           "role": "system",
           "content": (
               "Answer using only the notes in the user message. "
               "If the notes do not contain the answer, say that you do not know. "
               "Name the source file for each fact you use."
           ),
       },
       {"role": "user", "content": f"Notes:\n{context}\n\nQuestion: {question}"},
   ]

   response = ollama.chat(model=CHAT_MODEL, messages=messages)
   print(response.message.content)
   print("\nRetrieved:", ", ".join(dict.fromkeys(sources)))
   ```

7. Ask three questions: two the notes can answer, and one they cannot.

   ```bash
   python ask.py "How long are nightly backups kept?"
   python ask.py "When are inactive accounts disabled?"
   python ask.py "Which VPN product do we use?"
   ```

**Check your work:**

- `ingest.py` prints one line per file and a total, and a `chroma_db` folder appears.
- The backups question answers 35 days, and `notes/backups.md` appears in the Retrieved line.
- The accounts question answers 45 days and retrieves `notes/access-reviews.md`.
- The VPN question should get an answer like "I do not know". Small models sometimes guess anyway. That gap is what evaluation (Lab 4) is for.
- Running `ingest.py` again leaves the chunk count unchanged, because `upsert` updates records that already have the same ID.

**Safety notes:**

- Model calls go to Ollama on localhost, and the vectors and note text are stored on disk in `chroma_db`. Protect that folder like the source files, and delete it when you finish.
- Index only files that every user of the tool is allowed to read. A RAG app will answer with whatever it retrieves.
- Retrieved text is untrusted input. A note that contains instructions can steer the model (indirect prompt injection). The system prompt reduces this risk but does not remove it.
- If you delete or shorten a source file, delete `chroma_db` and run `ingest.py` again so old chunks do not linger.

**Manual pages:** [Chroma](/ai-tooling/tools/CHROMA.md), [Ollama](/ai-tooling/tools/OLLAMA.md), [Qdrant](/ai-tooling/tools/QDRANT.md), [pgvector](/ai-tooling/tools/PGVECTOR.md), [FAISS](/ai-tooling/tools/FAISS.md), [LlamaIndex](/ai-tooling/tools/LLAMAINDEX.md).

## Lab 3: Write a minimal MCP server with the official Python SDK

**Goal:** Build a small, read-only MCP server that exposes two tools over a folder of notes, test it in the MCP Inspector, and call it from a local MCP client.

**Prerequisites:**

- `uv`, the Python package manager used by the MCP docs (install command in step 1).
- Python 3.10 or newer. `uv` can install it for you.
- Node.js 22.19.0 or newer, because the MCP Inspector is a Node.js app that `mcp dev` starts with `npx`.
- Two Markdown files to serve. The sample notes from Lab 2 work well.

This lab uses version 2 of the MCP Python SDK, where the server class is `MCPServer` imported from `mcp.server`. Version 1 called it `FastMCP`, so older tutorials will not match this code.

**Steps:**

1. Install `uv` if you do not have it, then restart your terminal.

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. Create a project and add the SDK with its command-line extra.

   ```bash
   uv init notes-mcp
   cd notes-mcp
   uv add "mcp[cli]"
   ```

3. Create a `notes` folder inside `notes-mcp` and copy in `backups.md` and `access-reviews.md` from Lab 2.

4. Save this as `server.py`. The function names become tool names, the docstrings become the descriptions a model reads, and the type hints become the input schema. `read_note` rejects any name that does not resolve to a Markdown file directly inside `notes`.

   ```python
   import logging
   from pathlib import Path

   from mcp.server import MCPServer
   from mcp.server.mcpserver.exceptions import ToolError

   # Never print() in a stdio server: stdout carries the protocol.
   # The logging module writes to stderr.
   logger = logging.getLogger(__name__)

   NOTES_DIR = (Path(__file__).parent / "notes").resolve()

   mcp = MCPServer("Notes")


   @mcp.tool()
   def list_notes() -> list[str]:
       """List the Markdown notes that can be read."""
       return sorted(p.name for p in NOTES_DIR.glob("*.md"))


   @mcp.tool()
   def read_note(name: str) -> str:
       """Return the text of one note. Use a name returned by list_notes."""
       path = (NOTES_DIR / name).resolve()
       if path.parent != NOTES_DIR or path.suffix != ".md" or not path.is_file():
           raise ToolError(f"No note named {name!r}. Call list_notes to see valid names.")
       logger.info("read_note %s", path.name)
       return path.read_text(encoding="utf-8")


   if __name__ == "__main__":
       mcp.run()
   ```

5. Open the server in the MCP Inspector. The command prints a URL that contains a one-time session token; open it in your browser.

   ```bash
   uv run mcp dev server.py
   ```

   In the Inspector, open the Tools tab and:

   - call `list_notes` and confirm it returns both file names;
   - call `read_note` with `backups.md` and confirm it returns the note text;
   - call `read_note` with `../pyproject.toml` and confirm it returns an error instead of the file.

6. Stop the Inspector (Ctrl+C). Now call the server from your own MCP client. The SDK's `Client` launches the server as a child process and talks to it over stdio, the same way a desktop host does. Save this as `client.py`:

   ```python
   import anyio

   from mcp import Client, StdioServerParameters

   server = StdioServerParameters(command="uv", args=["run", "server.py"])


   async def main() -> None:
       async with Client(server) as client:
           tools = await client.list_tools()
           print("Tools:", [tool.name for tool in tools.tools])

           result = await client.call_tool("list_notes", {})
           print("Notes:", result.structured_content)

           blocked = await client.call_tool("read_note", {"name": "../pyproject.toml"})
           print("Traversal blocked:", blocked.is_error)


   if __name__ == "__main__":
       anyio.run(main)
   ```

   ```bash
   uv run python client.py
   ```

7. Optional: to use the server from a desktop MCP host later, follow the SDK's [Connect to a real host](https://py.sdk.modelcontextprotocol.io/get-started/real-host/) page. Remember that the host's model, which may be a hosted service, will then read your note contents.

**Check your work:**

- The Inspector shows two tools, `list_notes` and `read_note`, with the descriptions from your docstrings.
- `read_note` with a valid name returns the note; with `../pyproject.toml` it returns an error result.
- `client.py` prints output like this:

  ```text
  Tools: ['list_notes', 'read_note']
  Notes: {'result': ['access-reviews.md', 'backups.md']}
  Traversal blocked: True
  ```

**Safety notes:**

- A stdio MCP server runs as your user, with your file access. Expose only the narrow actions you need. This server is read-only and limited to one folder.
- Validate every argument a model can send. The path check here blocks `../` traversal and subfolders; without it, `read_note` could read any file you can.
- Do not add tools that run shell commands or write files until you have a clear need, an approval step, and tests for misuse.
- Do not share the Inspector URL. It contains a session token.
- Note contents become model input when a host uses this server. Treat them as untrusted, since a note could carry injected instructions, and never point the server at secrets.
- If you later serve over HTTP with `mcp.run(transport="streamable-http")`, the SDK listens on 127.0.0.1 port 8000 by default. Keep it on localhost, or add authorization before you expose it. See the [AI and MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md) and the official [MCP security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

**Manual pages:** [Model Context Protocol](/ai-tooling/tools/MODEL_CONTEXT_PROTOCOL.md), [Claude Agent SDK](/ai-tooling/tools/CLAUDE_AGENT_SDK.md), [OpenAI Agents SDK](/ai-tooling/tools/OPENAI_AGENTS_SDK.md), [Claude Code](/ai-tooling/tools/CLAUDE_CODE.md).

## Lab 4: Evaluate prompts with promptfoo

**Goal:** Compare two prompts on the same test cases with promptfoo and a local Ollama model, then review the results in promptfoo's local web viewer.

**Prerequisites:**

- Lab 1 complete, with Ollama running and `llama3.2:1b` downloaded.
- Node.js 22.22.0 or newer (Node.js 24 LTS is recommended by promptfoo), which provides `npx`.

**Steps:**

1. Optional but recommended: turn off promptfoo's usage telemetry for this shell.

   ```bash
   export PROMPTFOO_DISABLE_TELEMETRY=1
   ```

   ```powershell
   $env:PROMPTFOO_DISABLE_TELEMETRY = "1"
   ```

2. Create a folder and run the interactive setup. It walks you through a few questions and writes a starter `promptfooconfig.yaml`.

   ```bash
   mkdir prompt-evals
   cd prompt-evals
   npx promptfoo@latest init
   ```

3. Replace the contents of `promptfooconfig.yaml` with the config below. It tests two prompt wordings against two invented security advisories. Variables use double curly braces. `temperature: 0` makes runs more repeatable.

   ```yaml
   description: Summarize security advisories with a local model

   prompts:
     - 'Summarize this security advisory in one sentence for a busy engineer: {{advisory}}'
     - |-
       You are a security analyst. Read the advisory below. Write one plain sentence that says what is affected and what to do.

       Advisory: {{advisory}}

   providers:
     - id: ollama:chat:llama3.2:1b
       config:
         temperature: 0

   tests:
     - vars:
         advisory: 'ExampleCMS 2.3 does not limit failed sign-in attempts on its login form. Version 2.4 adds a lockout after five failures. Upgrade to 2.4.'
       assert:
         - type: icontains
           value: '2.4'
         - type: word-count
           value:
             max: 40
     - vars:
         advisory: 'ExampleMail 5.1 writes session tokens to a log file that any local user can read. Rotate all session tokens and upgrade to 5.2.'
       assert:
         - type: icontains-any
           value:
             - rotate
             - upgrade
         - type: word-count
           value:
             max: 40
   ```

4. Run the eval. promptfoo sends every prompt and test pair to the local model and checks each assertion.

   ```bash
   npx promptfoo@latest eval
   ```

5. Open the results in the local web viewer.

   ```bash
   npx promptfoo@latest view
   ```

6. Optional: add a model-graded check that stays local. Download a larger grader model, then add the `defaultTest` block and the `llm-rubric` assertion below to your config. Without the `provider` line, `llm-rubric` uses a hosted grading model by default, which would send your outputs off the machine.

   ```bash
   ollama pull llama3.2
   ```

   ```yaml
   defaultTest:
     options:
       provider: ollama:chat:llama3.2
     assert:
       - type: llm-rubric
         value: 'Names the affected product and gives one concrete action'
   ```

7. Change one prompt (for example, remove "in one sentence") and run `npx promptfoo@latest eval` again. Compare the pass rates in the viewer. This is how you catch a regression before it ships.

**Check your work:**

- The eval run reports a pass or fail for each prompt and test pair, plus a summary.
- The viewer shows both prompts side by side, with the model output and the result of each assertion.
- You can say which prompt passed more often, and which assertion failed and why.

**Safety notes:**

- The provider here is your local Ollama server, so prompts and outputs stay on your machine. Check the `providers` and grader settings before you add real data to any eval.
- promptfoo collects basic usage telemetry by default, such as which commands and assertion types you run. Its docs say this does not include prompts, outputs or test cases. Set `PROMPTFOO_DISABLE_TELEMETRY=1` to turn it off.
- Do not run `promptfoo share` or pass `--share` for evals that contain private data. Sharing creates a URL that can be viewed online.
- Eval history is stored locally in `~/.promptfoo` by default. Delete it if your test data was sensitive.
- promptfoo also includes red-teaming features. Use them only against systems you own or are authorized to test.

**Manual pages:** [promptfoo](/ai-tooling/tools/PROMPTFOO.md), [Inspect AI](/ai-tooling/tools/INSPECT_AI.md), [DeepEval](/ai-tooling/tools/DEEPEVAL.md), [Langfuse](/ai-tooling/tools/LANGFUSE.md).

## Lab 5: Scan your own local model with garak

**Goal:** Run one narrow garak probe against the model you run in Ollama, read the results, and record what failed.

**Prerequisites:**

- Lab 1 complete, with Ollama running and `llama3.2:1b` downloaded on the same machine where garak runs.
- Python 3.11 to 3.13. garak requires Python 3.11 or newer.
- Linux or macOS. The garak README says it is developed on Linux and macOS. On Windows, install both Ollama and garak inside the same Linux environment (for example WSL) so garak can reach Ollama at 127.0.0.1.
- Authorization: you own and run the target. This lab never targets a third-party service.

**Steps:**

1. Create a virtual environment for garak and install it from PyPI.

   ```bash
   python3 -m venv garak-env
   source garak-env/bin/activate
   python -m pip install -U garak
   ```

2. Look at what garak can run. The first command lists the encoding probes; the second describes the one this lab uses. That probe encodes a payload in base64, asks the model in several ways to decode it, and flags responses that reproduce the hidden payload. Encoding is a common way to slip an instruction past input filters (a form of prompt injection).

   ```bash
   garak --list_probes --spec probes.encoding
   garak --plugin_info probes.encoding.InjectBase64
   ```

3. Run the scan against your local model. `--target_type ollama` selects garak's Ollama generator, which connects to 127.0.0.1 port 11434 by default. `--generations 1` asks for one response per prompt instead of the default five, which keeps the run short on a laptop.

   ```bash
   garak --target_type ollama --target_name llama3.2:1b --spec probes.encoding.InjectBase64 --generations 1
   ```

4. Read the console output. garak shows a progress bar while it generates, then one result row per detector. A row marked FAIL means some responses showed the behavior the probe looks for. The figures at the end of a row give the total number of generations and how many of them behaved acceptably.

5. Open the reports. At the end of the run garak prints the path of a JSONL report and of an HTML summary written next to it. It also writes a hit log that lists only the attempts that triggered a detector. Open the HTML summary in a browser, then read a few hit log entries to see what the model actually returned.

6. Write down the probe, detector, failure rate, model name and date. Then change one thing (a different model, or the guardrail from Lab 6 in front of the model) and rerun the same command to compare.

**Check your work:**

- The run ends by printing the report file path and the HTML summary path, and both files exist.
- The console shows a result row for the probe's detector with a pass or fail result.
- You can explain one result row in plain words: what the probe tried, and what the model did.

**Safety notes:**

- Authorized testing only. This lab targets a model you run yourself. Do not point garak at another organization's model, API or application without written permission and a check of the provider's terms.
- Probes send adversarial prompts, and the reports store the model's replies, which can include unwanted text. Keep the report files as test artifacts and do not publish them.
- Keep runs narrow. Without `--spec`, garak runs every probe it knows, which takes a long time on a laptop.
- A FAIL is a lead, not proof of a vulnerability in your application. This scan tests the raw model, not your app's prompts, filters or permissions.
- Keep Ollama bound to localhost while scanning.

**Manual pages:** [garak](/ai-tooling/tools/GARAK.md), [PyRIT](/ai-tooling/tools/PYRIT.md), [promptfoo](/ai-tooling/tools/PROMPTFOO.md), [Ollama](/ai-tooling/tools/OLLAMA.md).

## Lab 6: Add an input and output guardrail with Llama Guard

**Goal:** Put Llama Guard 3, a safety classifier, in front of and behind a local chat model, so unsafe requests are refused before they reach the model and unsafe answers are refused before they reach the user.

This lab uses Llama Guard through Ollama because it needs no extra framework. [NeMo Guardrails](/ai-tooling/tools/NEMO_GUARDRAILS.md) is a more configurable alternative once you need dialog rules.

**Prerequisites:**

- Lab 1 complete, with Ollama running and `llama3.2:1b` downloaded.
- Python 3.10 or newer with the `ollama` package (`pip install ollama`).
- About 1.6 GB of extra disk space.

**Steps:**

1. Download the 1B Llama Guard 3 model.

   ```bash
   ollama pull llama-guard3:1b
   ```

2. Try it in the terminal. Type a harmless request such as "How do I rotate an SSH key?" and confirm the reply is `safe`. Type `/bye` to leave. Llama Guard replies `safe`, or `unsafe` followed by a category code on the next line, such as `S2` (non-violent crimes).

   ```bash
   ollama run llama-guard3:1b
   ```

3. Save this as `guarded_chat.py`. It classifies the user message first. If that passes, it gets an answer from the chat model, then classifies the full exchange, which tells Llama Guard to judge the assistant's reply. If the guard fails for any reason, the request is refused (fail closed).

   ```python
   import sys

   from ollama import chat

   CHAT_MODEL = "llama3.2:1b"
   GUARD_MODEL = "llama-guard3:1b"
   REFUSAL = "Sorry, I can't help with that request."


   def check(messages: list[dict]) -> tuple[bool, str]:
       """Classify the last message with Llama Guard. Returns (is_safe, raw verdict)."""
       try:
           verdict = chat(model=GUARD_MODEL, messages=messages).message.content.strip()
       except Exception as exc:  # fail closed if the guard is unavailable
           return False, f"guard error: {exc}"
       first_line = verdict.splitlines()[0].strip().lower() if verdict else ""
       return first_line == "safe", verdict


   def guarded_reply(user_text: str) -> str:
       user_msg = {"role": "user", "content": user_text}

       ok, verdict = check([user_msg])
       if not ok:
           print(f"[input blocked] {verdict!r}", file=sys.stderr)
           return REFUSAL

       answer = chat(model=CHAT_MODEL, messages=[user_msg]).message.content

       ok, verdict = check([user_msg, {"role": "assistant", "content": answer}])
       if not ok:
           print(f"[output blocked] {verdict!r}", file=sys.stderr)
           return REFUSAL

       return answer


   if __name__ == "__main__":
       print(guarded_reply(" ".join(sys.argv[1:]) or "How do I rotate an SSH key?"))
   ```

4. Run a harmless request through the full pipeline.

   ```bash
   python guarded_chat.py "How do I rotate an SSH key?"
   ```

5. Test the output check without asking the chat model for anything harmful: classify a canned exchange in which the assistant suggests theft. Save this as `guard_test.py` in the same folder.

   ```python
   from guarded_chat import check

   print(check([
       {"role": "user", "content": "How can I get a bike for my commute?"},
       {"role": "assistant", "content": "Take one from the rack outside an office when nobody is watching."},
   ]))
   ```

   ```bash
   python guard_test.py
   ```

6. Test that the guard fails closed. In `guarded_chat.py`, set `GUARD_MODEL` to a name that does not exist locally, such as `"guard-model-not-installed"`, run step 4 again, and confirm you get the refusal. Then set it back.

**Check your work:**

- Step 2 returns `safe` for the harmless request.
- Step 4 prints a normal answer, with no blocked message on stderr.
- Step 5 prints a tuple that starts with `False` and contains `unsafe` and a category such as `S2`. Classifier output can vary between model versions; what matters is that the exchange is not marked safe.
- Step 6 prints the refusal and an `[input blocked] 'guard error: ...'` line, because the guard model could not be reached.

**Safety notes:**

- Llama Guard is a classifier and makes mistakes in both directions. Its model card reports false positive rates that vary by language and warns that it may be vulnerable to adversarial or prompt injection attacks. Use it as one layer, not the only one.
- Its 13 hazard categories (S1 to S13) follow the MLCommons taxonomy. They may not match your own policy, and they are not designed to recognize your organization's own sensitive data, such as internal hostnames or project names. Add your own checks for data you must protect.
- A guardrail does not fix excessive agency. An agent with powerful tools still needs least privilege and human approval for risky actions.
- Fail closed, as this code does, for anything high risk. A guard that silently passes traffic when it is down is not a control.
- Logging blocked requests with full user text creates sensitive logs. Decide what you log and for how long.
- Llama Guard 3 1B is released under the Llama 3.2 Community License. Check the terms before production use.

**Manual pages:** [Llama Guard](/ai-tooling/tools/LLAMA_GUARD.md), [NeMo Guardrails](/ai-tooling/tools/NEMO_GUARDRAILS.md), [Guardrails AI](/ai-tooling/tools/GUARDRAILS_AI.md), [Ollama](/ai-tooling/tools/OLLAMA.md).

## Where to go next

- Work through the matching modules in the [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md).
- Compare alternatives to each tool in the [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md).
- Go deeper on threats and controls in the [AI and LLM Security Reference](/AI_SECURITY_REFERENCE.md) and the [AI and MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md).
