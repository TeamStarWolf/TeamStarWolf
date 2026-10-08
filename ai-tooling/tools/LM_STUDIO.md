# LM Studio

> In one minute: LM Studio is a desktop application for finding, downloading, and running open-weight language models locally, with a chat interface, document chat, MCP support, and a local API server. It suits people who want local models without building a toolchain, and developers who want an OpenAI-compatible endpoint on their own machine. The app is closed source; its server is unauthenticated until you turn authentication on.

| | |
|---|---|
| Category | Local inference |
| Maintainer | Element Labs, Inc. |
| License / access | Proprietary desktop app under the LM Studio app terms; `lms` CLI and SDKs are open source (MIT) |
| Official docs | [lmstudio.ai](https://lmstudio.ai/docs/app) |
| Repository | None (closed source app); CLI at [lmstudio-ai/lms](https://github.com/lmstudio-ai/lms) |
| Checked | 8 Oct 2026, 0.4.25 (Windows and Linux download pages) |

## What it is for

- Chatting with local models through a graphical interface, fully offline once models are downloaded.
- Chatting with your own documents (local RAG) without uploading them to a hosted service.
- Serving a local model to other apps through OpenAI-compatible, Anthropic-compatible, and native REST APIs.
- Running a headless server (llmster) on Linux machines, GPU rigs, or CI without a desktop session.
- Connecting local models to tools through MCP servers.

## Quick start

1. Install LM Studio from [lmstudio.ai/download](https://lmstudio.ai/download). It supports Apple silicon Macs, x64 and ARM64 Windows PCs, and x64 Linux PCs (AppImage or deb).

   For a headless server, install llmster instead and start its daemon:

   ```bash
   # macOS or Linux
   curl -fsSL https://lmstudio.ai/install.sh | bash
   ```

   ```powershell
   # Windows
   irm https://lmstudio.ai/install.ps1 | iex
   ```

   ```bash
   lms daemon up
   ```

2. If you installed the desktop app, run it at least once. Then confirm the `lms` CLI works:

   ```bash
   lms --help
   ```

3. Download a model (or use the Discover tab in the app):

   ```bash
   lms get llama-3.1-8b
   ```

4. List models on disk, load one, and start the local server:

   ```bash
   lms ls
   lms load <model-key>
   lms server start
   ```

5. Call the OpenAI-compatible API, which the docs show at `http://localhost:1234/v1`:

   ```bash
   curl http://localhost:1234/v1/models
   ```

## Key concepts

- **LM Studio, llmster, and lms**: the desktop app, the headless daemon, and the CLI that manages models and the server for either one.
- **Model formats**: GGUF models run through llama.cpp on macOS, Windows, and Linux; MLX models run through Apple's MLX framework on Apple silicon.
- **Runtimes**: inference engines are downloaded and updated separately from the app (Cmd+Shift+R or Ctrl+Shift+R).
- **Local server**: OpenAI-compatible endpoints (`/v1/models`, `/v1/responses`, `/v1/chat/completions`, `/v1/embeddings`, `/v1/completions`), Anthropic-compatible endpoints, and a native REST API.
- **Just-in-time loading**: the server can load a model when a request names it, rather than requiring it to be loaded first.
- **MCP host**: since 0.3.17, LM Studio can connect to local and remote MCP servers defined in `mcp.json`.
- **SDKs**: `lmstudio-python` and `lmstudio-js` (both MIT) for scripting the app or llmster.
- **LM Link**: a feature for using models across your own devices over end-to-end encrypted networks built with Tailscale.

## Security notes

- **Localhost by default, open when you change it.** `lms server start --bind` defaults to `127.0.0.1`. The "Serve on Local Network" setting or `--bind 0.0.0.0` (also settable through `LMS_SERVER_HOST`) exposes the server beyond localhost, and the docs recommend enabling authentication whenever you do.
- **Authentication is off by default.** Since LM Studio 0.4.0, the **Require Authentication** setting makes the REST API and SDKs demand an API token. Create tokens under **Manage Tokens** with only the permissions needed, copy them at creation (they are not shown again), and send them as `Authorization: Bearer <token>`. See [Authentication](https://lmstudio.ai/docs/developer/core/authentication).
- **Keep CORS off unless needed.** `--cors` lets browser pages on other origins call the server; the docs warn this can add risk and recommend authentication.
- **Treat MCP servers as code.** The docs say: "Never install MCPs from untrusted sources," and warn that some MCP servers can run arbitrary code, read local files, and use the network. The "Allow calling servers from mcp.json" server option is flagged as a risk and requires authentication.
- **Know what leaves the machine.** Per the [offline docs](https://lmstudio.ai/docs/app/offline), chats, attached documents, and local server requests stay local. Model search and downloads contact services such as huggingface.co, and the macOS and Windows apps check for updates at launch. For restricted environments, sideload vetted model files.
- **Patch the runtime.** GGUF models are parsed by llama.cpp, whose GGUF loader has had memory-safety CVEs; keep runtimes updated and download models from sources you trust. An NVD keyword search on 8 Oct 2026 found no CVEs filed against LM Studio itself.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md).

## Learn more

- [Getting started](https://lmstudio.ai/docs/app): install, download a model, and chat.
- [lms CLI](https://lmstudio.ai/docs/cli): commands for models, the server, and logs.
- [Developer docs](https://lmstudio.ai/docs/developer): OpenAI-compatible, Anthropic-compatible, and REST APIs.
- [Serve on local network](https://lmstudio.ai/docs/developer/core/server/serve-on-network): binding and exposure guidance.
- [Headless llmster](https://lmstudio.ai/docs/developer/core/headless): install and run without the GUI.
- [MCP in LM Studio](https://lmstudio.ai/docs/app/mcp): setup and safety warnings.
