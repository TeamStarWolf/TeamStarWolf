# Ollama

> In one minute: Ollama is an open-source tool that downloads and runs open-weight language models on your own machine, with a CLI and a local HTTP API. Developers, researchers, and security teams use it to run models offline or keep prompts on their own hardware. Its API has no built-in authentication, so an Ollama server bound to a public interface is open to anyone who can reach the port.

| | |
|---|---|
| Category | Local inference |
| Maintainer | Ollama (ollama on GitHub) |
| License / access | Open source (MIT) |
| Official docs | [docs.ollama.com](https://docs.ollama.com/quickstart) |
| Repository | [ollama/ollama](https://github.com/ollama/ollama) |
| Checked | 8 Oct 2026, v0.40.1 (released 7 Oct 2026) |

## What it is for

- Running open-weight models locally for chat, coding help, or summarization without sending prompts to a hosted service.
- Serving a local model to other tools through the native API or the OpenAI-compatible and Anthropic-compatible endpoints.
- Packaging a model with a custom system prompt and parameters (a Modelfile) and sharing it with a team.
- Testing prompts, guardrails, and red-team cases against a model you fully control.
- Running models in air-gapped or restricted environments once the weights are downloaded.

## Quick start

1. Install Ollama.

   macOS or Linux:

   ```shell
   curl -fsSL https://ollama.com/install.sh | sh
   ```

   Windows (PowerShell):

   ```powershell
   irm https://ollama.com/install.ps1 | iex
   ```

   Manual installers (`Ollama.dmg`, `OllamaSetup.exe`) are on [ollama.com/download](https://ollama.com/download). Docker users can run the `ollama/ollama` image instead (see the Docker guide below).

2. Start the server. On macOS and Windows, open the Ollama app. On Linux, if the service is not already running:

   ```shell
   ollama serve
   ```

3. Download and chat with a model. Type `/bye` to exit.

   ```shell
   ollama run gemma4
   ```

4. Call the local API from another terminal:

   ```shell
   curl http://localhost:11434/api/chat -d '{
     "model": "gemma4",
     "messages": [{
       "role": "user",
       "content": "Why is the sky blue?"
     }],
     "stream": false
   }'
   ```

5. Manage models with `ollama ls`, `ollama ps`, `ollama stop gemma4`, and `ollama rm gemma4`.

## Key concepts

- **Model and tag**: a name such as `gemma4` or `gemma4:e2b`, pulled from the [Ollama library](https://ollama.com/library) with `ollama pull` or on first `ollama run`.
- **Server**: `ollama serve` runs the background API. The CLI, desktop app, and integrations are all clients of this server.
- **Native API**: endpoints under `http://localhost:11434/api`, such as `/api/chat`.
- **Compatibility APIs**: OpenAI-compatible endpoints under `/v1` and an Anthropic-compatible `/v1/messages` endpoint, so existing SDKs can point at a local model.
- **Modelfile**: a plain-text recipe for a custom model. `FROM` (required) names a base model, Safetensors directory, or GGUF file; `PARAMETER`, `TEMPLATE`, `SYSTEM`, and `MESSAGE` shape behavior. Build it with `ollama create choose-a-model-name -f ./Modelfile`.
- **Environment variables**: `OLLAMA_HOST` (bind address), `OLLAMA_ORIGINS` (allowed browser origins), and `OLLAMA_MODELS` (model storage location) are the main server settings.
- **Cloud models**: after `ollama signin`, the same CLI and API can reach hosted models. Local models still run on your machine.

## Security notes

- **The local API has no authentication.** Ollama's API docs state that local requests do not need authentication. The default bind address is `127.0.0.1:11434`. Setting `OLLAMA_HOST=0.0.0.0` (a documented option) exposes every endpoint, including model pull, create, push, and delete, to anyone who can reach the port.
- **Exposed servers are common.** A [Cisco Talos study](https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama) (1 Sep 2025) found 1,139 internet-reachable Ollama instances through Shodan, 214 of them answering prompts with no credentials. Keep Ollama on localhost. If other machines need it, put an authenticating reverse proxy in front of `http://localhost:11434` and restrict access with a firewall or VPN. In Docker, publish the port to loopback only, for example `-p 127.0.0.1:11434:11434`.
- **[CVE-2026-7482](https://nvd.nist.gov/vuln/detail/CVE-2026-7482)** (CVSS 9.1): before 0.17.1, a crafted GGUF file sent to `/api/create` caused a heap out-of-bounds read during quantization. The leaked memory could include environment variables, API keys, system prompts, and other users' conversations, and could be exfiltrated through `/api/push` to an attacker's registry. Both endpoints are unauthenticated upstream.
- **[CVE-2024-37032](https://nvd.nist.gov/vuln/detail/CVE-2024-37032)** (CVSS 8.8): before 0.1.34, Ollama did not validate model digest format, allowing path traversal (such as a leading `../`) when resolving model paths. Pull models only from registries you trust.
- **[CVE-2024-28224](https://nvd.nist.gov/vuln/detail/CVE-2024-28224)**: before 0.1.29, a DNS rebinding flaw let a malicious web page reach the full local API. Keep `OLLAMA_ORIGINS` narrow; by default only `127.0.0.1` and `0.0.0.0` origins are allowed.
- **Windows auto-update**: [CERT Polska](https://cert.pl/en/posts/2026/04/CVE-2026-42248/) reported [CVE-2026-42248](https://nvd.nist.gov/vuln/detail/CVE-2026-42248) (no signature check on downloaded updates) and [CVE-2026-42249](https://nvd.nist.gov/vuln/detail/CVE-2026-42249) (path traversal in update file names). Versions 0.12.10 to 0.17.5 were confirmed vulnerable; the advisory names no fixed version. Treat update traffic on untrusted networks as a risk.
- **Least privilege and local-only mode**: the Linux service runs as an unprivileged `ollama` user. If policy requires purely local use, set `OLLAMA_NO_CLOUD=1` (or `"disable_ollama_cloud": true` in the server config) to turn off cloud models and web search.
- **Inventory local runtimes**: an unexpected Ollama service on an endpoint is worth investigating. Related library pages: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Quickstart](https://docs.ollama.com/quickstart): install, first model, and first chat.
- [API introduction](https://docs.ollama.com/api/introduction): base URLs, authentication, and compatibility endpoints.
- [FAQ](https://docs.ollama.com/faq): `OLLAMA_HOST`, proxies, CORS origins, model storage, and disabling cloud features.
- [Modelfile reference](https://docs.ollama.com/modelfile): all instructions for building custom models.
- [Docker guide](https://docs.ollama.com/docker): CPU and NVIDIA GPU containers.
- [Linux install](https://docs.ollama.com/linux): manual install and systemd service setup.
