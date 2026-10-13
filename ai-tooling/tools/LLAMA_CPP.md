# llama.cpp

> In one minute: llama.cpp is an open-source C/C++ engine for running large language models on CPUs and GPUs with minimal setup, using the GGUF model format and aggressive quantization. It powers many desktop apps and local AI tools, and it ships its own CLI and an OpenAI-compatible HTTP server. Because it parses model files and network input in native code, keeping it patched and isolated matters.

| | |
|---|---|
| Category | Local inference |
| Maintainer | ggml-org (open-source community project) |
| License / access | Open source (MIT) |
| Official docs | [github.com](https://github.com/ggml-org/llama.cpp/tree/master/docs) |
| Repository | [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp) |
| Checked | 8 Oct 2026, v0.6.0 (stable release, 5 Oct 2026); rolling build b11490 |

## What it is for

- Running quantized open-weight models on laptops, workstations, and servers, including Apple silicon, NVIDIA, AMD, Intel, and CPU-only machines.
- Serving a local model to applications through OpenAI-compatible and Anthropic-compatible HTTP endpoints, with a built-in web UI.
- Splitting a model across CPU and GPU when it does not fit in VRAM.
- Embedding inference in other software through the `libllama` C API (LM Studio, for example, runs GGUF models through llama.cpp).
- Converting and quantizing models to GGUF for smaller memory footprints.

## Quick start

1. Install the unified `llama` binary.

   macOS or Linux:

   ```bash
   curl -LsSf https://llama.app/install.sh | sh
   ```

   Windows (PowerShell):

   ```powershell
   irm https://llama.app/install.ps1 | iex
   ```

   Alternatives: prebuilt binaries from the [releases page](https://github.com/ggml-org/llama.cpp/releases), Docker images such as `ghcr.io/ggml-org/llama.cpp:server`, or a source build per the build guide.

2. Download a GGUF model from Hugging Face and chat with it:

   ```sh
   llama cli -hf ggml-org/Qwen3.5-0.8B-GGUF
   ```

3. Start the OpenAI-compatible server and web UI. It listens on `127.0.0.1:8080` by default. (The same server is also built as the standalone `llama-server` binary, which the Docker `server` images use.)

   ```sh
   llama serve -hf ggml-org/Qwen3.5-0.8B-GGUF
   ```

4. Send a request from another terminal:

   ```sh
   curl --request POST \
       --url http://localhost:8080/completion \
       --header "Content-Type: application/json" \
       --data '{"prompt": "Building a website can be done in 10 simple steps:","n_predict": 128}'
   ```

   OpenAI clients can use `http://localhost:8080/v1` as their base URL.

## Key concepts

- **GGUF**: the single-file model format llama.cpp loads. The `-hf` flag pulls a GGUF from a Hugging Face repository and defaults to the `Q4_K_M` quantization when present.
- **Quantization**: 1.5-bit to 8-bit integer formats that shrink memory use and speed up inference at some cost in quality.
- **ggml**: the tensor library underneath llama.cpp. It provides the CPU, CUDA, Metal, HIP, Vulkan, SYCL, and other backends.
- **Unified binary**: `llama` exposes subcommands such as `serve`, `cli`, `download`, and `update`.
- **Server**: `llama serve` / `llama-server` offers `/completion`, OpenAI-style `/v1/chat/completions`, `/v1/embeddings`, and `/v1/responses`, plus Anthropic-style `/v1/messages`.
- **GPU offload**: `-ngl` (`--n-gpu-layers`) sets how many layers live in VRAM (`auto` by default).
- **Router mode**: `--models-dir` lets one server load and switch between several models.
- **RPC backend**: `ggml-rpc` servers let one host offload compute to other machines over TCP.

## Security notes

- **No authentication by default.** The server binds to `127.0.0.1`, and `--api-key` defaults to none. Before using `--host` to listen on other addresses (the Docker examples use `--host 0.0.0.0`), set `--api-key` or `--api-key-file` and enable TLS with `--ssl-key-file` and `--ssl-cert-file` (requires a build with OpenSSL).
- **Follow the project security policy.** [SECURITY.md](https://github.com/ggml-org/llama.cpp/blob/master/SECURITY.md) says not to use the RPC backend or `llama-server` on untrusted networks, to run untrusted models in a sandbox such as a container or VM, and to check the hash of downloaded weights. It treats the web UI, experimental features, and most denial-of-service bugs as out of scope. It also says the private disclosure program is currently disabled.
- **Experimental agent features run with server privileges.** `--tools` (including `exec_shell_command`, `read_file`, and `write_file`), `--agent`, and MCP server configs are marked "do not enable in untrusted environments." Enabling them limits `--cors-origins` to localhost by default; `--tools-runtime` can move tool execution into a container.
- **Malicious model files**: [CVE-2025-49847](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-8wwf-w4qm-gpqr) (CVSS 8.8) let a crafted GGUF vocabulary overflow a buffer and potentially execute code; fixed in b5662. Several other GGUF parser overflows appear in the [security advisories](https://github.com/ggml-org/llama.cpp/security/advisories).
- **RPC backend**: [CVE-2026-34159](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-j8rj-fmpv-wcxw) (CVSS 9.8) gave unauthenticated remote code execution to anyone with TCP access to an RPC server port; fixed in b8492. The earlier [CVE-2024-42479](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-wcr5-566p-9cwj) (CVSS 10.0) allowed arbitrary memory writes; fixed in b3561. Keep RPC traffic on an isolated network.
- **Server bugs**: [CVE-2026-43632](https://nvd.nist.gov/vuln/detail/CVE-2026-43632) (CVSS 8.1) is a use-after-free in six tokenization endpoints when `--sleep-idle-seconds` is set (builds b7492 through b9060). Track the rolling `b` builds and update often.
- **Leave optional endpoints off**: `--props` (POST `/props`), `--metrics`, `--slot-save-path`, and `--media-path` (local `file://` access) are disabled by default; enable them only when needed.
- Related library pages: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md).

## Learn more

- [Server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md): every `llama-server` flag and endpoint.
- [Build guide](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md): CPU, CUDA, Metal, Vulkan, and other backends.
- [Docker guide](https://github.com/ggml-org/llama.cpp/blob/master/docs/docker.md): `full`, `light`, and `server` images and GPU variants.
- [Security policy](https://github.com/ggml-org/llama.cpp/blob/master/SECURITY.md): threat model and safe-use guidance.
- [llama.app](https://llama.app): desktop app and installer scripts from the llama.cpp team and Hugging Face.
