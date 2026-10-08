# vLLM

> In one minute: vLLM is an open-source Python library and server for fast, memory-efficient LLM inference on GPUs and other accelerators. Teams use it to serve open-weight models behind an OpenAI-compatible API, from one GPU up to multi-node clusters. It is a common choice for self-hosted production inference, which makes its network exposure and its large advisory history important to manage.

| | |
|---|---|
| Category | Local inference / serving |
| Maintainer | vLLM project (vllm-project on GitHub; started at UC Berkeley Sky Computing Lab) |
| License / access | Open source (Apache-2.0) |
| Official docs | [docs.vllm.ai](https://docs.vllm.ai/en/stable/) |
| Repository | [vllm-project/vllm](https://github.com/vllm-project/vllm) |
| Checked | 8 Oct 2026, v0.31.0 (released 5 Oct 2026) |

## What it is for

- Serving open-weight models to many concurrent users with high throughput.
- Exposing self-hosted models through OpenAI-compatible and Anthropic Messages APIs so existing clients work unchanged.
- Running offline batch inference over large prompt sets from Python.
- Scaling large models across GPUs and nodes with tensor, pipeline, data, and expert parallelism.
- Serving quantized models (FP8, INT8, INT4, GPTQ, AWQ, GGUF) and multimodal models that accept images, audio, or video.

## Quick start

The standard install targets Linux with Python 3.10 to 3.13. macOS on Apple silicon is supported through the separate vLLM-Metal project.

1. Create an environment and install vLLM (NVIDIA CUDA):

   ```bash
   uv venv --python 3.12 --seed
   source .venv/bin/activate
   uv pip install vllm --torch-backend=auto
   ```

   AMD ROCm uses `uv pip install vllm --extra-index-url https://wheels.vllm.ai/rocm/`; Google TPU uses `uv pip install vllm-tpu`.

2. Run offline batched inference:

   ```python
   from vllm import LLM, SamplingParams

   prompts = [
       "Hello, my name is",
       "The president of the United States is",
       "The capital of France is",
       "The future of AI is",
   ]
   sampling_params = SamplingParams(temperature=0.8, top_p=0.95)
   llm = LLM(model="facebook/opt-125m")
   outputs = llm.generate(prompts, sampling_params)

   for output in outputs:
       prompt = output.prompt
       generated_text = output.outputs[0].text
       print(f"Prompt: {prompt!r}, Generated text: {generated_text!r}")
   ```

3. Start the OpenAI-compatible server. It listens on `http://localhost:8000`; change this with `--host` and `--port`.

   ```bash
   vllm serve Qwen/Qwen2.5-1.5B-Instruct
   ```

4. Query it:

   ```bash
   curl http://localhost:8000/v1/completions \
       -H "Content-Type: application/json" \
       -d '{
           "model": "Qwen/Qwen2.5-1.5B-Instruct",
           "prompt": "San Francisco is a",
           "max_tokens": 7,
           "temperature": 0
       }'
   ```

5. To require a key on the OpenAI-style routes, pass `--api-key` or set `VLLM_API_KEY`. Several keys can be given for rotation.

## Key concepts

- **`LLM` and `SamplingParams`**: the Python entry points for offline batch generation.
- **`vllm serve`**: the HTTP server, with OpenAI-compatible, Anthropic Messages, and gRPC interfaces plus pooling, scoring, and speech-to-text endpoints.
- **PagedAttention**: vLLM's memory manager for the attention key-value cache, which lets it pack more requests onto a GPU.
- **Continuous batching and prefix caching**: new requests join running batches, and shared prompt prefixes reuse cached computation.
- **Parallelism**: tensor, pipeline, data, expert, and context parallel strategies for large models and clusters.
- **Engine arguments**: flags such as `--trust-remote-code` (default `False`) and `--allowed-media-domains` that control model loading and request handling.
- **Multimodal inputs**: image, audio, and video passed by URL or inline data, which the server fetches and decodes.

## Security notes

- **`--api-key` does not protect the whole server.** Per the [security guide](https://docs.vllm.ai/en/stable/usage/security/), it covers only `/v1`, `/v2`, `/inference`, and `/cohere`. Endpoints such as `/invocations`, `/pooling`, `/classify`, `/score`, `/rerank`, `/tokenize`, `/detokenize`, `/health`, `/version`, and `/load`, and operational ones such as `/pause` and `/update_weights`, stay open. Put vLLM behind a reverse proxy that allowlists only the endpoints you intend to expose, and add authentication, rate limiting, and logging there. Never set `VLLM_SERVER_DEV_MODE=1` in production.
- **[CVE-2026-48746](https://github.com/vllm-project/vllm/security/advisories/GHSA-94f4-hr76-p5j6)** (CVSS 9.1): from 0.3.0 to before 0.22.0, a crafted `Host` header let attackers bypass the API key check. Instances behind an RFC-conforming web server such as nginx were not affected.
- **Inter-node traffic is unauthenticated and unencrypted.** PyTorch distributed, KV cache transfer, and parallel communication accept connections without checks. Run nodes on an isolated network, set `VLLM_HOST_IP` (and `--kv-ip`, `data_parallel_master_ip`) explicitly, and firewall internal ports. [CVE-2025-47277](https://github.com/vllm-project/vllm/security/advisories/GHSA-hjq4-87xh-g4fv) (CVSS 9.8) showed the risk: the `PyNcclPipe` service deserialized untrusted network data, and its PyTorch `TCPStore` listened on all interfaces (0.6.5 to before 0.8.5). [CVE-2025-32444](https://nvd.nist.gov/vuln/detail/CVE-2025-32444) (CVSS 10.0) was a similar unsafe deserialization in the Mooncake integration, fixed in 0.8.5.
- **Media fetching can be abused.** Set `--allowed-media-domains` to an allowlist, set `VLLM_MEDIA_URL_ALLOW_REDIRECTS=0`, and keep `VLLM_MAX_MEDIA_DOWNLOAD_SIZE_MB` and related limits non-zero for untrusted users. [CVE-2026-22778](https://github.com/vllm-project/vllm/security/advisories/GHSA-4r2x-xpjr-7cvv) (CVSS 9.8) chained an error-message memory leak with a video decoder heap overflow into remote code execution on servers hosting video models (0.8.3 to before 0.14.1).
- **Model code is code.** Leave `--trust-remote-code` off unless you have reviewed the model repository. [CVE-2026-27893](https://nvd.nist.gov/vuln/detail/CVE-2026-27893) (CVSS 8.8) found two model files that hardcoded `trust_remote_code=True`, overriding the user's choice (0.10.1 to before 0.18.0).
- **Protect cache directories.** The security guide notes cache contents load without integrity checks, including formats that can execute code. Keep them private and never copy cache artifacts from untrusted sources.
- **Patch quickly.** The project had 93 published GitHub security advisories when checked (5 critical, 22 high), about half of them denial-of-service issues. Watch the [advisories page](https://github.com/vllm-project/vllm/security/advisories) and upgrade on a regular cadence.
- Related library pages: [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Quickstart](https://docs.vllm.ai/en/stable/getting_started/quickstart/): install, offline inference, and online serving.
- [Security guide](https://docs.vllm.ai/en/stable/usage/security/): threat model, unprotected endpoints, and network hardening.
- [Engine arguments](https://docs.vllm.ai/en/stable/configuration/engine_args/): every server and model-loading flag.
- [Online serving](https://docs.vllm.ai/en/stable/serving/online_serving/): the endpoint catalog and chat templates.
- [Security advisories](https://github.com/vllm-project/vllm/security/advisories): published GHSA and CVE records.
