# LiteLLM

> In one minute: LiteLLM is an open-source Python SDK and self-hosted proxy (an AI gateway) that lets you call more than 100 LLM providers through one OpenAI-format interface. Platform teams run the proxy to hand out virtual keys with budgets, track spend, and add fallbacks, guardrails, and an MCP gateway. Because it sits on the path of every request and holds provider credentials, it is a high-value target, as the March 2026 PyPI backdoor showed.

| | |
|---|---|
| Category | LLM gateway |
| Maintainer | BerriAI |
| License / access | Open source (MIT), except the `enterprise/` directory, which has its own license |
| Official docs | [docs.litellm.ai](https://docs.litellm.ai/docs/) |
| Repository | [BerriAI/litellm](https://github.com/BerriAI/litellm) |
| Checked | 8 Oct 2026, v1.104.1 (latest stable, released 7 Oct 2026) |

## What it is for

- Calling many providers (OpenAI, Anthropic, Vertex AI, Bedrock, Azure OpenAI, Ollama, and others) with one `completion()` call.
- Running a central, OpenAI-compatible gateway so existing OpenAI clients work without code changes.
- Issuing virtual keys with per-key, per-team, and per-user budgets, rate limits, and spend tracking.
- Retries and fallbacks across deployments with the Router.
- Guardrails, logging callbacks to observability tools, and an MCP gateway with per-key access control.

## Quick start

Pin an exact, current version in production (see Security notes). Commands below are for macOS or Linux.

1. Install the SDK and call a model. The key is read from the environment.

   ```bash
   pip install litellm
   export ANTHROPIC_API_KEY="YOUR_API_KEY"
   ```

   ```python
   from litellm import completion

   response = completion(
       model="anthropic/claude-sonnet-5",
       messages=[{"role": "user", "content": "Hello, how are you?"}],
   )
   print(response.choices[0].message.content)
   ```

2. To run the proxy, install it and write a `config.yaml`. The `os.environ/` syntax reads values from environment variables instead of storing secrets in the file. The master key must start with `sk-`.

   ```bash
   uv tool install 'litellm[proxy]'
   export LITELLM_MASTER_KEY="sk-YOUR_MASTER_KEY"
   ```

   ```yaml
   model_list:
     - model_name: claude
       litellm_params:
         model: anthropic/claude-sonnet-5
         api_key: os.environ/ANTHROPIC_API_KEY

   general_settings:
     master_key: os.environ/LITELLM_MASTER_KEY
   ```

3. Start the proxy (it listens on port 4000) and send a test request:

   ```bash
   litellm --config config.yaml

   curl http://0.0.0.0:4000/chat/completions \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
     -d '{"model": "claude", "messages": [{"role": "user", "content": "what llm are you"}]}'
   ```

4. Virtual keys need a Postgres database (`DATABASE_URL`). With it configured, create scoped keys through `POST /key/generate` using the master key, and give those to applications instead of the master key.

## Key concepts

- **SDK and proxy**: the SDK is a Python library; the proxy (AI gateway) is a server that exposes an OpenAI-compatible API.
- **Model string**: `provider/model`, such as `anthropic/claude-sonnet-5`, selects the backend.
- **`model_list`**: maps a public `model_name` that clients request to the real deployment in `litellm_params`.
- **Master key**: the proxy admin key, used to create other keys.
- **Virtual keys**: database-backed keys that carry budgets, rate limits, and allowed models for a team or user.
- **Router and fallbacks**: retry and failover logic across deployments.
- **Guardrails and callbacks**: content filtering, PII masking, and logging hooks.
- **MCP gateway**: one MCP endpoint in front of many MCP servers, with per-key access control.

## Security notes

- **March 2026 PyPI backdoor.** On 24 March 2026 the TeamPCP group published backdoored `litellm` 1.82.7 (10:39 UTC) and 1.82.8 (10:52 UTC) to PyPI. Per the [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-pypi-backdoor-ai-toolchain-supply/), TeamPCP had compromised Aqua Security's Trivy GitHub Actions on 19 March; LiteLLM's CI/CD ran the poisoned scanner, which harvested a PyPI publish token that the attackers used to upload outside the normal release workflow. PyPI quarantined both versions within about an hour, but [LiteLLM's security update](https://docs.litellm.ai/blog/security-update-march-2026) gives an exposure window of 10:39 to 16:00 UTC because of caches. The last clean version is 1.82.6; the clean 1.83.0 shipped on 30 March from a rebuilt pipeline. The official proxy Docker image was not affected, but images built in the window with an unpinned `pip install litellm` could be. Advisory: [PYSEC-2026-2](https://github.com/pypa/advisory-database/blob/main/vulns/litellm/PYSEC-2026-2.yaml).
- **What the payload did.** 1.82.7 hid code in `litellm/proxy/proxy_server.py`; 1.82.8 added `litellm_init.pth` to `site-packages`, which Python runs at every interpreter start. It collected SSH keys, AWS, GCP, and Azure credentials, Kubernetes tokens, database credentials, `.env` files, and LLM API keys, and sent them to `models.litellm[.]cloud`. It persisted as a systemd service named "System Telemetry Service" and, where Kubernetes access existed, deployed privileged `node-setup-*` pods in `kube-system`.
- **If either version was installed.** Treat the host as compromised and rotate every credential it could reach, including all LLM provider keys. Uninstalling does not remove `litellm_init.pth`; delete it from every `site-packages`. Check for `~/.config/sysmon/sysmon.py` and the services "System Telemetry Service", `pgmon.service`, and `sysmon.service`, audit `kube-system` for `node-setup-*` pods, and review outbound traffic for `models.litellm[.]cloud` and `checkmarx[.]zone`.
- **Harden the supply chain.** Install with pinned hashes (`pip install --require-hashes`), compare against the SHA-256 checksums LiteLLM published for audited releases, and verify cosign signatures on Docker images from v1.83.0-nightly onward. CSA also recommends secrets managers, short-lived OIDC credentials in CI, and dependency monitoring. See the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).
- **Keep the proxy patched.** [CVE-2026-49468](https://github.com/BerriAI/litellm/security/advisories/GHSA-4xpc-pv4p-pm3w) (Critical): a crafted `Host` header could bypass proxy authentication on protected management routes; fixed in 1.84.0. [GHSA-7hp6-4w63-5g45](https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45) (Critical, 30 Sep 2026): an authenticated internal user could forge an admin session through the shared salt key and run commands on the host; fixed in 1.100.4, 1.101.3, 1.102.2, and 1.103.1. Watch the [advisories page](https://github.com/BerriAI/litellm/security).
- **Lock down keys.** Always set a master key; the project's security policy treats a missing `master_key` as a misconfiguration, not a vulnerability. Keep provider keys and the master key in the environment or a secrets manager, and hand applications [virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys) with budgets and model limits.
- **The gateway widens prompt-injection reach.** One proxy can expose many models and MCP servers to many keys. Grant each key only the models and MCP servers it needs, and treat tool output as untrusted. See the [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md) and [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).

## Learn more

- [LiteLLM docs](https://docs.litellm.ai/docs/): SDK and gateway overview with provider examples.
- [Proxy quick start](https://docs.litellm.ai/docs/proxy/quick_start): install, config, and first request.
- [Proxy config](https://docs.litellm.ai/docs/proxy/configs): `model_list`, `os.environ/` references, and settings.
- [Virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys): master key, database setup, and key generation.
- [Security update, March 2026](https://docs.litellm.ai/blog/security-update-march-2026): the official incident timeline, indicators, and verified checksums.
