# Hugging Face Hub

> In one minute: The Hugging Face Hub is a hosted platform where people publish and download machine learning models, datasets, and demo apps called Spaces, all stored in git-versioned repositories. The `huggingface_hub` library and the `transformers` library are the usual way to fetch, load, and publish those artifacts from Python. It matters to defenders because model files can carry executable code, and an access token can grant write access to repositories that many others download.

| | |
|---|---|
| Category | Model hub |
| Maintainer | Hugging Face |
| License / access | Hosted platform with free sign-up and paid PRO, Team, and Enterprise plans; `huggingface_hub` and `transformers` are open source (Apache-2.0) |
| Official docs | [huggingface.co/docs](https://huggingface.co/docs/hub/index) |
| Repository | [huggingface/huggingface_hub](https://github.com/huggingface/huggingface_hub) (client library; see also [huggingface/transformers](https://github.com/huggingface/transformers)) |
| Checked | 8 Oct 2026, hosted service; `huggingface_hub` 2.1.1 (1 Oct 2026), `transformers` 5.19.0 (6 Oct 2026) |

## What it is for

- Finding and downloading pretrained models and datasets by repository ID.
- Hosting public or private model, dataset, and Space repositories with version history.
- Loading models for local inference and fine-tuning with `transformers` (`pipeline`, `from_pretrained`, `Trainer`).
- Sharing demo applications in Spaces.
- Distributing gated models, such as Meta Llama, that require users to accept license terms first.

## Quick start

These steps follow the official `huggingface_hub` quick start.

1. Install the library. It includes the `hf` command-line tool.

   ```bash
   pip install --upgrade huggingface_hub
   ```

2. Log in. The command opens a browser flow, or you can paste a User Access Token from your settings page. Confirm the active account afterward.

   ```bash
   hf auth login
   hf auth whoami
   ```

   In CI or a Space, set the `HF_TOKEN` environment variable instead; it takes priority over the stored token.

3. Download and cache a file. Pin `revision` to a full-length commit hash when you need a reproducible, reviewed version.

   ```python
   from huggingface_hub import hf_hub_download

   hf_hub_download(
       repo_id="google/pegasus-xsum",
       filename="config.json",
       revision="4d33b01d79672f27f001f6abade33f22d993b151",
   )
   ```

4. Create a private repository and upload a file. This needs a token with `write` permission.

   ```python
   from huggingface_hub import HfApi

   api = HfApi()
   api.create_repo(repo_id="super-cool-model", private=True)
   api.upload_file(
       path_or_fileobj="README.md",
       path_in_repo="README.md",
       repo_id="YOUR_USERNAME/super-cool-model",
   )
   ```

## Key concepts

- **Repository**: a git-versioned model, dataset, or Space identified as `owner/name`. A `revision` is a branch, tag, or full commit hash.
- **Cache**: downloaded files are stored locally and reused; the login token is saved under `HF_HOME` (default `~/.cache/huggingface/token`).
- **User Access Token**: `read`, `write`, or `fine-grained` (scoped to specific resources). Used by the libraries, by git, and as a bearer token for Inference Providers.
- **Gated model**: a repository that requires you to share details and accept conditions before download.
- **Weight formats**: `safetensors` stores tensors without executable code; PyTorch pickle files (such as `pytorch_model.bin`) can run code when loaded.
- **`trust_remote_code`**: a `from_pretrained` option that runs modeling code from the repository instead of code shipped with `transformers`.
- **Spaces secrets**: environment variables, such as `HF_TOKEN`, stored for a Space app.

## Security notes

- **Pickle files can execute code.** The [pickle scanning docs](https://huggingface.co/docs/hub/security-pickle) explain that unpickling can import and call arbitrary functions. The Hub runs ClamAV and a pickle import scan on every pushed file and highlights suspicious imports, but says the scan is not 100% foolproof. Prefer `safetensors`; `from_pretrained` loads it when available.
- **Malicious models are a real pattern.** In February 2024 [JFrog](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/) reported about 100 malicious models, including one that opened a reverse shell through a pickle `__reduce__` payload. Scanners can be evaded: [CVE-2025-10155](https://github.com/advisories/GHSA-jgw4-cr84-mqxg) and two related September 2025 advisories let files bypass `picklescan` (fixed in 0.0.31). The [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-malicious-ai-model-repositories-attack-sur/) recommends a safetensors-only policy, commit pinning, checksum checks, and loading models in network-isolated containers.
- **Review before `trust_remote_code=True`.** The [model loading guide](https://huggingface.co/docs/transformers/models) warns to take extra precaution with custom models and to pin a specific `revision` so the code cannot change after you review it.
- **Scope and separate tokens.** The [token guide](https://huggingface.co/docs/hub/security-tokens) recommends one token per app or machine and fine-grained tokens for production. Use `read` tokens where you do not need to push. CI can use Trusted Publishers, which exchanges an OIDC identity token for a short-lived Hub token instead of storing a secret. Set `HF_HUB_DISABLE_IMPLICIT_TOKEN=1` if you do not want the stored token sent on every request.
- **Revoke leaked tokens fast.** Delete or refresh your own leaked token in settings. Anyone who finds a Hugging Face token can invalidate it through `POST https://huggingface.co/api/credentials/revoke`, and the Hub runs TruffleHog on each push and emails you about verified secrets ([secrets scanning](https://huggingface.co/docs/hub/security-secrets)).
- **Spaces secrets have been targeted.** On 31 May 2024 Hugging Face [disclosed](https://huggingface.co/blog/space-secrets-disclosure) unauthorized access to Spaces secrets, revoked affected tokens, and advised users to refresh any key or token stored there.
- **Use account protections.** The Hub supports 2FA, GPG-signed commits, SSO, and resource groups for access control ([security overview](https://huggingface.co/docs/hub/security)). A signed commit proves origin, not that a file is safe.
- Related library pages: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [huggingface_hub quick start](https://huggingface.co/docs/huggingface_hub/quick-start): login, download, create repositories, and upload.
- [Transformers quickstart](https://huggingface.co/docs/transformers/quicktour): load models, run pipelines, and fine-tune with Trainer.
- [Hub security](https://huggingface.co/docs/hub/security): tokens, 2FA, malware, pickle, and secrets scanning.
- [Hub documentation](https://huggingface.co/docs/hub/index): repositories, model cards, gated models, and Spaces.
- [LLM Course](https://huggingface.co/learn/llm-course): a course on large language models and NLP with Hugging Face libraries.
