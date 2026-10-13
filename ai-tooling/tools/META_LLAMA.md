# Meta Llama

> In one minute: Llama is Meta's family of open-weight large language models, published as downloadable weights under Meta's own community licenses. Teams fine-tune and self-host them with libraries and servers such as transformers, vLLM, and SGLang, or reach them through cloud partners. For defenders, Llama usually appears as model files inside your own infrastructure, so license terms, file provenance, and the safety layers around the model are your responsibility rather than a vendor's.

| | |
|---|---|
| Category | Open-weight models |
| Maintainer | Meta |
| License / access | Open weights under Meta's Llama community licenses (custom terms plus a use policy per version); gated download |
| Official docs | [dev.meta.ai/llama](https://dev.meta.ai/llama/) |
| Repository | [meta-llama/llama-models](https://github.com/meta-llama/llama-models) |
| Checked | 8 Oct 2026, Llama 4 (Scout and Maverick; Llama 4 license effective 5 Apr 2025); `llama-models` 0.3.0 |

## What it is for

- Self-hosting a general-purpose model when prompts and data must stay inside your environment.
- Fine-tuning on domain data, subject to the license's naming and attribution rules.
- Text plus image input with Llama 4, or smaller text-only models such as Llama 3.2 1B Instruct.
- Adding safety layers with Meta's Llama Guard and Prompt Guard classifiers.
- Measuring model cyber risk with Meta's CyberSecEval benchmarks.

## Quick start

This path uses the official `meta-llama` organization on Hugging Face.

1. Sign in to Hugging Face, open a model page such as `meta-llama/Llama-3.2-1B-Instruct`, fill in the access form, and accept the license. Meta reviews requests; approval can take a few days and arrives by email.
2. Install the libraries and log in with a Hugging Face token (the `hf` tool ships with `huggingface_hub`, which `transformers` installs):

   ```bash
   pip install -U transformers accelerate
   hf auth login
   ```

3. Run the model with a pipeline:

   ```python
   from transformers import pipeline

   pipe = pipeline("text-generation", model="meta-llama/Llama-3.2-1B-Instruct")
   messages = [
       {"role": "user", "content": "Who are you?"},
   ]
   print(pipe(messages))
   ```

4. Alternative: download from Meta directly. After approval Meta emails a signed URL. Install the CLI, find the model ID, and paste the URL when prompted:

   ```bash
   pip install llama-models
   llama-model list
   llama-model download --source meta --model-id CHOSEN_MODEL_ID
   ```

   The links expire after 24 hours and a limited number of downloads.

## Key concepts

- **Model families**: Llama 4 (natively multimodal, mixture-of-experts), Llama 3 (3.1, 3.2, and 3.3), and Llama 2.
- **Llama 4 Scout and Maverick**: both use 17B active parameters; Scout has 109B total with 16 experts and a 10M-token context, Maverick has 400B total with 128 experts and a 1M-token context. Both take text and up to 5 images and output text. Knowledge cutoff is August 2024.
- **Mixture of experts**: only a subset of the parameters (the "active" ones) is used for each token.
- **Instruct and base models**: instruct models are tuned for chat; base (pretrained) models are for further training.
- **Prompt format**: special tokens such as `<|begin_of_text|>`, `<|header_start|>` and `<|header_end|>` around roles, and `<|eot|>` at the end of a turn. Tool output goes in the `ipython` role.
- **Community license and use policy**: each version (Llama 2, 3, 3.1, 3.2, 3.3, 4) has its own license and use policy.
- **Llama Protections**: Llama Guard 4 (a 12B multimodal input and output moderation model), Prompt Guard 2 (86M and 22M injection and jailbreak classifiers), LlamaFirewall, and CodeShield.
- **Site change**: Meta's developer site now features its newer Muse models; Llama documentation remains at dev.meta.ai/llama.

## Security notes

- **Read the license before you ship.** The [Llama 4 Community License](https://dev.meta.ai/llama/llama4/license/) requires a separate license from Meta for products with more than 700 million monthly active users, a prominent "Built with Llama" notice, model names that begin with "Llama" for distributed derivatives, and compliance with the [use policy](https://dev.meta.ai/llama/llama4/use-policy/). Older versions have their own terms.
- **Control provenance.** Pull weights only through Meta's download flow or the official [meta-llama organization](https://huggingface.co/meta-llama), pin the exact revision you reviewed, and prefer `safetensors` files. Treat re-uploads, merges, and quantized copies from other publishers as untrusted artifacts until reviewed. See the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- **The serving stack has its own bugs.** [CVE-2024-50050](https://github.com/advisories/GHSA-2m97-q37r-gwpc) (CVSS 6.3): Llama Stack used Python pickle for socket communication, which could allow remote code execution. The fix switched that channel to JSON. Patch inference frameworks as carefully as any other network service.
- **You own the endpoint.** A self-hosted model has no provider in front of it, so authentication, rate limits, network isolation, and logging are yours to build. See [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).
- **Add injection and content screening.** Open weights ship without provider-side filters. Meta's [Llama Protections](https://dev.meta.ai/llama/llama-protections/) include Prompt Guard 2 for prompt injection and jailbreak detection, Llama Guard 4 for input and output moderation, LlamaFirewall to orchestrate guard checks across agent tool use, and CodeShield to filter insecure generated code. Source and licenses are in [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama). Classifiers reduce risk but do not remove it.
- **Tool output is untrusted input.** In agent setups the model emits tool calls that your code executes and receives results in the `ipython` role. Validate arguments, allowlist tools, and keep secrets out of the model's reach. See the [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md).
- Related library page: [AI Security Reference](/AI_SECURITY_REFERENCE.md).

## Learn more

- [Llama documentation](https://dev.meta.ai/llama/): model families, licenses, and protections.
- [Getting the models](https://dev.meta.ai/llama/docs/getting-the-models/): direct download from Meta, Hugging Face, Kaggle, and cloud and edge partners.
- [Llama 4 model card and prompt formats](https://dev.meta.ai/llama/docs/model-cards-and-prompt-formats/llama4/): sizes, context, and special tokens.
- [Llama cookbook](https://github.com/meta-llama/llama-cookbook): MIT-licensed guides for inference, fine-tuning, and RAG.
- [Developer use guide resources](https://dev.meta.ai/llama/docs/how-to-guides/responsible-use-guide-resources/): use-case policy, alignment, system-level safeguards, and transparency practices.
