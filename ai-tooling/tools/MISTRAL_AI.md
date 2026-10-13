# Mistral AI

> In one minute: Mistral AI is a French model developer that offers a hosted API and developer console, now called Studio (earlier docs called it La Plateforme), plus a catalog of models that includes many open-weight releases. Developers call the API for chat, coding, OCR, audio, and moderation, or download open weights to run on their own hardware. It matters to defenders because the same model family can arrive as a third-party API dependency or as weights inside your own infrastructure, and each path has different data and supply chain risks.

| | |
|---|---|
| Category | Model platform (API) |
| Maintainer | Mistral AI |
| License / access | Commercial API with a free mode; many models are open-weight (several under Apache 2.0, others under Modified MIT or CC BY-NC 4.0); Python SDK is open source (Apache-2.0) |
| Official docs | [docs.mistral.ai](https://docs.mistral.ai/) |
| Repository | [mistralai/client-python](https://github.com/mistralai/client-python) |
| Checked | 8 Oct 2026, hosted service; Python SDK `mistralai` 3.1.0 (released 6 Oct 2026) |

## What it is for

- Chat and text generation through the hosted API.
- Function calling so a model can request actions from your application.
- OCR, transcription, text-to-speech, and embeddings with specialized models.
- Content moderation and input guardrails, including a jailbreaking category.
- Self-hosting open-weight models such as Mistral Small 4 and the Ministral 3 family, which the models page lists under Apache 2.0.

## Quick start

These steps follow the official "Send your first API request" quickstart on macOS or Linux.

1. In the Mistral console, open Studio, go to API keys, and create a key. Copy it right away; it is shown only once.
2. Export the key:

   ```bash
   export MISTRAL_API_KEY="YOUR_API_KEY"
   ```

3. Install the Python SDK:

   ```bash
   pip install mistralai
   ```

4. Save this as `quickstart.py` and run `python quickstart.py`:

   ```python
   import os
   from mistralai.client import Mistral

   client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])

   response = client.chat.complete(
       model="mistral-large-latest",
       messages=[
           {"role": "user", "content": "What is Mistral AI?"}
       ],
   )

   print(response.choices[0].message.content)
   ```

5. Check the [models overview](https://docs.mistral.ai/models) for current model names and each model's license.

## Key concepts

- **Studio and Admin panel**: Studio is the developer console and the Mistral API, where keys are created. Usage, limits, and privacy settings are managed in the Admin panel.
- **Chat completion**: `client.chat.complete` takes a `model` and a list of `messages` and returns `choices`.
- **Open and Premier models**: the models page tags open-weight models with their license and lists commercial models (such as OCR, Codestral, and embedding models) separately.
- **Organizations and workspaces**: an organization contains workspaces. Rate limits are shared across all API keys in a workspace, and spending limits can be set per organization and per workspace (a workspace limit cannot exceed the organization limit).
- **Function calling**: the model generates function arguments; the developer is responsible for executing the function.
- **Custom Guardrails**: moderation rules declared in an API request, backed by the `mistral-moderation-2603` model.
- **Agents API and Fine-Tuning API**: stateful services that keep data longer than plain chat calls.

## Security notes

- **Protect keys like passwords.** Keys are shown once at creation, so store them in a secrets manager and read them from the environment as the quickstart does. GitHub secret scanning includes a pattern for Mistral AI API keys (see the [supported patterns list](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)). Revoke and replace any key that reaches a repository, log, or ticket.
- **Know the retention defaults.** The [privacy policy](https://legal.mistral.ai/terms/privacy-policy) says that, except for specific APIs, Mistral keeps inputs and outputs for the time needed to generate the output and then for 30 rolling days to monitor abuse, unless zero data retention is activated. Agents API inputs and outputs are kept until you terminate your account, and fine-tuning data is kept until you delete it.
- **Check the training setting.** Confirm whether your organization lets Mistral use its API data to improve models. A [help center article](https://help.mistral.ai/en/articles/455207-can-i-opt-out-of-my-input-or-output-data-being-used-for-training) places the Studio and API opt-out toggle in the Admin panel's Privacy menu under "Anonymous improvement data". Review it for every organization that handles sensitive data.
- **Use limits to contain misuse.** Per [Usage and limits](https://docs.mistral.ai/admin/billing-usage/usage-limits), completions are limited by tokens per minute and requests per second, and limits are shown under Admin Panel > API > Limits. Set [workspace spending limits](https://docs.mistral.ai/admin/workspaces/usage-limits) so a leaked key cannot run up unbounded cost; a workspace that reaches its limit has API access suspended until the next month or until an admin raises it. Give separate applications separate workspaces so each has its own spending cap.
- **Guardrails screen inputs only.** [Moderation and Guardrailing](https://docs.mistral.ai/studio-api/safety-moderation) states that Custom Guardrails run before the request reaches the model and block it with HTTP 403 when triggered. They do not check model outputs, so validate outputs yourself before acting on them.
- **Tool calls are your code.** The [function calling guide](https://docs.mistral.ai/capabilities/function_calling) makes the developer responsible for executing functions. Treat model-generated arguments and any retrieved content as untrusted input, allowlist the functions an agent can reach, and require confirmation for consequential actions.
- **Open weights are a supply chain input.** Self-hosted weights bring licensing terms and model-file risks. Pin the exact model revision you reviewed and follow the guidance in the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) and [AI Infrastructure & MLOps Security](/AI_INFRASTRUCTURE_SECURITY_REFERENCE.md).
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md).

## Learn more

- [Send your first API request](https://docs.mistral.ai/getting-started/quickstarts/developer/first-api-request): key setup and a first call.
- [Models overview](https://docs.mistral.ai/models): current models, versions, and licenses.
- [Function calling](https://docs.mistral.ai/capabilities/function_calling): the tool-calling loop and calling patterns.
- [Moderation and Guardrailing](https://docs.mistral.ai/studio-api/safety-moderation): the moderation API, categories, and Custom Guardrails.
- [mistralai/cookbook](https://github.com/mistralai/cookbook): MIT-licensed example notebooks.
