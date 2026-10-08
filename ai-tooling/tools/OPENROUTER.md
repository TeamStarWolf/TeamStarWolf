# OpenRouter

> In one minute: OpenRouter is a hosted gateway that gives access to hundreds of models from many providers through one OpenAI-compatible API, one key, and one credit balance. Developers use it to switch models, get automatic provider fallbacks, and compare vendors without separate accounts. It matters to defenders because every prompt passes through an extra party and then to an upstream provider whose data policy may differ, so routing and privacy settings decide where your data actually goes.

| | |
|---|---|
| Category | LLM gateway |
| Maintainer | OpenRouter |
| License / access | Commercial hosted service with prepaid credits; free model variants exist with lower rate limits; Python SDK is open source (Apache-2.0) |
| Official docs | [openrouter.ai/docs](https://openrouter.ai/docs/quickstart) |
| Repository | [OpenRouterTeam/python-sdk](https://github.com/OpenRouterTeam/python-sdk) (official Python SDK) |
| Checked | 8 Oct 2026, hosted service; Python SDK `openrouter` 1.3.33 (released 8 Oct 2026) |

## What it is for

- Calling models from many vendors with one API key and one endpoint.
- Reusing existing OpenAI SDK code by changing only the base URL.
- Routing each request across providers by price, latency, or a fixed order, with automatic fallbacks.
- Falling back to a different model when every provider for the first one fails.
- Enforcing spend limits, model allowlists, and data policies per key or team member.
- Using your own provider keys (BYOK) while keeping OpenRouter's routing.

## Quick start

These steps follow the official quickstart.

1. Sign in, open the Keys page in your account settings, create a key, and give it a credit limit.
2. Export it (macOS or Linux):

   ```bash
   export OPENROUTER_API_KEY="YOUR_API_KEY"
   ```

3. Send a first request with cURL:

   ```bash
   curl https://openrouter.ai/api/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     -d '{
     "model": "~openai/gpt-sol-latest",
     "messages": [
       {
         "role": "user",
         "content": "What is the meaning of life?"
       }
     ]
   }'
   ```

4. Or use the official Python SDK:

   ```bash
   pip install openrouter
   ```

   ```python
   from openrouter import OpenRouter
   import os

   with OpenRouter(api_key=os.getenv("OPENROUTER_API_KEY")) as client:
       response = client.chat.send(
           model="~openai/gpt-sol-latest",
           messages=[
               {"role": "user", "content": "What is the meaning of life?"}
           ],
       )

       print(response.choices[0].message.content)
   ```

5. Existing OpenAI SDK code works by setting `base_url="https://openrouter.ai/api/v1"` and passing your OpenRouter key. Browse model slugs at [openrouter.ai/models](https://openrouter.ai/models).

## Key concepts

- **Model slug**: `vendor/model`. A `~` prefix marks a "latest" alias, such as `~openai/gpt-sol-latest`, that resolves to the newest model in a family. IDs ending in `:free` are free variants.
- **Providers and endpoints**: one model can be served by several providers. By default requests are load balanced across top providers, weighted by price.
- **`provider` object**: per-request routing controls such as `order`, `allow_fallbacks`, `only`, `ignore`, `data_collection`, and `zdr`.
- **Model fallbacks**: a list of alternate models to try when all providers for the first model are exhausted.
- **Credits and key limits**: usage draws on a prepaid balance; each key can carry its own credit limit that resets daily, weekly, or monthly.
- **Guardrails**: workspace rules assigned to members or API keys (budgets, allowlists, data policies, content filters).
- **BYOK**: your own provider keys, stored encrypted by OpenRouter, used for requests to that provider.

## Security notes

- **Cap every key.** The [authentication docs](https://openrouter.ai/docs/api/reference/authentication) recommend a credit limit on every key, because an unlimited key lets a leaked key or runaway agent spend the whole balance, including auto top-ups. Never commit keys or ship them in client-side code. OpenRouter is a GitHub secret scanning partner and emails you when it detects an exposed key; delete it and create a new one right away.
- **Your data takes two hops.** OpenRouter states it does not retain prompts unless you opt in to prompt logging, but each upstream provider has its own retention and training terms ([provider logging](https://openrouter.ai/docs/guides/privacy/provider-logging)). In privacy settings you can block providers that may train on prompts. Per request, `data_collection: "deny"` limits routing to providers that do not collect user data.
- **Enforce zero data retention where needed.** [ZDR](https://openrouter.ai/docs/guides/features/zdr) can be required account-wide, per model group, per guardrail, or per request with `zdr: true`; the request flag can only tighten, not loosen, other settings. ZDR covers inference routing only. Server tools and plugins such as web search follow the third party's policy, and OpenRouter does not count in-memory prompt caching as retention.
- **Watch BYOK fallback.** Per the [BYOK guide](https://openrouter.ai/docs/guides/overview/auth/byok), if all your provider keys hit rate limits or fail, requests fall back to shared OpenRouter endpoints by default, which may carry different terms than your own provider agreement.
- **Plan for limits.** Per [Limits](https://openrouter.ai/docs/api/reference/limits), exhausted credits or key limits return HTTP 402 with `error.metadata.limit_source`, and rate limits return 429 either from OpenRouter (free-model caps, DDoS protection) or from the upstream provider. Call `GET /api/v1/key` to monitor remaining credit before requests fail.
- **Guardrails help but regex is a first filter.** [Guardrails](https://openrouter.ai/docs/guides/features/guardrails) add budgets, model and provider allowlists, ZDR, PII redaction, and regex-based [prompt injection detection](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection) that can flag, redact, or block matches. Pattern matching misses novel phrasing, so keep tool permissions narrow and treat tool output as untrusted.
- **Pin model slugs after review.** A `~...-latest` alias can change the underlying model without a redeploy. Pin an explicit slug for workflows that passed security review or evaluations.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

## Learn more

- [Quickstart](https://openrouter.ai/docs/quickstart): direct API, client SDKs, and the OpenAI SDK.
- [Provider routing](https://openrouter.ai/docs/guides/routing/provider-selection): ordering, fallbacks, data policies, and price limits.
- [Model fallbacks](https://openrouter.ai/docs/guides/routing/model-fallbacks): trying alternate models automatically.
- [Zero Data Retention](https://openrouter.ai/docs/guides/features/zdr): enforcement scopes and ZDR endpoint lists.
- [Guardrails](https://openrouter.ai/docs/guides/features/guardrails): budgets, allowlists, and content filters per key or member.
