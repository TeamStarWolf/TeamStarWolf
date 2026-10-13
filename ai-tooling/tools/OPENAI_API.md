# OpenAI API

> In one minute: The OpenAI API is OpenAI's hosted interface to its GPT models for text, images, speech, and realtime voice. Developers call it from servers and tools through official SDKs or plain HTTPS. It sits behind a large share of AI applications, so its key handling, data controls, and tool-calling behavior shape the risk of many systems defenders have to protect.

| | |
|---|---|
| Category | Model platform (API) |
| Maintainer | OpenAI |
| License / access | Commercial API with usage-based billing; a Free usage tier exists in allowed geographies; Python SDK is open source (Apache-2.0) |
| Official docs | [developers.openai.com](https://developers.openai.com/api/docs) |
| Repository | [openai/openai-python](https://github.com/openai/openai-python) |
| Checked | 8 Oct 2026, hosted service; Python SDK `openai` 3.26.0 (released 6 Oct 2026) |

## What it is for

- Generating and transforming text, code, and structured data with the Responses API.
- Connecting models to your own functions and APIs through function calling.
- Speech-to-text, text-to-speech, and realtime voice applications.
- Image generation and editing.
- Specialized models, such as a cybersecurity model offered for authorized vulnerability research and security testing.

## Quick start

These steps follow the official developer quickstart.

1. Create an API key in the OpenAI API platform.
2. Export the key. The SDK reads `OPENAI_API_KEY` automatically.

   macOS or Linux:

   ```bash
   export OPENAI_API_KEY="YOUR_API_KEY"
   ```

   Windows (the docs use `setx`; open a new terminal afterward):

   ```powershell
   setx OPENAI_API_KEY "YOUR_API_KEY"
   ```

3. Install the Python SDK:

   ```bash
   pip install openai
   ```

4. Make a first request:

   ```python
   from openai import OpenAI

   client = OpenAI()  # reads OPENAI_API_KEY

   response = client.responses.create(
       model="gpt-6-astra",
       input="Write a one-sentence bedtime story about a unicorn.",
   )

   print(response.output_text)
   ```

5. Model IDs change over time; check the [models page](https://developers.openai.com/api/docs/models) for current IDs.

## Key concepts

- **Responses API**: the main generation endpoint (`client.responses.create`). It takes `input` and returns output items; `output_text` is a convenience accessor for the text.
- **Chat Completions**: the older message-list endpoint, still supported.
- **Models**: IDs such as `gpt-6-astra` (flagship), `gpt-6.1-sol`, and `gpt-6-luna`, plus speech, realtime, image, and specialized models.
- **Function calling**: you describe tools in the request, the model may return a tool call, your application runs it and sends the output back, and the model answers or calls again.
- **Organizations and projects**: rate limits apply at both levels, data residency is set per project, and separate projects isolate staging from production.
- **Usage tiers**: rate limits rise automatically as cumulative credit purchases cross each tier threshold.
- **Stored state**: some objects (stored responses, conversations, files, vector stores, fine-tuning jobs, batches) persist on OpenAI servers.

## Security notes

- **Keep keys out of code and split environments.** The [production best practices](https://developers.openai.com/api/docs/guides/production-best-practices) guide says to supply keys through environment variables or a secrets manager and to use separate projects for staging and production. Turn on per-key usage tracking and review the Usage page for anomalies. GitHub secret scanning includes a pattern for OpenAI API keys (see the [supported patterns list](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)).
- **Default data use.** Per [data controls](https://developers.openai.com/api/docs/guides/your-data), API data is not used to train OpenAI models unless you opt in. Abuse monitoring logs are kept for up to 30 days. Zero data retention and Modified Abuse Monitoring remove customer content from those logs, but both need OpenAI approval through sales.
- **Turn off storage you do not need.** Responses are stored for 30 days by default; set `store` to `false` when you do not need server-side state. Conversations, files, vector stores, fine-tuning jobs, batches, and evals persist until you delete them and are not covered by zero data retention.
- **Data residency is per project.** Regional processing is offered in the US, EU, and UAE through regional hostnames such as `eu.api.openai.com`. Non-US regions require approval and contract amendments.
- **Plan for rate limits.** [Rate limits](https://developers.openai.com/api/docs/guides/rate-limits) apply at the organization and project level as RPM, RPD, TPM, TPD, and IPM. Exceeding them returns HTTP 429 (`rate_limit_error`); a hard spend limit also returns 429. Read the `x-ratelimit-*` headers and honor `Retry-After`. Project-level limits help contain a leaked key or runaway job.
- **Treat untrusted text as hostile when tools are attached.** OpenAI's [agent safety guide](https://developers.openai.com/api/docs/guides/agent-builder-safety) (written for Agent Builder, which OpenAI is retiring on 30 Nov 2026) advises passing untrusted input through user messages rather than developer messages, using structured outputs between steps, extracting only validated fields, and keeping MCP tool approvals on. It warns that guardrails are a useful first layer but not foolproof.
- **Test and constrain.** The [safety best practices](https://developers.openai.com/api/docs/guides/safety-best-practices) recommend adversarial testing that includes prompt injection, human review for high-stakes output, input and output length limits, and a hashed `safety_identifier` per end user so abuse can be traced without sharing personal data.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Developer quickstart](https://developers.openai.com/api/docs/quickstart): key setup and a first request in several languages.
- [Text generation](https://developers.openai.com/api/docs/guides/text): prompting and structuring requests with the Responses API.
- [Function calling](https://developers.openai.com/api/docs/guides/function-calling): defining tools and handling tool calls.
- [OpenAI Cookbook](https://developers.openai.com/cookbook): recipes and worked examples.
- [openai/openai-cookbook](https://github.com/openai/openai-cookbook): the MIT-licensed source notebooks for the cookbook.
