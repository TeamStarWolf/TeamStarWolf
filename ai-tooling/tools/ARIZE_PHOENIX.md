# Arize Phoenix

> In one minute: Phoenix is an AI observability and evaluation platform from Arize AI. Developers run it locally or self-host it to collect OpenTelemetry traces from LLM apps and agents, then score them with LLM-as-a-judge or code evaluators. It helps teams see what an application actually did on each request and test changes to prompts and models against datasets.

| | |
|---|---|
| Category | Observability |
| Maintainer | Arize AI |
| License / access | Elastic License 2.0 (ELv2) for the Phoenix server and `arize-phoenix-evals`; the `arize-phoenix-otel` and OpenInference instrumentation packages are Apache-2.0; free to self-host |
| Official docs | [arize.com/docs/phoenix](https://arize.com/docs/phoenix) |
| Repository | [Arize-ai/phoenix](https://github.com/Arize-ai/phoenix) |
| Checked | 8 Oct 2026, v20.19.0 (PyPI `arize-phoenix`, published 1 Oct 2026) |

## What it is for

- Tracing LLM calls, tool calls, and retrieval steps from many frameworks through OpenTelemetry auto-instrumentation.
- Scoring outputs for accuracy, groundedness, relevance, and safety with LLM-as-a-judge or deterministic evaluators.
- Running experiments that compare prompt, model, or retrieval changes against versioned datasets.
- Managing prompt versions and testing them in the Playground.
- Running a fully local, air-gapped observability stack for sensitive workloads.

## Quick start

1. Start Phoenix locally. The UI and OTLP HTTP endpoint are on port 6006 (`http://localhost:6006`); OTLP gRPC uses port 4317.

   ```bash
   pip install arize-phoenix
   phoenix serve
   ```

2. In your application environment, install the tracing wrapper and the OpenAI instrumentation.

   ```bash
   pip install arize-phoenix-otel openinference-instrumentation-openai openai
   ```

3. Point the app at Phoenix and set your model key.

   ```bash
   export PHOENIX_COLLECTOR_ENDPOINT="http://localhost:6006"
   export OPENAI_API_KEY="<your-key>"
   ```

4. Register a tracer with auto-instrumentation, then call the model as usual.

   ```python
   import openai
   from phoenix.otel import register

   tracer_provider = register(
       project_name="my-llm-app",
       auto_instrument=True,
   )

   client = openai.OpenAI()
   response = client.chat.completions.create(
       model="gpt-4o",
       messages=[{"role": "user", "content": "Write a haiku."}],
   )
   print(response.choices[0].message.content)
   ```

5. Open `http://localhost:6006` and select the project to see the trace in the Traces view.

## Key concepts

- **Project**: A container for traces from one application. It is created the first time the app sends data.
- **Trace and span**: A trace is one request; spans are its steps (LLM call, tool call, retrieval), following OpenTelemetry.
- **OpenInference**: An Apache-2.0 project of OpenTelemetry instrumentation for AI observability. Phoenix uses it to auto-instrument installed LLM SDKs and frameworks.
- **Evaluators**: LLM-as-a-judge or code-based checks (exact match, regex, custom logic) that score traces, experiment results, or datasets.
- **Datasets and experiments**: Versioned example sets, and runs that compare app versions against them.
- **Prompt management and Playground**: Versioned, tagged prompts that can be tested interactively.
- **API keys**: System keys for automation and user keys tied to a person, used once authentication is enabled.

## Security notes

- Traces show the full path of an agent request, which supports incident review for prompt injection, data leakage, and tool misuse.
- Authentication is off by default. For any shared deployment, set `PHOENIX_ENABLE_AUTH=True` and a long random `PHOENIX_SECRET`, and store both in a secret store.
- With auth on, the first login is `admin@localhost` with password `admin` and you are prompted to change it. Set `PHOENIX_DEFAULT_ADMIN_INITIAL_PASSWORD` to avoid a known default.
- Send API keys as a bearer token or through `PHOENIX_API_KEY`. Set `PHOENIX_USE_SECURE_COOKIES=True` when serving over HTTPS.
- Phoenix collects basic web analytics from its UI, not trace data. Disable it with `PHOENIX_TELEMETRY_ENABLED=false`. For air-gapped sites, `PHOENIX_ALLOW_EXTERNAL_RESOURCES=false` also blocks fonts, update checks, and other outbound requests.
- Traces contain prompts, outputs, and retrieved documents. Limit who can read projects, and do not expose port 6006 to untrusted networks.
- Relate trace findings to the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Phoenix documentation](https://arize.com/docs/phoenix)
- [Tracing quickstart](https://arize.com/docs/phoenix/get-started/get-started-tracing)
- [OpenAI tracing integration](https://arize.com/docs/phoenix/integrations/llm-providers/openai/openai-tracing)
- [Evaluation](https://arize.com/docs/phoenix/evaluation/llm-evals)
- [Authentication](https://arize.com/docs/phoenix/self-hosting/features/authentication) and [privacy settings](https://arize.com/docs/phoenix/self-hosting/security/privacy)
- [OpenInference repository](https://github.com/Arize-ai/openinference)
