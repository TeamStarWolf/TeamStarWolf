# Langfuse

> In one minute: Langfuse is an open source platform for tracing, evaluating, and managing LLM applications and agents. Engineering and platform teams use it to see every model call, tool call, and retrieval step in a request, along with cost, latency, and quality scores. It can run as a managed cloud service or be self-hosted, which matters when traces contain sensitive prompts and data.

| | |
|---|---|
| Category | Observability |
| Maintainer | Langfuse, part of ClickHouse since January 2026 |
| License / access | Open source (MIT), except the `ee` folders, which hold enterprise features that need a license key; managed Langfuse Cloud also available |
| Official docs | [langfuse.com](https://langfuse.com/docs) |
| Repository | [langfuse/langfuse](https://github.com/langfuse/langfuse) |
| Checked | 8 Oct 2026, server v4.54.0 (GitHub release, 7 Oct 2026); Python SDK `langfuse` v4.17.0 |

## What it is for

- Debugging agents and RAG pipelines by following one request through every nested LLM call, tool call, and retrieval step.
- Grouping multi-turn conversations into sessions and tracking which end user triggered each trace.
- Versioning prompts and deploying them to environments with labels, outside the application code.
- Scoring traces with LLM-as-a-judge evaluators, user feedback, or custom scores, and running experiments against datasets.
- Watching quality, cost, and latency on dashboards.

## Quick start

1. Run Langfuse locally with Docker Compose. Before starting, replace every secret marked `# CHANGEME` in `docker-compose.yml` with a long random value.

   ```bash
   git clone https://github.com/langfuse/langfuse.git
   cd langfuse
   docker compose up
   ```

2. When the `langfuse-web-1` container logs "Ready", open `http://localhost:3000`, sign up (there is no default login), create an organization and project, and create API keys.

3. In your application environment, install the SDK and set the keys.

   ```bash
   pip install langfuse openai
   export LANGFUSE_PUBLIC_KEY="pk-lf-..."
   export LANGFUSE_SECRET_KEY="sk-lf-..."
   export LANGFUSE_BASE_URL="http://localhost:3000"
   export OPENAI_API_KEY="<your-key>"
   ```

4. Trace an OpenAI call by swapping the import for the Langfuse wrapper.

   ```python
   from langfuse.openai import openai

   completion = openai.chat.completions.create(
     name="test-chat",
     model="gpt-4o",
     messages=[
         {"role": "system", "content": "You are a very accurate calculator. You output only the result of the calculation."},
         {"role": "user", "content": "1 + 1 = "}],
     metadata={"someMetadataKey": "someValue"},
   )
   ```

5. Open the project in the Langfuse UI to view the trace. In short-lived scripts, call `flush()` on the client from `langfuse.get_client()` before exit so events are sent.

## Key concepts

- **Trace**: One request or operation, such as a single chatbot exchange from question to answer. It groups all observations with the same trace ID.
- **Observation**: One step inside a trace, such as an LLM call, tool call, or retrieval. Observations nest. Types include span, generation (an LLM call), and event.
- **Session**: A group of traces from the same user interaction, such as a chat thread.
- **User and environment**: Trace attributes for the end user and the deployment context, such as production or staging.
- **Score**: An evaluation result attached to a trace, as a number, boolean, or category.
- **Prompt management**: Versioned prompts served to the app and promoted with labels.
- **Datasets and experiments**: Collections of test cases, and runs of prompts or models against them.
- **OpenTelemetry**: Langfuse is built on OpenTelemetry, so traces can come from non-Langfuse SDKs and also go to other backends.

## Security notes

- Traces are a security asset: they show which tools an agent called, what it retrieved, and what it returned. They help investigate prompt injection, data leakage, and misuse.
- Traces also hold full prompts, outputs, and retrieved documents. Treat the Langfuse databases and blob storage as sensitive, restrict project access, and keep traces only as long as your data policy allows.
- Mask sensitive data in the SDK before it leaves the application. Server-side ingestion masking is also available but requires an Enterprise license.
- For self-hosting, set strong unique values for `ENCRYPTION_KEY` (64 hex characters), `SALT`, and `NEXTAUTH_SECRET`, and change every `# CHANGEME` secret in the Compose file.
- The Docker Compose setup is for trying Langfuse. It lacks high availability, scaling, and backups. Use the Kubernetes (Helm) or cloud guides for production.
- Treat `LANGFUSE_SECRET_KEY` like a password: keep it in environment variables or a secret store, never in client-side code or repositories.
- Use traces when mapping incidents to the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Langfuse documentation](https://langfuse.com/docs)
- [Get started with tracing](https://langfuse.com/docs/observability/get-started)
- [Observability data model](https://langfuse.com/docs/observability/data-model)
- [Self-hosting overview](https://langfuse.com/self-hosting) and [Docker Compose deployment](https://langfuse.com/self-hosting/deployment/docker-compose)
- [Data masking](https://langfuse.com/self-hosting/security/data-masking)
- [Langfuse joins ClickHouse](https://langfuse.com/blog/joining-clickhouse)
