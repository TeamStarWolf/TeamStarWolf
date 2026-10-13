# Google Gemini API

> In one minute: The Gemini API is Google's hosted developer interface to its Gemini models, managed through Google AI Studio and Google Cloud projects. Developers use it for text, multimodal, live audio, and agent applications through the Google Gen AI SDKs. It matters to defenders because Gemini access rides on Google API keys and project settings, and a 2026 disclosure showed how that can quietly turn ordinary keys into AI credentials.

| | |
|---|---|
| Category | Model platform (API) |
| Maintainer | Google |
| License / access | Commercial API with a free tier; Python SDK is open source (Apache-2.0) |
| Official docs | [ai.google.dev](https://ai.google.dev/gemini-api/docs) |
| Repository | [googleapis/python-genai](https://github.com/googleapis/python-genai) |
| Checked | 8 Oct 2026, hosted service; Python SDK `google-genai` 2.29.0 (released 7 Oct 2026) |

## What it is for

- Text generation, summarization, and extraction with Gemini models.
- Understanding images and documents such as PDFs alongside text prompts.
- Live and realtime audio applications, text-to-speech, and transcription.
- Function calling so a model can request actions in your application.
- Grounding answers with Google Search results.

## Quick start

These steps follow the official quickstart.

1. Create an API key in Google AI Studio.
2. Set the key. The SDK reads `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) automatically.

   macOS or Linux:

   ```bash
   export GEMINI_API_KEY="YOUR_API_KEY"
   ```

   On Windows, add a user environment variable named `GEMINI_API_KEY` in the Environment Variables dialog, then open a new terminal.

3. Install the Google Gen AI SDK:

   ```bash
   pip install -U google-genai
   ```

4. Make a first request with the Interactions API:

   ```python
   from google import genai

   client = genai.Client()  # reads GEMINI_API_KEY

   interaction = client.interactions.create(
       model="gemini-3.8-flash",
       input="Explain how AI works in a few words"
   )
   print(interaction.output_text)
   ```

5. Model codes change over time; check the [models page](https://ai.google.dev/gemini-api/docs/models) for current stable and preview models.

## Key concepts

- **Interactions API**: the recommended, generally available API. Each call creates an Interaction resource that records the turn as execution steps. Set `previous_interaction_id` to continue a conversation.
- **generateContent**: the original API. The docs call it legacy, but it remains fully supported.
- **Models**: stable codes such as `gemini-3.8-flash` and preview codes such as `gemini-3.1-pro-preview`. Preview models have tighter limits.
- **API keys and projects**: keys are created in AI Studio and belong to a Google Cloud project. If both `GOOGLE_API_KEY` and `GEMINI_API_KEY` are set, `GOOGLE_API_KEY` wins.
- **Usage tiers**: Free, Tier 1, Tier 2, and Tier 3, reached through linked billing and cumulative spend.
- **Function calling**: the model returns a function name and arguments. It does not execute anything; your application does.
- **Safety settings**: adjustable content filters on top of the built-in defaults.

## Security notes

- **Handle keys as secrets.** The [API key guide](https://ai.google.dev/gemini-api/docs/api-key) says never commit keys, never embed them in web or mobile clients (use a backend proxy), keep production keys in a secret store such as Secret Manager, and set billing alerts. To rotate, create and deploy a new key, then disable the old one. Restrict each key; the Gemini API rejects unrestricted standard keys, and a key restricted to other APIs will not work for Gemini, so use a dedicated key.
- **Audit legacy Google API keys.** In February 2026 [Truffle Security](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules) reported that enabling the Generative Language API on a project let existing keys in that project, including keys embedded in public pages for services like Maps, authenticate to Gemini. Researchers found more than 2,800 such live keys in public web data. Google classified it as single-service privilege escalation and added blocking for leaked keys. Check every project with the Generative Language API enabled for unrestricted or exposed keys and rotate them.
- **Free and paid data use differ.** Under the [Gemini API terms](https://ai.google.dev/gemini-api/terms), content sent to unpaid services is used to improve Google products and may be read by human reviewers, and the terms say not to submit sensitive, confidential, or personal information to unpaid services. Paid-tier prompts and responses are not used to improve products but are logged for a limited period to detect policy violations. Grounding with Google Search stores prompts and output for 30 days, including on paid quota.
- **Interactions are stored by default.** Per the [Interactions API docs](https://ai.google.dev/gemini-api/docs/interactions), `store` defaults to true, with retention of 55 days on the paid tier and 1 day on the free tier. Set `store=false` or delete interactions you do not need.
- **Rate limits are per project, not per key.** [Rate limits](https://ai.google.dev/gemini-api/docs/rate-limits) cover requests per minute, tokens per minute, and requests per day, and exceeding them returns HTTP 429 `RESOURCE_EXHAUSTED`. Every key in a project shares the same quota, so one leaked key can exhaust or bill the whole project.
- **Prompt injection and tool calls.** Google's [safety and factuality guidance](https://ai.google.dev/gemini-api/docs/safety-guidance) compares prompt injection to SQL injection and notes that narrower tasks and stronger human oversight reduce risk. The [function calling guide](https://ai.google.dev/gemini-api/docs/function-calling) advises validating function calls before executing them and using appropriate authentication for external APIs.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Gemini API quickstart](https://ai.google.dev/gemini-api/docs/quickstart): install the SDK and make a first request.
- [Interactions API](https://ai.google.dev/gemini-api/docs/interactions): stateful turns, storage, and conversation history.
- [Function calling](https://ai.google.dev/gemini-api/docs/function-calling): declaring functions and handling calls.
- [Using Gemini API keys](https://ai.google.dev/gemini-api/docs/api-key): environment variables, restrictions, and key hygiene.
- [Gemini API cookbook](https://github.com/google-gemini/cookbook): Apache-2.0 examples and guides.
