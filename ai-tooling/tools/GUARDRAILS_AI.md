# Guardrails AI

> In one minute: Guardrails AI is an open source Python framework that wraps LLM calls in input and output "guards" built from reusable validators. Developers use it to detect and handle risks such as PII, toxic language, or off-policy content, and to force model output into a structured schema. It gives application teams a simple, testable place to enforce rules on what goes into and comes out of a model.

| | |
|---|---|
| Category | Guardrails |
| Maintainer | Guardrails AI |
| License / access | Open source (Apache-2.0); individual validator packages carry their own licenses (for example MIT) |
| Official docs | [guardrailsai.com](https://guardrailsai.com/guardrails/docs) |
| Repository | [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) |
| Checked | 8 Oct 2026, v0.11.0 (GitHub release and PyPI `guardrails-ai`, 14 Aug 2026) |

## What it is for

- Validating LLM output against rules (format, regex, PII, toxicity, competitor mentions) before it reaches users.
- Validating user input before it is sent to a model.
- Getting structured data from an LLM that matches a Pydantic model.
- Choosing what happens on failure: raise, fix, filter, refrain, or ask the model again.
- Running guards as a separate service with an OpenAI-compatible endpoint, so several apps share one policy.

## Quick start

1. Install the framework.

   ```bash
   pip install guardrails-ai
   ```

2. Optional: run the CLI setup. It asks whether to enable anonymous metrics reporting.

   ```bash
   guardrails configure
   ```

3. Install a validator. Validators are now standard PyPI packages named `guardrails-ai-<name>`.

   ```bash
   pip install guardrails-ai-regex-match
   ```

4. Create a guard and validate text (official README example: a phone-number pattern).

   ```python
   from guardrails import Guard, OnFailAction
   from guardrails_ai.regex_match import RegexMatch

   guard = Guard().use(
       RegexMatch, regex="\(?\d{3}\)?-? *\d{3}-? *-?\d{4}", on_fail=OnFailAction.EXCEPTION
   )

   guard.validate("123-456-7890")  # Guardrail passes

   try:
       guard.validate("1234-789-0000")  # Guardrail fails
   except Exception as e:
       print(e)
   ```

5. Combine several validators in one guard by passing more than one to `Guard().use(...)`, for example `guardrails-ai-detect-pii` with your own rules.

## Key concepts

- **Guard**: The object that runs validators on LLM inputs or outputs, or wraps the LLM call itself.
- **Validator**: A check that returns a pass result, or a fail result that triggers the configured on-fail action. You can write custom validators.
- **On-fail actions**: `exception`, `fix`, `filter`, `refrain`, `reask`, `noop`, `fix_reask`, and `custom`, available as `OnFailAction` values.
- **Guardrails Hub**: The catalog of pre-built validators. Since July 2026 validators are moving to public PyPI packages that import from the `guardrails_ai` namespace; registered names such as `guardrails/detect_pii` stay the same.
- **Structured output**: `Guard.for_pydantic(...)` asks the model for output that matches a Pydantic class, using function calling where supported.
- **Guardrails server**: `guardrails start` serves guards over a REST API, including an OpenAI-compatible route per guard.
- **Runtime metadata**: Values some validators need at call time, passed as `metadata` to `guard.validate` or `guard()`.

## Security notes

- Guards are an application-layer control. Pair them with model-level safety, least-privilege tool access, and red team testing, since a validator only catches what it was built to detect.
- Hosted validator inference is being retired. The project announced that `guardrails hub install`, the private validator registry, and the Guardrails-hosted inference servers would stop working by 25 August 2026 (the migration issue also cites 6 August for inference). Validators that used remote inference must run locally (`use_local=True`) or call your own endpoint (`validation_endpoint=...`). Check older deployments for breakage.
- Running validators locally keeps prompts and outputs inside your environment, but model-based validators download and run ML models. Pin validator versions and install only the official `guardrails-ai-*` packages from PyPI.
- For security rules, prefer `exception`, `filter`, or `refrain` over `noop`, which lets failing content through. A `reask` sends the failing content back to the LLM for another try, which adds cost and latency.
- `guardrails configure` asks whether to enable anonymous metrics reporting. Review that choice on build agents and servers.
- Keep provider keys in environment variables, not in guard configs committed to source control.
- For the threats these controls address, see the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Guardrails documentation](https://guardrailsai.com/guardrails/docs)
- [Quickstart](https://guardrailsai.com/guardrails/docs/getting_started/quickstart)
- [Validators concept guide](https://guardrailsai.com/guardrails/docs/concepts/validators)
- [Guardrails Hub](https://guardrailsai.com/hub)
- [Validator migration to PyPI and end of hosted inference (issue 1560)](https://github.com/guardrails-ai/guardrails/issues/1560)
