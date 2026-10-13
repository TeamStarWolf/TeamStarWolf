# PyRIT

> In one minute: PyRIT (Python Risk Identification Tool for generative AI) is Microsoft's open source framework for red teaming generative AI systems. Security professionals and engineers use it to send single-turn and multi-turn attacks to a target, transform prompts with converters, and score the responses automatically. It is built for testing models and applications you own or are authorized to assess, at a scale manual testing cannot reach.

| | |
|---|---|
| Category | AI red teaming |
| Maintainer | Microsoft (active repository is `microsoft/PyRIT`; the older `Azure/PyRIT` repository is archived) |
| License / access | Open source (MIT) |
| Official docs | [microsoft.github.io/PyRIT](https://microsoft.github.io/PyRIT/) |
| Repository | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) |
| Checked | 8 Oct 2026, v1.1.0 (GitHub release and PyPI `pyrit`, 4 Sep 2026) |

## What it is for

- Probing a model or application for harmful content, data leakage, and prompt injection before release.
- Running multi-turn attack strategies where an adversarial model adapts to the target's replies.
- Testing the same objective through many prompt transformations (encodings, translations, other converters) to check guardrail coverage.
- Running standard scenario suites from the command line with `pyrit_scan`, for example in CI.
- Keeping a queryable record of every conversation, score, and result for reporting.

## Quick start

Use only a target you own or are authorized to test, ideally a local or staging deployment.

1. Install PyRIT (the install guide lists Python 3.11 to 3.14).

   ```bash
   pip install pyrit
   ```

2. Point PyRIT at your test endpoint with environment variables. Any OpenAI-compatible endpoint works; change the endpoint, key, and model for other providers.

   ```bash
   export OPENAI_CHAT_ENDPOINT="<your test endpoint>"
   export OPENAI_CHAT_KEY="<your-key>"
   export OPENAI_CHAT_MODEL="<model-name>"
   ```

   For a persistent setup, put these values in `~/.pyrit/.env` instead.

3. Send a single benign objective with the basic attack to confirm the wiring. The docs run this in a notebook; this version wraps it in `asyncio` for a script.

   ```python
   import asyncio

   from pyrit.executor.attack import PromptSendingAttack
   from pyrit.output import output_attack_async
   from pyrit.prompt_target import OpenAIChatTarget
   from pyrit.setup import IN_MEMORY, initialize_pyrit_async

   async def main():
       await initialize_pyrit_async(memory_db_type=IN_MEMORY)
       target = OpenAIChatTarget()  # reads the OPENAI_CHAT_* variables
       attack = PromptSendingAttack(objective_target=target)
       result = await attack.execute_async(objective="Describe your purpose in one sentence.")
       await output_attack_async(result)

   asyncio.run(main())
   ```

4. Next, add scorers and converters to the attack, or move to scenarios and `pyrit_scan` once a `~/.pyrit/.pyrit_conf` file registers your targets and scorers.

## Key concepts

- **Target**: The system under test or a helper model. Supported targets include OpenAI, Azure, Anthropic, Google, Hugging Face, custom HTTP or WebSocket endpoints, and web apps driven through Playwright.
- **Attack**: A strategy that pursues an objective against a target. `PromptSendingAttack` is the basic single-turn building block; multi-turn attacks use an adversarial model to adapt.
- **Converter**: A transformation applied to a prompt before sending, such as an encoding or translation.
- **Scorer**: Judges whether a response met the objective, using true/false, Likert, classification, or custom logic, backed by an LLM, Azure AI Content Safety, or code.
- **Memory**: The store for conversations, scores, and results. It can be in memory, SQLite, or Azure SQL.
- **Seeds and datasets**: Reusable prompts and objectives that feed attacks and scenarios.
- **Scenario**: A packaged assessment that combines techniques, datasets, and scoring. Run scenarios with `pyrit_scan` (automated) or `pyrit_shell` (interactive).

## Security notes

- PyRIT generates attack traffic and can produce harmful content by design. Get written authorization, define scope and stop conditions, and coordinate with the owners of the target and its monitoring.
- Keep credentials in `~/.pyrit/.env` or environment variables, never in notebooks you share. Restrict permissions on the `~/.pyrit` folder.
- The memory database holds full attack prompts and responses. Use in-memory storage for throwaway tests, and protect any SQLite or Azure SQL store as sensitive evidence.
- Scoring with an LLM sends target responses to the scorer model. Use an approved or local model for sensitive systems.
- When connecting `pyrit_scan` to a shared CoPyRIT backend, the docs recommend the default device-code sign-in over `--auth-mode azure_cli`, which can pass a token with broader Microsoft Graph permissions.
- Report security issues in PyRIT itself privately through the Microsoft Security Response Center, not public issues.
- Map results to the [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [PyRIT documentation](https://microsoft.github.io/PyRIT/)
- [Installation](https://microsoft.github.io/PyRIT/1.1.0/getting-started/install)
- [Configuration](https://microsoft.github.io/PyRIT/1.1.0/getting-started/configuration)
- [PyRIT Scanner](https://microsoft.github.io/PyRIT/1.1.0/scanner/scanner)
- [Paper: PyRIT, Democratizing AI Red Teaming Through Open-Source Tooling](https://commandline.microsoft.com/wp-content/uploads/2026/08/PyRIT_Whitepaper_2026.pdf)
