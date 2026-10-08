# garak

> In one minute: garak (Generative AI Red-teaming and Assessment Kit) is NVIDIA's open source command-line scanner for LLM weaknesses. It sends batteries of probes to a model or dialog system and uses detectors to flag failures such as prompt injection, data leakage, toxic output, and hallucination. Its maintainers compare it to nmap or Metasploit, but for language models, and it is meant for testing models and applications you own or are authorized to assess.

| | |
|---|---|
| Category | AI red teaming |
| Maintainer | NVIDIA |
| License / access | Open source (Apache-2.0) |
| Official docs | [docs.garak.ai](https://docs.garak.ai/) (user guide) and [reference.garak.ai](https://reference.garak.ai/en/latest/) (reference) |
| Repository | [NVIDIA/garak](https://github.com/NVIDIA/garak) |
| Checked | 8 Oct 2026, v0.17.0 (GitHub release and PyPI `garak`, 9 Sep 2026) |

## What it is for

- Scanning a model before deployment for known failure modes: prompt injection, encoding-based injection, jailbreak susceptibility, data leakage, toxicity, and misinformation.
- Comparing models, or versions of one model, on the same probe set to see whether safety tuning or guardrails helped.
- Testing a whole application through its REST API, not just the base model, using the REST generator.
- Grouping results by a taxonomy such as OWASP to feed a risk register.
- Re-running the same scan in a pipeline after model, prompt, or guardrail changes.

## Quick start

Run scans only against models and endpoints you own or have written permission to test. Start with a local model.

1. Install garak (Python 3.11 or later) in its own environment.

   ```bash
   python -m pip install -U garak
   ```

2. List the available probes.

   ```bash
   garak --list_probes
   ```

3. Check your setup without a real model, using the built-in test generator, which always returns an empty string.

   ```bash
   python -m garak --target_type test.Blank --spec probes.encoding
   ```

4. Scan a small local Hugging Face model with the encoding-based prompt injection probes. The model downloads from the Hub and runs on your machine.

   ```bash
   python -m garak --target_type huggingface --target_name gpt2 --spec probes.encoding
   ```

5. Read the results. garak prints a pass/fail row per probe and detector, writes a JSONL report and a hit log for the run (file names are printed at the start and end), and appends debug output to `garak.log`.

For a hosted model, set the provider key as an environment variable (for example `OPENAI_API_KEY` with `--target_type openai`), never on the command line.

## Key concepts

- **Generator**: The connector to the system under test, chosen with `--target_type` and `--target_name`. Types include Hugging Face, OpenAI, Bedrock, NIM, LiteLLM, GGUF models, and generic REST endpoints.
- **Probe**: A module that generates interactions designed to make the model fail in a specific way. Probes are grouped into families such as `encoding`, `promptinject`, and `lmrc`.
- **Detector**: Checks each output for a given failure mode. Each probe recommends its own detectors.
- **Harness**: Structures the run. The default `probewise` harness runs each probe with its recommended detectors.
- **Evaluator**: Turns detector results into the reported pass/fail rates.
- **Spec**: The `--spec` option selects probes by module, class, or tag (for example `tag:owasp:llm01`). It replaces the deprecated `--probes` option.
- **Generations**: Each prompt is sent several times (10 by default), so results are failure rates, not single answers.

## Security notes

- Authorization comes first. garak sends adversarial traffic by design. Get written approval, scope the target, and tell the owners of any shared endpoint, rate limit, or monitoring system before you scan.
- Prefer local or staging targets. Scans against hosted APIs generate many requests and can incur cost or trip abuse detection on your account.
- Reports and hit logs contain the adversarial prompts and any harmful output the model produced. Store them as sensitive test evidence with restricted access.
- Keep API keys in environment variables or a garak config file excluded from version control.
- Use `--taxonomy` (for example `owasp`) to group findings, then map them to the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), and [MITRE ATLAS Reference](/ATLAS_REFERENCE.md). The [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md) gives real-world context.
- A clean scan is not proof of safety. Probes cover known patterns, and adaptive attackers can find others. Pair scanning with guardrails, monitoring, and manual testing.
- Install from PyPI or the official repository only, and pin the version you validated.

## Learn more

- [garak user guide](https://docs.garak.ai/)
- [Reference documentation](https://reference.garak.ai/en/latest/)
- [CLI reference](https://reference.garak.ai/en/latest/cliref.html)
- [Project home](https://garak.ai/)
- [Paper: garak, A Framework for Security Probing Large Language Models](https://arxiv.org/abs/2406.11036)
