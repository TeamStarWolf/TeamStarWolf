# Inspect

> In one minute: Inspect is a Python framework for running evaluations of large language models, including agent and tool-use evaluations. It was created by the UK AI Security Institute and helps researchers and safety teams measure coding, reasoning, knowledge, and agentic behavior in a repeatable way. It ships with a log viewer, a sandboxing system for untrusted model actions, and a large set of ready-made benchmarks.

| | |
|---|---|
| Category | Evaluation |
| Maintainer | UK AI Security Institute and Meridian Labs (repository under the UKGovernmentBEIS GitHub organization) |
| License / access | Open source (MIT) |
| Official docs | [inspect.aisi.org.uk](https://inspect.aisi.org.uk/) |
| Repository | [UKGovernmentBEIS/inspect_ai](https://github.com/UKGovernmentBEIS/inspect_ai) |
| Checked | 8 Oct 2026, v0.3.277 (PyPI `inspect-ai`, published 6 Oct 2026) |

## What it is for

- Benchmarking a model on question-answering, reasoning, or knowledge datasets with automatic scoring.
- Evaluating agents that use tools such as bash, Python, text editing, web browsing, and MCP tools over many turns.
- Running capture the flag style cyber evaluations where the model acts inside an isolated sandbox.
- Running ready-made benchmarks (the docs list over 200) against any supported model instead of writing new ones.
- Comparing hosted and local models (Hugging Face, vLLM, SGLang) with the same task code.

## Quick start

1. Install Inspect.

   ```bash
   pip install inspect-ai
   ```

2. Install the client for your model provider and set its key in the environment.

   ```bash
   pip install openai
   export OPENAI_API_KEY="<your-key>"
   ```

3. Save the official "Hello, Inspect" task as `simpleqa.py`.

   ```python
   from inspect_ai import Task, task
   from inspect_ai.dataset import FieldSpec, hf_dataset
   from inspect_ai.scorer import model_graded_qa
   from inspect_ai.solver import generate

   @task
   def simpleqa():
       return Task(
           dataset=hf_dataset(
               "codelion/SimpleQA-Verified",
               split="train",
               sample_fields=FieldSpec(
                   input="problem",
                   target="answer",
               ),
           ),
           solver=generate(),
           scorer=model_graded_qa(),
       )
   ```

4. Run the eval, choosing a model with `--model` in `provider/model` form.

   ```bash
   inspect eval simpleqa.py --model openai/gpt-5
   ```

5. Open the log viewer to browse samples, scores, and transcripts.

   ```bash
   inspect view
   ```

## Key concepts

- **Task**: The unit of evaluation. It combines a dataset, a solver, and a scorer. The `@task` decorator lets `inspect eval` find it by name.
- **Dataset**: Labelled samples, usually with an `input` (the prompt) and a `target` (the ideal answer or grading guidance). CSV, JSON, Hugging Face, and in-memory datasets are supported.
- **Solver**: Produces the answer for each sample. It can be a single `generate()` call or a full agent.
- **Scorer**: Grades the output with text comparison, a model grader, or custom logic.
- **Agents and tools**: Built-in agents such as `react()`, multi-agent primitives, built-in tools, and support for running external coding agents.
- **Sandbox**: An isolated environment (Docker built in; Kubernetes, Modal, Proxmox, Vagrant and others through extensions) where tool calls and model-written code run.
- **Eval log**: A record of each run, written to `./logs` by default in the `.eval` format, holding inputs, outputs, scores, message history, and an event transcript.

## Security notes

- Inspect is a measurement tool for a defensive program: use it to test whether a model or agent can be misused, and to check that safety mitigations hold before deployment.
- Use a real sandbox for any task where the model runs commands or code. The `local` sandbox has no isolation and runs as your user.
- The auto-generated Docker sandbox config sets `network_mode: none`. A custom Compose file replaces that default, so add `network_mode: none` yourself unless the task needs network access.
- Sandboxing covers only work sent through the sandbox interface. Code in custom tools, agents, or scorers runs in the eval process and can reach the internet.
- Eval logs store prompts, model outputs, and some raw API requests and responses. Treat them as sensitive, keep them out of public repositories, and set `INSPECT_LOG_DIR` to a controlled location.
- Keep provider keys in environment variables or a `.env` file excluded from version control.
- Cyber and agentic evals can produce working attack steps. Run them only against lab targets you control. Related threats are covered in the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Inspect documentation home](https://inspect.aisi.org.uk/)
- [Tutorial](https://inspect.aisi.org.uk/tutorial.html)
- [Agents](https://inspect.aisi.org.uk/agents.html)
- [Sandboxing](https://inspect.aisi.org.uk/sandboxing.html)
- [Eval logs](https://inspect.aisi.org.uk/eval-logs.html)
- [Inspect Evals collection](https://github.com/UKGovernmentBEIS/inspect_evals)
