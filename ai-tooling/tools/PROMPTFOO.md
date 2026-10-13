# promptfoo

> In one minute: promptfoo is a command-line tool and library for testing LLM applications. Developers and security teams use it to compare prompts and models against test cases, and to run automated red team scans against their own apps, agents, and RAG pipelines. It turns "the model seems fine" into repeatable tests that can run in CI.

| | |
|---|---|
| Category | Evaluation and red teaming |
| Maintainer | Promptfoo, now part of OpenAI (acquisition announced 9 March 2026; the project states it remains open source and MIT licensed) |
| License / access | Open source (MIT) |
| Official docs | [promptfoo.dev](https://www.promptfoo.dev/docs/intro/) |
| Repository | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) |
| Checked | 8 Oct 2026, v0.124.0 (npm `promptfoo`, published 6 Oct 2026) |

## What it is for

- Comparing several prompts or models side by side on the same test cases before a release.
- Adding regression tests for LLM output to CI/CD, so a prompt or model change that breaks expected behavior fails the build.
- Red teaming an application you own: generating adversarial inputs, sending them to your target, and grading the responses.
- Producing a red team report to support pre-deployment risk decisions. The red team guide discusses frameworks such as the OWASP LLM Top 10, the NIST AI Risk Management Framework, and the EU AI Act.
- Reviewing pull requests for LLM-related security issues with its code scanning feature.

## Quick start

Evaluations:

1. Install the CLI (Homebrew `brew install promptfoo` and `pip install promptfoo` are also supported, or prefix commands with `npx promptfoo@latest` without installing).

   ```bash
   npm install -g promptfoo
   ```

2. Create the official getting-started example. It writes a `promptfooconfig.yaml` with prompts, providers, and tests.

   ```bash
   promptfoo init --example getting-started
   ```

3. Set the API key for your provider as an environment variable. Do not put real keys in the config file.

   ```bash
   export OPENAI_API_KEY="<your-key>"
   ```

4. Run the eval and open the local web viewer.

   ```bash
   cd getting-started
   promptfoo eval
   promptfoo view
   ```

Red teaming (only against a model or application you own or are authorized to test, ideally a local or staging target):

1. Create a red team config with the browser setup, or without the UI.

   ```bash
   promptfoo redteam setup
   # or
   promptfoo redteam init --no-gui
   ```

2. Point the target at your test endpoint, then generate and run the test cases.

   ```bash
   promptfoo redteam run
   ```

3. Review the findings.

   ```bash
   promptfoo redteam report
   ```

## Key concepts

- **Prompts**: The instructions sent to a model. Placeholders in double curly braces, such as `{{language}}`, are filled from each test.
- **Providers**: The models or endpoints being compared. promptfoo supports hosted APIs, local models, and custom HTTP endpoints.
- **Tests and vars**: Each test supplies `vars` (input values) that are run through every prompt and provider combination.
- **Assertions**: Optional automatic checks on outputs, such as `contains`, or model-graded checks. Results can also be reviewed by hand in the viewer.
- **Targets**: In red teaming, the model or application under test.
- **Plugins**: Red team generators that produce adversarial inputs for a given risk area.
- **Strategies**: Techniques that wrap generated inputs in a specific attack pattern.
- **Purpose**: An optional description of the application and its users. It improves the quality of generated test cases and grading.

## Security notes

- Scope and authorization: the red team scanner can reach any endpoint your machine can reach. Run it only against systems you own or have written permission to test, and prefer a staging copy over production.
- Data leaving the machine: evals run locally and call providers directly. For red teaming, if no `OPENAI_API_KEY` (or supported login) is configured, test generation and grading go to the hosted `api.promptfoo.app` service, including the application purpose, prompts sent to your target, and its responses.
- To keep red team generation local, set `PROMPTFOO_DISABLE_REMOTE_GENERATION=true` and configure your own generation and grading model. The docs note this is not network isolation, and some plugins only work with remote generation.
- Do not type real credentials, authorization headers, or production request samples into the red team target forms. The data handling guide says these values are sent to the service when entered there.
- Telemetry records commands and assertion types, not prompts or outputs. Disable it with `PROMPTFOO_DISABLE_TELEMETRY=1`; disable update checks with `PROMPTFOO_DISABLE_UPDATE=1`.
- Results files and the local viewer contain full prompts and model outputs, which can include sensitive data or harmful generated text. Store them like other test evidence and avoid public sharing links for internal findings.
- Map findings to the library's threat references: [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Getting started with evals](https://www.promptfoo.dev/docs/getting-started/)
- [Red teaming overview](https://www.promptfoo.dev/docs/red-team/) and [red team quickstart](https://www.promptfoo.dev/docs/red-team/quickstart/)
- [Red team data handling and privacy](https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/)
- [Telemetry settings](https://www.promptfoo.dev/docs/configuration/telemetry/)
- [CI/CD integration](https://www.promptfoo.dev/docs/integrations/ci-cd/)
- [Company update: Promptfoo joining OpenAI](https://www.promptfoo.dev/blog/promptfoo-joining-openai/)
