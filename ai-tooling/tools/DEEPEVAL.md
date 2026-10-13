# DeepEval

> In one minute: DeepEval is an open source framework for testing LLM applications, built to feel like unit testing with Pytest. Developers use it to score outputs from chatbots, RAG pipelines, and agents with ready-made metrics such as faithfulness, answer relevancy, bias, and task completion. It lets teams catch quality and safety regressions before a release instead of after.

| | |
|---|---|
| Category | Evaluation |
| Maintainer | Confident AI |
| License / access | Open source (Apache-2.0); optional Confident AI cloud platform for storing results |
| Official docs | [deepeval.com](https://deepeval.com/docs/getting-started) |
| Repository | [confident-ai/deepeval](https://github.com/confident-ai/deepeval) |
| Checked | 8 Oct 2026, v4.2.8 (PyPI `deepeval`, published 2 Oct 2026) |

## What it is for

- Writing pass/fail tests for LLM output that run with `deepeval test run`, the same way Pytest collects tests.
- Measuring RAG quality: whether answers are relevant and faithful to the retrieved context.
- Evaluating agents on task completion, plan quality, and correct tool use.
- Checking outputs for safety issues such as bias, toxicity, and PII leakage.
- Building evaluation datasets ("goldens") and running them in CI.

## Quick start

1. Install DeepEval in a new virtual environment (Python 3.9 or later).

   ```bash
   pip install -U deepeval
   ```

2. Set the key for the LLM that will act as the judge. The default examples use OpenAI.

   ```bash
   export OPENAI_API_KEY="<your-key>"
   ```

   To use a local judge model through Ollama instead:

   ```bash
   deepeval set-ollama --model=<model-name>
   ```

3. Create `test_chatbot.py` with the official example.

   ```python
   import pytest
   from deepeval import assert_test
   from deepeval.metrics import GEval
   from deepeval.test_case import LLMTestCase, SingleTurnParams

   def test_case():
       correctness_metric = GEval(
           name="Correctness",
           criteria="Determine if the 'actual output' is correct based on the 'expected output'.",
           evaluation_params=[SingleTurnParams.ACTUAL_OUTPUT, SingleTurnParams.EXPECTED_OUTPUT],
           threshold=0.5
       )
       test_case = LLMTestCase(
           input="What if these shoes don't fit?",
           # Replace this with the actual output from your LLM application
           actual_output="You have 30 days to get a full refund at no extra cost.",
           expected_output="We offer a 30-day full refund at no extra costs.",
           retrieval_context=["All customers are eligible for a 30 day full refund at no extra costs."]
       )
       assert_test(test_case, [correctness_metric])
   ```

4. Run the test.

   ```bash
   deepeval test run test_chatbot.py
   ```

5. Optional: `deepeval login` sends results to the Confident AI platform. To keep results local, set `DEEPEVAL_RESULTS_FOLDER` instead.

   ```bash
   export DEEPEVAL_RESULTS_FOLDER="./data"
   ```

## Key concepts

- **Test case**: One unit of interaction with your app. An `LLMTestCase` has a required `input` and `actual_output`, and optional fields such as `expected_output` and `retrieval_context`.
- **Metric**: A scorer that returns a value from 0 to 1 with a reason. Built-in families cover RAG, agents, multi-turn chat, safety, and images.
- **G-Eval**: A custom metric where you describe the grading criteria in plain language.
- **Threshold**: The minimum score for a test to pass. The default is 0.5.
- **LLM judge**: Most metrics use an LLM to grade the test case. You can switch to Ollama, Gemini, or any model by subclassing `DeepEvalBaseLLM`.
- **Evaluation dataset and goldens**: An `EvaluationDataset` holds `Golden` items, the reference inputs you run your app against.
- **DeepTeam**: A separate framework from the same team for red teaming LLMs, built on DeepEval.

## Security notes

- Use DeepEval as a release gate: safety metrics (bias, toxicity, PII leakage, role violation) and RAG faithfulness checks catch regressions before users see them.
- Test case content, including retrieval context, is sent to whichever judge model you configure. If the data is sensitive, use a local or approved judge.
- `deepeval login` uploads test runs to Confident AI, which stores them in its cloud unless your plan says otherwise. Decide this deliberately, and keep the `CONFIDENT_API_KEY` in a secret store.
- Anonymous telemetry (event and metric names, an anonymous ID, and public IP for coarse region) goes to PostHog. Opt out with `DEEPEVAL_TELEMETRY_OPT_OUT=1`.
- DeepEval loads `.env.local` and `.env` files automatically at import. Keep those files out of version control, or set `DEEPEVAL_DISABLE_DOTENV=1`.
- LLM judges can be wrong or manipulated by the content they grade. Combine model-graded metrics with deterministic checks for security-critical rules.
- For threat context behind safety metrics, see the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Quickstart](https://deepeval.com/docs/getting-started)
- [Test cases](https://deepeval.com/docs/evaluation-test-cases)
- [Metrics introduction and judge configuration](https://deepeval.com/docs/metrics-introduction)
- [Data privacy and telemetry](https://deepeval.com/docs/data-privacy)
- [DeepTeam repository](https://github.com/confident-ai/deepteam)
