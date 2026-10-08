# CrewAI

> In one minute: CrewAI is an open-source Python framework for orchestrating teams of role-playing AI agents, called Crews, inside event-driven, stateful workflows, called Flows. You define each agent by role, goal, backstory, and tools, assign it tasks, and let the crew collaborate or delegate. Crews often hold web, file, and database tools, so tool scope and sandboxing are the main security controls.

| | |
|---|---|
| Category | Agent framework |
| Maintainer | CrewAI (crewAI, Inc.) |
| License / access | Open source (MIT). CrewAI AMP is a separate hosted platform for deploying Flows. |
| Official docs | [docs.crewai.com](https://docs.crewai.com/en/introduction) |
| Repository | [crewAIInc/crewAI](https://github.com/crewAIInc/crewAI) |
| Checked | 8 Oct 2026, crewai 1.15.25 (PyPI) |

## What it is for

- Research and reporting pipelines, for example a researcher agent that searches the web and writes a report.
- Business process automation where a Flow owns state and execution order and calls crews for specific steps.
- Delegation between specialist agents with different roles and tools.
- Structured task outputs (JSON or Pydantic) for downstream systems.
- Human review of a task's result before the workflow continues.

## Quick start

1. Install the CrewAI CLI with uv (condensed from the official Flow quickstart). CrewAI requires Python 3.10 or later and earlier than 3.14.

   ```bash
   uv tool install crewai
   ```

2. Scaffold a Flow project.

   ```bash
   crewai create flow latest-ai-flow
   cd latest_ai_flow
   ```

3. Define the agent in `src/latest_ai_flow/crews/content_crew/agents/researcher.jsonc`. Values like `{topic}` come from the kickoff inputs.

   ```json
   {
     "role": "{topic} Senior Data Researcher",
     "goal": "Uncover cutting-edge developments in {topic}",
     "backstory": "You're a seasoned researcher who finds relevant information and presents it clearly.",
     "tools": ["SerperDevTool"],
     "settings": { "verbose": true }
   }
   ```

4. Define the crew in `src/latest_ai_flow/crews/content_crew/crew.jsonc`.

   ```json
   {
     "name": "Research Crew",
     "agents": ["researcher"],
     "tasks": [
       {
         "name": "research_task",
         "description": "Conduct thorough research about {topic}. Use web search to find recent, credible information.",
         "expected_output": "A markdown report with clear sections: key trends, notable tools or companies, and implications.",
         "agent": "researcher",
         "output_file": "output/report.md",
         "markdown": true
       }
     ],
     "process": "sequential",
     "verbose": true
   }
   ```

5. Replace the generated `content_crew.py` with a loader, then call it from a step of the Flow in `src/latest_ai_flow/main.py`.

   ```python
   from pathlib import Path
   from crewai.project import load_crew

   def kickoff_content_crew(inputs: dict):
     crew, default_inputs = load_crew(Path(__file__).with_name("crew.jsonc"))
     return crew.kickoff(inputs={**default_inputs, **inputs})
   ```

   ```python
   from pydantic import BaseModel
   from crewai.flow import Flow, listen, start
   from latest_ai_flow.crews.content_crew.content_crew import kickoff_content_crew

   class ResearchFlowState(BaseModel):
     topic: str = ""
     report: str = ""

   class LatestAiFlow(Flow[ResearchFlowState]):
     @start()
     def prepare_topic(self, crewai_trigger_payload: dict | None = None):
       self.state.topic = "AI Agents"

     @listen(prepare_topic)
     def run_research(self):
       result = kickoff_content_crew(inputs={"topic": self.state.topic})
       self.state.report = result.raw

   def kickoff():
     LatestAiFlow().kickoff()
   ```

6. Put keys in `.env` at the project root and keep that file out of version control: `SERPER_API_KEY` for the search tool, `MODEL=provider/model-id`, and your model provider's key (for OpenAI, `OPENAI_API_KEY`).

7. Install dependencies and run. The report lands in `output/report.md`.

   ```bash
   crewai install
   crewai run
   ```

## Key concepts

- **Agent**: an autonomous unit with a role, goal, backstory, tools, and LLM. Options include `max_iter` (default 20) and `allow_delegation` (default False).
- **Task**: a description, an expected output, and an assigned agent. Tasks support `guardrail` validation, `human_input` review, and `output_file`.
- **Crew**: a team of agents and tasks run by a process, such as sequential.
- **Flow**: an event-driven workflow with typed state; methods marked `@start()` and `@listen()` define execution order.
- **Tools**: capabilities such as `SerperDevTool` for web search, plus custom tools you write.
- **Project format**: new projects use JSONC agent and crew files; an older YAML scaffold is still available.

## Security notes

- CERT/CC note [VU#221883](https://www.kb.cert.org/vuls/id/221883) (March 2026) covered four flaws. [CVE-2026-2275](https://nvd.nist.gov/vuln/detail/CVE-2026-2275): the Code Interpreter tool fell back to a weaker `SandboxPython` when Docker was unreachable, enabling code execution; CVE-2026-2287 covered the same fallback when Docker stopped mid-run; CVE-2026-2285 was a local file read in the JSON loader tool; [CVE-2026-2286](https://nvd.nist.gov/vuln/detail/CVE-2026-2286) was SSRF through RAG search tools.
- CrewAI responded by removing `CodeInterpreterTool` and deprecating `allow_code_execution` and `code_execution_mode`. The docs now direct code execution to a dedicated sandbox service. Do not run model-written code on the host.
- SSRF protection has been bypassed before: [CVE-2026-62240](https://nvd.nist.gov/vuln/detail/CVE-2026-62240) bypassed `validate_url` with redirects to internal addresses or DNS rebinding (fixed in 1.15.1). Add network egress controls for any agent that fetches URLs.
- Scope tools tightly. Give each agent only the tools its task needs, leave `allow_delegation` off unless required, keep `max_iter` bounded, and add task guardrails or `human_input` before outputs that trigger actions. Write tools deserve extra care: CVE-2026-37007 was a path traversal in `FileWriterTool`.
- Web search results and scraped pages flow straight into agent context and can carry prompt injection. Be most careful when the same crew also holds write, email, or database tools.
- CrewAI collects anonymous usage telemetry, including tool names and agent roles, so keep personal data out of those fields. Setting `share_crew=True` also sends task descriptions, backstories, and goals, which may include personal data. Turn telemetry off with `CREWAI_DISABLE_TELEMETRY=true` or `OTEL_SDK_DISABLED=true`.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Introduction](https://docs.crewai.com/en/introduction)
- [Quickstart](https://docs.crewai.com/en/quickstart)
- [Agents](https://docs.crewai.com/en/concepts/agents)
- [Tasks](https://docs.crewai.com/en/concepts/tasks)
- [Telemetry](https://docs.crewai.com/en/telemetry)
- [CrewAI courses](https://learn.crewai.com/)
