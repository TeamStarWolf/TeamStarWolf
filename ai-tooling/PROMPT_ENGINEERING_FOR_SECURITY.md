# Prompt Engineering for Security Work

A short prompt usually gets a short, shallow answer. For security work, where the output feeds a report, a triage decision, or a remediation plan, the quality of the prompt decides the quality of the result. This page gives an eight-pillar framework for writing prompts that return accurate, structured, decision-useful output, with security examples and the cautions that matter when a security team puts data in front of a language model. The eight-pillar framing is adapted, with credit, from the MIT-licensed [Prompt-Improver---Zafran](https://github.com/domeger/Prompt-Improver---Zafran) project by domeger; the writing and the security guidance here are this library's own.

## Why prompt quality matters for security

A language model answers the prompt it is given, not the question in your head. "Show assets missing SentinelOne" returns a list; the same intent written as a prompt that names the scope, the data fields, the risk framing, and the output format returns a report an analyst can act on. The difference is not the model, it is the prompt. The pillars below are a checklist for turning a one-line request into that fuller prompt.

## The eight pillars of an effective prompt

1. Specificity and context. State exactly what you want and the situation it sits in. Name the environment, the scope, and the constraint. "Across the production Windows fleet in the PCI scope" beats "on our systems."
2. Structure and organization. Tell the model how to organize the answer: sections, a table, a ranked list. A request for "a table of affected hosts with owner and severity" removes guesswork.
3. Data requirements. Name the fields and the sources you expect. Ask for asset name, owner, last-seen date, and the control that is missing, rather than an unspecified "details" column.
4. Risk and impact. Ask the model to tie findings to risk: exploitability, exposure, business impact, and what an attacker could do. This turns a list into a prioritization.
5. Timeline and actions. Ask for next steps with an order and a rough timeframe: mitigate now, remediate this week, validate on rescan. Security output is only useful if it says what to do.
6. Quality elements. Ask for the things that make the output trustworthy: assumptions stated, confidence noted, gaps flagged, and sources named. This also surfaces where the model is guessing.
7. Accountability. Ask who owns each item and how completion is proven. A finding without an owner and an exit condition does not get fixed.
8. Professional formatting. Specify the format the reader needs: an executive summary first, consistent headings, and plain language. A report that a manager can skim and an engineer can act on serves both.

## A worked example

A basic prompt and the same intent written against the pillars:

```text
Basic:
Show assets missing SentinelOne.

Improved:
Produce a report of production assets in the PCI scope that do not have the
SentinelOne agent installed and reporting.
- Structure: executive summary, then a table, then prioritized actions.
- Data per asset: hostname, owner, OS, last-seen date, business criticality.
- Risk: group by criticality and note why an unmonitored host raises risk.
- Actions: for each group, the mitigation to apply now and the remediation
  to schedule, with a target timeframe and the owner.
- Quality: state assumptions, flag any assets with stale data, and name the
  data source.
```

The basic prompt returns a flat list. The improved prompt returns a structured, owned, prioritized report, because every pillar is present.

## Running this locally

For sensitive security data, prefer a local model over a hosted one. A tool like Ollama runs an open-weight model on your own machine, so asset inventories, scan output, and configuration never leave your control. The [AI Labs](/ai-tooling/AI_LABS.md) page walks through running a model with Ollama, and the [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md) covers prompting, retrieval, and local models in more depth. A local model is also what makes a prompt-improver workflow safe to point at real Zafran or scanner output; see [Zafran](/platforms/zafran.md).

## Security cautions when using a language model

Prompt quality does not remove the risks of using a model on security data.

- Do not paste secrets, credentials, tokens, or regulated data into a hosted model; use a local model for anything sensitive, and redact before sending (CWE-312 for exposing sensitive data to a third party).
- Treat output as a draft, not a fact. Models invent plausible asset names, CVE numbers, and command flags; verify every specific against the source before acting.
- Untrusted content in a prompt can carry instructions. Data pulled from a ticket, a web page, or a scan result may try to steer the model (prompt injection); keep instructions and data separate and do not let tool output issue actions on its own.
- Record the prompt and the model version alongside any output you keep, so a result can be reproduced and audited.

For the broader risks of building and running AI systems, see the [AI Security Reference](/AI_SECURITY_REFERENCE.md).

## Resources and credits

- [Prompt-Improver---Zafran](https://github.com/domeger/Prompt-Improver---Zafran) by domeger (MIT license): the interactive prompt-rewriting tool and the eight-pillar framing this page adapts, with its training materials and example outputs.
- [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md), [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md), and [AI Labs](/ai-tooling/AI_LABS.md) for the tools, study order, and hands-on labs.

## Related pages

- [AI Tools and LLMs Index](/ai-tooling/AI_TOOLS_INDEX.md)
- [AI and LLM Learning Path](/ai-tooling/AI_LEARNING_PATH.md)
- [AI Labs](/ai-tooling/AI_LABS.md)
- [AI Security Reference](/AI_SECURITY_REFERENCE.md)
- [Zafran](/platforms/zafran.md)
