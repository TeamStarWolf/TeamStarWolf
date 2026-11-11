# Tines

Tines is a no-code security automation and orchestration platform. It lets teams build workflows that connect to any system with an HTTP or API endpoint, without writing integration code and without waiting for a pre-built connector.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

SOC engineers and automation builders who run, tune or assess Tines

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,294 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Tines for security orchestration and automation, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Cortex XSOAR](/platforms/cortex-xsoar.md), [Splunk Enterprise Security](/platforms/splunk.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Tines automates the repetitive work that sits between security tools. It takes an input, calls out to one or more systems, shapes the data, and decides what to do next. Teams use it for triage, enrichment, containment, and routine operational tasks.

The platform's model is general. Because an action can call any HTTP or API endpoint, Tines is not limited to a catalog of supported products. If a system has an API, a story can talk to it.

In a security program, Tines is an automation and orchestration layer, similar in role to a SOAR platform. It does not detect threats or store endpoint data itself. It connects the tools that do and runs logic across them.

## Architecture and how it works

A Tines deployment is built from a small set of concepts. Understanding them is enough to read most workflows.

- Stories are the workflows. A story is a diagram of connected actions that runs when it is triggered. Stories are the unit teams build, test, and change.
- Actions are the steps inside a story. The main action types are HTTP request (call an API), trigger (branch on a condition), transform (reshape data), send email, and AI (apply a model to text).
- Webhooks receive data into a story. An external system posts to a webhook URL, and that event starts or feeds the workflow.
- The credential store holds secrets that actions use to authenticate. Credentials are referenced by name rather than written into the action.

Data moves through a story as structured events. Each action receives the events from the actions before it, does its work, and emits a result that later actions can read. This passing of events is how enrichment accumulates across a workflow.

Because the HTTP request action is generic, Tines reaches new systems by configuration rather than by code. A team points an action at an endpoint, sets the method and body, and references a credential. No connector package is required.

## Key capabilities

- Stories: visual workflows that chain actions, branch on conditions, and loop over lists.
- HTTP request action: a general connector to any REST or HTTP API, which removes the dependence on pre-built integrations.
- Transform action: data reshaping, parsing, and extraction between steps.
- Trigger action: conditional branching so a story takes different paths based on its data.
- Send email action: notifications and human-in-the-loop messages.
- AI action: application of a model to classify, summarize, or extract from text within a workflow.
- Webhooks: inbound events that start or feed stories in near real time.
- Credential store: named, centrally held secrets that actions use without exposing the values.

## Deployment and operations

Tines runs as a cloud-hosted service or as a self-hosted deployment that an organization operates itself. The self-hosted form suits teams that need the platform inside their own network boundary.

Deployments are divided into tenants. A tenant is an isolated workspace with its own stories, credentials, and members. Teams use tenants to separate environments or business units.

The license tier decides which features and limits are in force. Confirm entitlements against the tier in use rather than assuming a feature is present.

Operationally, teams version and test stories before putting them into production, watch which stories run most often, and review the external endpoints each story calls. A story that takes an action in another system deserves closer review than one that only reads data.

## Integrations and data flow

Data enters Tines through a webhook, a scheduled run, or a manual start. The entry event carries the input the story works on.

Actions then process that event. An HTTP request action queries an external API; a transform action reshapes the response; a trigger action branches on the result. Each step passes its output forward, so later actions build on earlier ones.

Outbound calls act on other systems. A story can tell an endpoint tool to isolate a host, a ticketing system to open a case, or an identity provider to disable an account. These calls use credentials from the credential store.

Because any endpoint is reachable, data flow is defined per story rather than fixed by a connector. This flexibility means the security of a workflow depends on how it is built and which endpoints it is allowed to call.

## Adversary perspective

Tines runs logic and holds credentials across connected systems, so adversaries value the credential store and the stories' outbound reach, and the platform and its webhooks are themselves a target. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and tampering

- Suppressing or altering workflows (ATT&CK T1685, Disable or Modify Tools): with access an attacker can disable or edit a story so a detection-driven action never runs, or change it to hide its own activity.
- Credential store abuse: the store holds secrets that authenticate to connected systems, so a compromise turns those into a foothold that can isolate hosts, open or close tickets, or disable accounts ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)).
- Webhook and endpoint abuse: because the HTTP action can call any endpoint, an unreviewed or altered story can send data to an unintended destination, and an exposed webhook URL can be driven with crafted input to trigger actions ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)).

### Residual risk and own exposure

Automation acts only on the events it receives, and a call that returns success has not proven the target acted. The platform concentrates credentials and can reach many systems, so its servers, tenants, and webhooks are high-value and belong in the patch and monitoring scope.

### Why it matters

Treat story changes, credential use, and the list of outbound endpoints as detection and review signals, and gate consequential actions. See [the red team reference](/RED_TEAM_REFERENCE.md) for the evasion techniques and [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for response integrity.

## Hardening and secure use

Keep secrets in the credential store, not in action bodies or story inputs. Hardcoded secrets are a known weakness (CWE-798: Use of Hard-coded Credentials). The credential store lets an action authenticate without the value ever appearing in the story definition.

Apply role-based access so members get only the permissions their work needs. Building and editing stories, and managing credentials, are higher-trust tasks that should be limited to fewer people.

Put change control on stories. A story that acts on live systems can cause real harm if changed carelessly. Test in a separate tenant or a draft, review changes, and promote deliberately.

Scope API tokens to least privilege for every connected system. A story needs only the access its actions require. A read-only task should hold a read-only token, so a mistake or a compromise cannot do more than the workflow was meant to do.

Review the endpoints stories are permitted to reach. Because the HTTP action can call anything, an unreviewed story could send data to an unintended destination. Treat the list of outbound endpoints as part of the security review.

## Where it fits in the program

Tines is the automation and orchestration layer for a security team. It reduces manual effort in triage, enrichment, and routine operations, and it connects tools that do not integrate directly.

For vulnerability management, Tines can automate ticket creation, finding enrichment, and follow-up on overdue items by calling the APIs of the scanning and ticketing tools. It coordinates those systems rather than replacing them.

The platform's general reach is both its strength and its exposure. Credential handling, access control, change control, and endpoint review decide whether that reach stays safe.

## Resources

- Tines documentation
- Tines University training
- Tines Story Library reference

## Related pages

- [Platforms index](/platforms/README.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Cortex XSOAR](/platforms/cortex-xsoar.md)
- [Splunk](/platforms/splunk.md)
