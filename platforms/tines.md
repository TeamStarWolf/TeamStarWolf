# Tines

Tines is a no-code security automation and orchestration platform. It lets teams build workflows that connect to any system with an HTTP or API endpoint, without writing integration code and without waiting for a pre-built connector.

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
