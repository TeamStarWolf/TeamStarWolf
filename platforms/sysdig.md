# Sysdig

Sysdig is a cloud-native security and monitoring platform built on the open-source Falco project. Sysdig Secure provides runtime threat detection, cloud detection and response, vulnerability management, and posture, with deep visibility drawn from system calls. The sections below describe the generally available product in 2026. The licence tier a team holds decides which modules are in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Cloud security and platform engineers who run, tune or assess Sysdig

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (994 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Sysdig for cloud and workload security, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Aqua Security](/platforms/aqua-security.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it fits

Sysdig watches what workloads actually do at runtime. Its roots are in deep system visibility, and it reads activity at the system-call level to see processes, files, network connections, and container behavior as they happen.

Sysdig Secure applies that visibility to security. It detects threats at runtime, supports cloud detection and response, manages vulnerabilities with runtime context, and checks posture across clouds and clusters. Falco, the open-source engine Sysdig created and maintains, supplies the detection core and is widely used on its own.

A cloud security team uses Sysdig when it wants strong runtime evidence. It answers what a workload is doing right now, whether that behavior matches a known threat, and which of its vulnerabilities are actually exercised at runtime.

## Architecture and how it works

Sysdig pairs a vendor-hosted backend with components deployed close to the workloads. The backend holds policy, findings, and analytics. Collection happens where the workloads run, on the hosts and clusters in scope.

Runtime visibility comes from system-call instrumentation. A Sysdig agent observes kernel-level events on each host, which gives a detailed view of process, file, and network activity inside containers and on the host itself. This is the same foundation Falco uses to evaluate detection rules.

Threat detection evaluates that activity against rules. Falco rules describe suspicious behavior, and the platform adds managed rule content and analytics. When activity matches, Sysdig raises an event with the runtime context that explains it.

Cloud detection and response extends the view beyond the host. Sysdig ingests cloud provider activity logs and evaluates them for suspicious actions, so detection spans both workload behavior and control-plane events. Vulnerability management uses runtime insight to show which vulnerable packages are actually loaded and in use, and posture management checks configuration across clouds and clusters.

## Key capabilities

- Runtime threat detection built on Falco, driven by system-call visibility into process, file, and network activity.
- Cloud detection and response over provider activity logs, correlating control-plane events with workload behavior.
- Vulnerability management with runtime context that highlights which vulnerable packages are in use.
- Cloud and Kubernetes security posture management across accounts and clusters.
- Container and host visibility deep enough to support incident investigation.
- Managed and custom detection rules, with Falco rules portable across environments.
- Forensics and response data captured from the runtime record.

## Deployment and operations

Deployment begins with the agent. A team installs the Sysdig agent on the hosts or into the clusters it wants to cover, which gives runtime visibility and feeds the detection engine. Falco can be adopted on its own first and later connected to the platform.

Cloud detection and posture need connected accounts. A team grants a scoped role per cloud account so Sysdig can read activity logs and configuration. Vulnerability management ties into image and workload data so findings carry runtime context.

Operations center on runtime events and vulnerability findings. A team tunes detection rules to its workloads to keep noise down, triages events with the captured context, and investigates incidents using the runtime record. On the vulnerability side, runtime context helps a team fix the packages that are actually used first.

Rule and policy management is ongoing. Teams maintain their Falco and managed rule sets, document suppressions, and route events to messaging, ticketing, and a SIEM so work reaches owners and records are retained.

## Integrations and data flow

Data flows into Sysdig from agents on hosts and clusters and from connected cloud accounts. Agents stream runtime events, and cloud connectors deliver activity logs and configuration. Image and workload data feed vulnerability analysis.

Outbound, events and findings reach the team's response stack. Alerts and tickets route to messaging and work-tracking systems. Runtime and cloud events feed a SIEM for correlation and retention. An API and automation hooks let detections drive response workflows.

Because Falco is open source, its detections also flow through standalone and third-party pipelines, which gives a team a consistent runtime detection engine across tooling.

## Hardening and secure use

Run the agent and cloud connector with least privilege. The agent needs the access required to observe the hosts in scope, and the cloud connector needs only read access to activity logs and configuration. Granting either more than it needs widens the blast radius if a component is compromised.

Use role-based access inside the platform. Separate responders, auditors, and administrators so routine triage and investigation do not require platform-wide control. Review membership regularly and remove access that is no longer needed.

Protect API credentials as sensitive secrets (CWE-798). Keep platform API keys and connector credentials out of source, images, and pipeline definitions. Store them in a secrets manager, scope them narrowly, rotate them, and revoke any that are unused. Hard-coded credentials are a common path to platform compromise.

Treat detection rules and suppressions as security controls. Changes to what is detected or silenced shape visibility, so review them with the same care given to other control changes.

## Where it fits in the program

Sysdig is the runtime visibility and detection layer for a team that wants strong evidence of what workloads are doing. It feeds detection and response with runtime and cloud events, and it feeds vulnerability management with runtime-aware findings.

Alongside a posture-focused CNAPP such as Wiz, Prisma Cloud, or Orca Security, Sysdig often provides the runtime depth, while the CNAPP provides broad posture and entitlement coverage. Falco also serves teams that want a shared open-source detection engine independent of the platform.

## Resources

- Sysdig Secure product documentation
- Falco project documentation
- Sysdig agent deployment guides
- Sysdig API reference

## Related pages

- [Security platforms](/platforms/README.md)
- [Cloud Security Reference Library](/CLOUD_SECURITY_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Aqua Security](/platforms/aqua-security.md)
- [Wiz](/platforms/wiz.md)
- [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md)
