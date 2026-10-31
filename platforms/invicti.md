# Invicti

Invicti is a dynamic and interactive application security testing platform. It scans running web applications and APIs for exploitable vulnerabilities and confirms many of them automatically. Invicti is the platform that brought together the Netsparker and Acunetix product lines.

## What it is and where it fits

Invicti tests applications from the outside, the way an attacker reaches them, rather than reading source. This dynamic approach finds issues that appear only when the application is running, such as injection flaws reachable through a live endpoint.

It fits the application security program alongside static tools. Static analysis reads code and infrastructure-as-code reads configuration, while Invicti exercises the deployed application. Together they cover different stages of the same risk.

The platform combines dynamic application security testing with an interactive mode that uses a sensor inside the application. The dynamic engine crawls and attacks from outside. The interactive sensor observes the application during the scan to improve accuracy and coverage.

Licence tier decides which engines, how many targets, and which governance features are in force. Confirm the active tier before you assume interactive testing, a given integration, or a reporting feature is available.

## Architecture and how it works

Invicti is offered as a cloud service or as an on-premises deployment, with scan agents that reach the targets under test. The agents run near the applications so internal systems can be scanned without exposing them externally.

The dynamic engine starts by crawling the application to map its pages, forms, parameters, and endpoints. It then sends crafted requests designed to trigger vulnerable behavior. The engine covers web applications and APIs, including those described by a machine-readable definition.

Proof-based scanning is the distinctive part of the engine. When the scanner finds a candidate vulnerability, it attempts a safe confirmation step that demonstrates the issue is real. A finding that is confirmed this way is marked as proven, which cuts the false positives a team must triage.

Interactive testing adds a sensor deployed with the application. The sensor reports what happens inside the application as the dynamic engine attacks it. This inside view helps confirm findings and reach code paths that a purely external scan might miss.

Authenticated scanning lets Invicti test the parts of an application that sit behind a login. The scanner is given credentials and a defined scope so it can exercise authenticated functionality while staying inside the area the team intends to test.

## Key capabilities

- Dynamic scanning of web applications for common and complex vulnerability classes.
- API scanning driven by machine-readable API definitions.
- Proof-based scanning that confirms exploitability to cut false positives.
- Interactive testing with a sensor inside the running application.
- Authenticated scanning that reaches functionality behind a login.
- Continuous-integration gating that can act on scan results in a pipeline.
- Retest and verification to confirm a reported issue is fixed.
- Web application firewall rule export where the integration supports it.
- Role-based access control over scans, targets, and reports.

Proof-based scanning changes how a team spends triage time. A confirmed finding needs no manual reproduction, so analysts can focus review on the findings that the engine could not prove on its own.

Retest and verification close the loop after remediation. When a developer reports a fix, Invicti reruns the relevant checks against the target to confirm the issue is gone rather than relying on the claim alone.

## Deployment and operations

Invicti can run as a cloud service or be deployed on-premises. Both models use scan agents to reach the applications under test. The choice depends on where the targets live and what network access policy allows.

Setting up a scan means defining the target, its scope, and any authentication the scanner needs to log in. Scope control keeps the scanner on the intended application and away from systems that are out of bounds. Scheduling and concurrency are tuned so scans do not overload a target.

Operations work includes maintaining authenticated-scan configurations as applications change, reviewing results, and routing confirmed findings into the team's tracking process. Credentials used for authenticated scans need periodic review because they grant the scanner real access.

Because dynamic scans send active requests, coordinate with application owners so a scan against a sensitive or production-like environment is expected. Run against staging or test environments where the program requires it.

## Integrations and data flow

Invicti connects to issue trackers, continuous-integration and delivery systems, and web application firewalls. These integrations move findings out of the scanner and into the places where teams act on them.

Issue-tracker integration turns a confirmed finding into a work item in the team's backlog, with the detail a developer needs to reproduce and fix it. Pipeline integration lets a scan run as part of delivery and gate a release on its result.

Where supported, Invicti can export rules for a web application firewall. This gives a team a temporary mitigation for a confirmed issue while a code fix is developed, shortening the window of exposure.

Data flows from the scanned application to the platform, which stores findings, scan history, and reports. Confirmed findings then flow outward to trackers and pipelines. Keep that flow scoped to the applications and environments the program intends to test.

## Hardening and secure use

Handle scan credentials carefully. Authenticated scans require real login details for the target application, and those stored credentials grant access. Embedding them in a script or a shared configuration file risks exposure, a case of use of hard-coded credentials (CWE-798). Store them in the platform's credential store or a secrets manager and rotate them.

Control authenticated-scan scope deliberately. A scan given broad credentials and a loose scope can reach functionality or data the team did not mean to test. Define the scope so the scanner stays within the intended application and does not act against out-of-bounds systems.

Use role-based access so that starting scans, viewing results, and changing configuration are limited to the right people. A dynamic scanner is an active tool, and the ability to launch scans against targets should be granted only to those who need it.

Protect the scanner's own deployment. The agents and the platform hold target credentials and findings, so treat them as sensitive infrastructure with restricted access and current patching.

## Where it fits in the program

Invicti is the dynamic testing layer of the application security program. It validates that a deployed application resists the attacks that static and composition tools can only predict from code. A proven finding is direct evidence of exploitable risk.

Its confirmed findings feed vulnerability management as high-confidence items that need remediation and tracking. Its web application firewall export gives the program a mitigation path while a fix is built. Its retest feature provides the verification step that closes a finding.

Invicti does not read source or dependency trees, so it complements rather than replaces static analysis and software composition analysis. The program uses both to cover code and running behavior.

## Resources

- Invicti Documentation
- Invicti Help Center
- Invicti Support documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Scanner platforms reference](/SCANNER_PLATFORMS_REFERENCE.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Snyk](/platforms/snyk.md)
- [HackerOne](/platforms/hackerone.md)
