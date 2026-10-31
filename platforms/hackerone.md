# HackerOne

HackerOne is a crowdsourced security platform. It connects organizations with a community of external security researchers who find and report vulnerabilities. The platform manages the programs, the incoming reports, and the workflow that turns a report into a tracked fix.

## What it is and where it fits

HackerOne brings outside testers to an organization's attack surface. Where internal scanning and testing find what known tools detect, a researcher community finds issues that come from human creativity and from attacker-style thinking.

It fits the program as a channel for findings that originate outside the organization. A bug bounty program rewards researchers for valid reports. A vulnerability disclosure program gives anyone a defined, safe way to report a flaw they found.

The platform also offers managed services. Triage services help validate and prioritize incoming reports. Pentest-as-a-service runs structured, time-boxed tests by vetted researchers against a defined scope, with results delivered through the same platform.

Licence tier and program type decide which features and services are in force. Confirm what a given program includes before assuming triage support, pentest delivery, or a particular integration is available.

## Architecture and how it works

HackerOne is a hosted platform. An organization configures one or more programs, each with a scope that states which assets are in bounds and which are not, and the rules researchers must follow.

Researchers submit reports through the platform. Each report describes a vulnerability, how to reproduce it, and its impact. The platform assigns severity and supports CVSS scoring so findings are rated on a common scale rather than by prose alone.

Incoming reports pass through triage. Duplicate detection groups reports that describe the same underlying issue, so a team does not pay out or work the same flaw twice. A triager, whether internal or from HackerOne's service, validates the report and confirms it is real and in scope.

Valid findings move into a workflow. The platform tracks each report's state from new through triaged, resolved, and closed. Integrations push findings into the organization's own tracking and monitoring tools so remediation happens in the normal engineering process.

For bug bounty programs, the platform handles reward payments to researchers for valid, in-scope reports. For pentest-as-a-service, it coordinates the engagement and delivers structured results through the same interface.

## Key capabilities

- Bug bounty programs that reward researchers for valid reports.
- Vulnerability disclosure programs that provide a safe reporting channel.
- Triage services that validate and prioritize incoming reports.
- A researcher community that brings varied skills to the attack surface.
- Pentest-as-a-service for structured, scoped, time-boxed testing.
- Severity and CVSS scoring for consistent rating of findings.
- Duplicate detection to collapse repeated reports of one issue.
- Workflow integrations with issue trackers and, through the API, a SIEM.

The vulnerability disclosure program is the channel for outside reports. It complements internal scanning by giving external finders a clear, authorized path, so a discovered flaw reaches the security team rather than going public or unreported.

Severity scoring and duplicate detection keep the incoming stream manageable. A team sees rated, deduplicated findings instead of a raw queue, which makes prioritization against other work practical.

## Deployment and operations

HackerOne is a hosted platform, so there is no scanner or server for a team to deploy. Getting started means defining a program, writing its scope and rules, and deciding whether it is a private invited program or a public one.

Scope definition is the central operational task. It states which assets researchers may test and which they may not, which keeps testing authorized and protects systems that are out of bounds. A clear scope also reduces out-of-scope reports that waste triage time.

Running a program means handling the report stream: triaging new reports, communicating with researchers, deciding rewards where a bounty applies, and moving valid findings into remediation. Teams can run triage themselves or use HackerOne's triage service.

Operations also include managing who has access to the program, keeping integrations authorized, and reviewing program metrics such as time to triage and time to resolve. These measures show whether the program is keeping pace with incoming reports.

## Integrations and data flow

HackerOne integrates with issue trackers so a valid report becomes a work item in the team's backlog. Through the API, findings can also flow to a SIEM or other systems that an organization uses to centralize security data.

The main data flow starts with a researcher submitting a report. The report is triaged and scored on the platform, then, once valid, pushed to the issue tracker where engineering works it. State changes can sync so the platform and the tracker stay aligned.

The API is the extension point for anything beyond the built-in integrations. It lets an organization pull reports, program data, and state into its own tooling, including a SIEM for correlation with other security events.

Data flowing out includes vulnerability detail and reproduction steps, which are sensitive. Route that flow only to the organization's own authorized systems and recipients, and keep the integration scoped to what the program needs.

## Hardening and secure use

Protect the platform's API tokens. A token can read reports and program data and drive integrations, so scope each token to only what its integration needs. Placing a token in a script or committing it to a repository risks exposure, a case of use of hard-coded credentials (CWE-798). Store tokens in a secrets manager and rotate them.

Define program scope precisely so testing stays authorized. Scope is what makes researcher activity legal and bounded. A vague or overly broad scope can invite testing against systems the organization did not intend to expose. State in-bounds and out-of-bounds assets clearly and keep the scope current.

Use role-based access so that managing programs, reading reports, and changing integrations are limited to the right people. Report detail is sensitive until a fix ships, and access to it should match that sensitivity.

Treat the researcher relationship as part of secure use. Clear rules, prompt communication, and consistent reward decisions keep a program healthy and keep findings coming through the authorized channel rather than elsewhere.

## Where it fits in the program

HackerOne is the external-findings layer of the program. It adds human, attacker-style testing that automated scanners do not provide, and it gives outside finders a route that ends in the security team's queue rather than in public.

Its reports feed vulnerability management as rated, deduplicated findings that join the same prioritization and tracking process as internal results. Pentest-as-a-service adds structured testing on demand without standing up an in-house red team for every engagement.

HackerOne does not replace continuous internal scanning or static and dynamic application testing. It complements them by covering the issues that come from people probing the live attack surface, and its disclosure program is the standing channel for outside reports.

## Resources

- HackerOne Documentation
- HackerOne Help Center
- HackerOne API documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Scanner platforms reference](/SCANNER_PLATFORMS_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Snyk](/platforms/snyk.md)
- [Invicti](/platforms/invicti.md)
