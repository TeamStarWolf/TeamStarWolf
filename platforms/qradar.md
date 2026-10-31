# IBM QRadar

IBM QRadar is a security information and event management (SIEM) platform that collects events and network flows, correlates them with rules, and raises offenses for analyst review.

## What it is and where it fits

QRadar ingests log events from devices and applications and network flow data from the wire. It parses both into a common format, correlates them, and produces offenses, which are prioritized, grouped indicators that something warrants investigation.

Its distinguishing trait among SIEMs is the first-class treatment of network flow data alongside events. Combining the two lets a rule reason about both what a device logged and what actually crossed the network.

In a SOC, QRadar occupies the detection and triage layer. It answers what is happening across the environment and bundles related activity into a single offense an analyst can work.

## Architecture and how it works

QRadar is built from collection, processing, and console components.

- Event collectors and processors receive log events, normalize them, and store them.
- QFlow collects network flow data and produces flow records that describe conversations between hosts.
- Flow processors store and correlate flow records.
- The console provides the analyst interface, search, and administration.

Device Support Modules (DSMs) are the parsers. A DSM knows the log format of a given product and maps its fields into the normalized QRadar event model. New or custom log sources need a matching DSM, or a custom parser, to be understood.

Rules and building blocks drive detection. A building block is a reusable test, for example a definition of internal address space. A rule combines tests, often referencing building blocks, and fires when its conditions match, contributing to or creating an offense. Offenses aggregate related events and flows so an analyst sees one case rather than hundreds of lines.

The Ariel Query Language (AQL) queries the event and flow databases. Analysts use AQL for searches and investigations that go beyond the prebuilt views.

## Key capabilities

- Event collection and normalization through DSMs across a wide range of products.
- Network flow collection with QFlow for visibility into actual traffic.
- Correlation rules and building blocks for detection logic that spans events and flows.
- Offenses that group related activity into prioritized, investigable cases.
- AQL for flexible search across stored events and flows.
- Reference sets and reference data for tracking indicators such as watchlists.
- Dashboards and reporting for operational and compliance views.

## Deployment and operations

QRadar on-premises is deployed as appliances or software, from an all-in-one system to a distributed set of collectors, processors, and a console. Sizing follows events per second and flows per minute.

A 2024 to 2025 transition reshaped the product line. IBM's QRadar SaaS assets moved to Palo Alto Networks, and customers of the cloud offering are guided toward Cortex XSIAM. IBM has stated it continues the on-premises QRadar SIEM. State this plainly to anyone planning long-term: the on-premises product continues under IBM, while the former SaaS path points to Cortex XSIAM. Confirm current details and any dates with the vendors, because the specifics evolved over that period.

Operations center on log source management (ensuring each source has a working DSM and is parsing), rule tuning, and offense management. Untuned rules produce noisy offenses; rule and building block tuning is the ongoing work that keeps the queue meaningful.

## Integrations and data flow

Inbound, QRadar receives syslog and other event feeds from firewalls, endpoints, identity systems, applications, and cloud services, each handled by a DSM. QFlow and flow sources feed network flow data.

Outbound and lateral, offenses can trigger notifications, open tickets, and feed response tooling. QRadar can send data to and receive context from other platforms, and offenses can drive orchestration in a separate SOAR product.

Data flows from sources into collectors, through processors where normalization and correlation happen, and into offenses and searches at the console. Reference sets let external context, such as a threat indicator list, participate in rules.

## Hardening and secure use

Control access by role. QRadar user roles and security profiles define which data a user can see and which functions they can use. Assign them by job need so analysts reach only the networks and log sources their work requires.

Treat authorized service tokens as secrets. QRadar issues authorized service tokens for API and integration access. A leaked token grants programmatic access to data and functions, so scope each token narrowly, store it in a secret manager, and rotate it. Do not embed tokens in scripts or configuration files; hardcoded tokens map to CWE-798 (Use of Hard-coded Credentials).

Require TLS. Encrypt the console, API, and, where supported, log source transport. Event and flow data and administrative sessions should not cross the network in cleartext.

Tune offenses and rules. Beyond signal quality, tuning is a security control: a flood of false offenses hides real ones. Review building blocks that define trusted hosts and networks, because an over-broad trust definition can suppress genuine detections.

Audit administrative and search activity. Track changes to rules, log sources, and service tokens, and review who accessed sensitive data.

## Where it fits in the program

QRadar is the detection and triage engine of a SOC that values network flow visibility alongside logs. It is where raw telemetry becomes offenses an analyst investigates.

In a wider program it pairs with remediation and response tooling rather than replacing them. Asset and vulnerability context can enrich its rules, and its offenses can feed incident response and orchestration. Given the product-line transition, architecture decisions should account for whether an organization stays on IBM's on-premises QRadar or moves along the Cortex XSIAM path.

For leadership it provides detection coverage and compliance reporting. For analysts it is the offense queue and the AQL search behind investigations.

## Resources

- IBM QRadar SIEM documentation
- IBM QRadar DSM Configuration Guide
- IBM QRadar Ariel Query Language documentation
- IBM QRadar administration and tuning guides

## Related pages

- [Platforms index](/platforms/README.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Splunk Enterprise Security](/platforms/splunk.md)
- [Cortex XSOAR](/platforms/cortex-xsoar.md)
