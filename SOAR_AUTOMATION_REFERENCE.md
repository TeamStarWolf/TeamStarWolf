# SOAR Automation Reference Library
> Professional Cybersecurity Reference | Maintained by TeamStarWolf Security Engineering

> **In one minute** — This is a working reference for SOAR (Security Orchestration, Automation, and Response): platforms that let a SOC connect its security tools, automate repetitive triage, and run incident response through playbooks (predefined response workflows). It covers playbook design patterns, then platform-specific code and APIs for Splunk SOAR, Palo Alto XSOAR, Microsoft Sentinel, and IBM QRadar SOAR, plus ready-made automation for phishing, malware, ransomware, and BEC. It is useful because the examples are copy-adaptable Python, YAML, and API calls, not just concepts.

| | |
|---|---|
| **Read this when** | you are designing or hardening a playbook (triggers, error handling, approval gates), you need the API or SDK pattern for a specific SOAR platform, you are automating phishing/malware/ransomware/BEC response, you are measuring SOAR ROI or playbook effectiveness |
| **Start at** | [SOAR Fundamentals](#_1-soar-fundamentals), [Playbook Design](#_2-playbook-design), [IR Automation by Incident Type](#_9-ir-automation-by-incident-type) |
| **Pairs with** | [SIEM_REFERENCE.md](SIEM_REFERENCE.md), [THREAT_INTELLIGENCE_REFERENCE.md](THREAT_INTELLIGENCE_REFERENCE.md), [THREAT_HUNTING_PLAYBOOKS.md](THREAT_HUNTING_PLAYBOOKS.md), [disciplines/incident-response.md](disciplines/incident-response.md) |

---

## Table of Contents
1. [SOAR Fundamentals](#_1-soar-fundamentals)
2. [Playbook Design](#_2-playbook-design)
3. [Splunk SOAR (Phantom)](#_3-splunk-soar-phantom)
4. [Palo Alto XSOAR](#_4-palo-alto-xsoar)
5. [Microsoft Sentinel Automation](#_5-microsoft-sentinel-automation)
6. [IBM QRadar SOAR](#_6-ibm-qradar-soar)
7. [Phishing & Malware Triage Automation](#_7-phishing-amp-malware-triage-automation)
8. [Threat Intelligence Automation](#_8-threat-intelligence-automation)
9. [IR Automation by Incident Type](#_9-ir-automation-by-incident-type)
10. [SOAR Metrics & Operations](#_10-soar-metrics-amp-operations)

---

## 1. SOAR Fundamentals

### What Is SOAR?
Security Orchestration, Automation, and Response (SOAR) is a category of security platforms that enables SOC teams to collect threat data from multiple sources, automate repetitive tasks, and orchestrate complex incident response workflows. The term was coined by Gartner and encompasses three core capabilities:

- **Orchestration**: Connecting and coordinating disparate security tools, systems, and data sources into unified workflows. Orchestration ties together firewalls, EDR platforms, threat intel feeds, ticketing systems, communication tools, and cloud APIs so they act as a single cohesive defense ecosystem.
- **Automation**: Executing predefined response actions without human intervention. This includes enriching alerts with threat context, blocking malicious IPs, quarantining endpoints, disabling compromised accounts, and generating incident reports at machine speed.
- **Response**: Providing case management, playbook execution tracking, collaboration workspaces (war rooms), and structured IR workflows that guide analysts from detection through remediation and closure.

SOAR platforms reduce mean time to detect (MTTD) and mean time to respond (MTTR), decrease alert fatigue by filtering noise, and allow Tier-1 analysts to focus on high-value decisions rather than repetitive triage tasks.

### SOAR vs SIEM vs XDR

| Dimension | SIEM | SOAR | XDR |
|---|---|---|---|
| **Primary Function** | Log aggregation, correlation, alerting | Workflow automation, orchestration, case management | Cross-layer detection and native response |
| **Data Scope** | Logs from any source | Inputs from SIEM, EDR, TIP, ticketing | Endpoint, network, cloud, email (vendor ecosystem) |
| **Response Capability** | Limited (basic alerting) | Full playbook-driven automation | Native automated response within vendor stack |
| **Integration Model** | Log ingestion via syslog/API | API-driven bidirectional integrations | Deep vendor-native integrations |
| **Analyst Workflow** | Alert review, manual investigation | Guided/automated investigation + response | Unified investigation console |
| **Typical Users** | SIEM analysts, threat hunters | SOC automation engineers, IR leads | Enterprise SOC teams (vendor-aligned) |
| **Example Platforms** | Splunk, Microsoft Sentinel, IBM QRadar | Splunk SOAR, XSOAR, IBM SOAR, Tines | Microsoft Defender XDR, CrowdStrike Falcon, Palo Alto Cortex |

SIEM and SOAR are highly complementary: SIEM detects and generates alerts; SOAR consumes those alerts and drives automated or guided response. XDR increasingly absorbs some SOAR capabilities natively but typically lacks the deep third-party orchestration breadth that dedicated SOAR platforms provide.

### Core SOAR Components

**Orchestration Engine**
The orchestration engine is the workflow runtime that executes playbooks. It manages task sequencing (sequential, parallel, conditional branching), handles inter-action data passing, evaluates decision logic, and coordinates across integrated tools. Enterprise-grade engines support hundreds of concurrent playbook executions with queuing, prioritization, and fault tolerance.

**Automation Engine**
The automation engine executes individual actions against integrated tools: running API calls, executing scripts, invoking threat intel lookups, or triggering cloud functions. It manages authentication, retry logic, rate limit handling, and response parsing. Modern automation engines support containerized execution environments to isolate and version integrations independently.

**Case Management**
Case management (sometimes called incident management) provides structured tracking of security incidents from creation through closure. Features include: incident timeline visualization, task assignment and tracking, SLA monitoring, evidence attachment, analyst collaboration notes, audit trail logging, and integration with external ticketing systems (ServiceNow, Jira, PagerDuty).

**Threat Intelligence Platform (TIP) Integration**
SOAR platforms integrate with TIPs to automatically enrich indicators (IPs, domains, hashes, URLs) with reputation data, attribution, MITRE ATT&CK mappings, and related IOC context. Some SOAR platforms include embedded TIP functionality such as XSOAR indicator management and Splunk SOAR artifact enrichment.

**Integration Layer**
The integration layer provides pre-built connectors (apps, integrations, plugins) to hundreds of security and IT tools. Connections are authenticated via API keys, OAuth, certificates, or service accounts. Integration catalogs range from 300+ (Tines) to 1000+ (XSOAR marketplace). Custom integrations can be built using SDKs or REST API wrappers.

### Deployment Models

| Model | Description | Use Case |
|---|---|---|
| **On-Premises** | SOAR installed in customer data center | Air-gapped environments, strict data residency |
| **Cloud-Hosted SaaS** | Vendor-managed cloud deployment | Fastest time-to-value, automatic upgrades |
| **Hybrid** | Cloud SOAR with on-prem integration bridges | Large enterprises with mixed environments |
| **Multi-Tenant** | Single SOAR instance serving multiple orgs | MSSPs, managed security service providers |

### Vendor Landscape

| Vendor | Platform | Key Strengths |
|---|---|---|
| **Splunk** | Splunk SOAR (formerly Phantom) | Largest app catalog (~500+), strong Python SDK, on-prem/cloud/hybrid |
| **Palo Alto Networks** | Cortex XSOAR | Deep Palo Alto integration, MSSP multi-tenancy, rich marketplace |
| **IBM** | QRadar SOAR (formerly Resilient) | Mature case management, privacy/compliance modules, strong QRadar sync |
| **Microsoft** | Sentinel Playbooks (Logic Apps) | Azure-native, 200+ Logic App connectors, tight M365/Defender integration |
| **Swimlane** | Swimlane Turbine | Low-code builder, strong reporting, flexible data model |
| **Tines** | Tines | No-code/low-code, transparent pricing, fast onboarding |
| **Torq** | Torq Hyperautomation | Hyperautomation focus, enterprise scalability, AI-assisted building |
| **D3 Security** | D3 Smart SOAR | MITRE ATT&CK native, strong case management, global deployment |

### ROI Metrics
SOAR ROI is quantified across several dimensions:

- **MTTD Reduction**: Automated enrichment cuts analyst time to understand an alert from hours to seconds. Typical organizations report 60-80% MTTD reduction within 12 months of SOAR deployment.
- **MTTR Reduction**: Automated containment and remediation actions drive MTTR from days to hours or minutes. Industry benchmarks show 50-70% MTTR improvement with mature playbook coverage.
- **Automation Rate %**: Percentage of alerts handled without analyst intervention. Leading SOCs achieve 70-90% automation rates for high-volume, well-defined alert types (phishing, malware, vulnerability notifications).
- **Alert-to-Ticket Ratio**: Ratio of raw alerts to actionable tickets created. SOAR filtering and correlation typically reduces this ratio by 80-95%.
- **Analyst Hours Saved**: Calculated as (avg manual task time x volume) minus (SOAR execution time x volume). A single phishing playbook handling 200 alerts per day at 15 minutes per alert manual equals 50 analyst-hours per day saved.
- **Cost Per Incident**: Total SOC operating cost divided by incident volume. SOAR reduces cost per incident by increasing throughput without proportional headcount growth.

### SOAR Maturity Model

| Level | Name | Characteristics |
|---|---|---|
| **L0** | Manual | All triage and response manual; SOAR not deployed |
| **L1** | Alert Enrichment | SOAR enriches alerts automatically; analysts still decide actions |
| **L2** | Semi-Automated Response | Common response actions automated (IP block, user disable); analyst approves |
| **L3** | Playbook-Driven SOC | Comprehensive playbooks for all tier-1 alert types; minimal manual triage |
| **L4** | Autonomous Response | AI-assisted decision-making; fully automated containment for known patterns |
| **L5** | Adaptive & Self-Optimizing | Playbooks self-tune based on outcomes; threat-intel-driven proactive automation |

Most enterprise SOCs target L3 within 18-24 months of SOAR deployment. L4-L5 maturity requires significant data quality investment, ML model development, and governance frameworks to manage autonomous response risk.

---
## 2. Playbook Design

### Trigger Types

**Alert-Based Triggers**
The most common trigger: a SIEM alert, EDR detection, or threat intel hit creates an event that fires a playbook. Alert triggers typically pass the alert metadata (severity, source IP, affected host, rule name) into the playbook as input data. Filtering criteria determine which playbooks fire for which alert types, preventing runaway execution.

```yaml
trigger:
  type: alert
  conditions:
    - field: alert.type
      operator: equals
      value: "phishing_email"
    - field: alert.severity
      operator: gte
      value: 3
```

**Scheduled Triggers**
Playbooks that run on a cron-like schedule for proactive tasks: threat intel sync, vulnerability report generation, IOC expiry cleanup, SLA breach checks, and daily health checks on integrations. Scheduled playbooks typically pull data from external sources and push updates to internal systems.

```yaml
trigger:
  type: schedule
  cron: "0 6 * * *"   # Daily at 06:00 UTC
  timezone: "UTC"
```

**Manual Triggers**
Analyst-initiated playbook execution against a specific case, artifact, or indicator. Manual triggers are essential for ad-hoc investigation workflows, re-investigation of closed cases, or running enrichment on newly discovered IOCs. Most SOAR UIs expose a "Run Playbook" button with a selection dialog.

**Webhook Triggers**
Inbound HTTP POST requests from external systems fire playbooks in real time. Common sources: vulnerability scanners (Tenable, Qualys), cloud security posture tools (Wiz, Orca), identity providers (Okta, Azure AD), or custom in-house tools. Webhook endpoints require authentication via HMAC signature validation, API key headers, or mTLS.

```python
# Webhook validation example (Splunk SOAR)
import hmac, hashlib

def validate_webhook(secret, payload, signature):
    computed = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)
```

### Decision Trees and Conditional Logic

Playbook decision trees encode the analyst decision-making logic into structured conditional branches. Well-designed trees handle the full spectrum of possible outcomes at each step:

```
Phishing Alert Received
+-- Is URL present?
|   +-- YES -> Detonate URL in sandbox
|   |   +-- Verdict: Malicious -> Block URL + Notify Reporter + Escalate
|   |   +-- Verdict: Suspicious -> Analyst Review Queue
|   |   +-- Verdict: Clean -> Close + Notify Reporter
|   +-- NO -> Is attachment present?
|       +-- YES -> Submit hash to TIP
|       +-- NO -> Header analysis only -> Low-confidence close
```

Key principles for decision tree design:
- Every branch must have a defined outcome with no hanging paths
- Include explicit handling for API errors and timeouts
- Parameterize thresholds (severity scores, confidence levels) rather than hardcoding values
- Document the rationale for each decision node in playbook comments

### Parallel vs Sequential Execution

**Sequential Execution**: Actions run one after another, each depending on the previous result. Use for workflows where action B requires output from action A, for example get device ID then isolate device by ID.

**Parallel Execution**: Multiple independent actions run simultaneously, reducing total wall-clock time. Use when actions do not depend on each other's results, for example simultaneously querying VirusTotal, AbuseIPDB, and Shodan for IP enrichment.

```
Sequential (total: A+B+C time):      Parallel (total: max(A,B,C) time):
A -> B -> C                           A --+
                                      B --+--> Join -> D
                                      C --+
```

Most SOAR platforms support fan-out/fan-in patterns with join nodes that wait for all parallel branches to complete before proceeding.

### Error Handling and Rollback

Robust playbooks anticipate failures at every action:

```yaml
action:
  name: block_ip_on_firewall
  app: palo_alto_firewall
  parameters:
    ip: "{{artifact.cef.sourceAddress}}"
  on_success: notify_analyst_blocked
  on_failure:
    - action: log_failure
      message: "Firewall block failed for {{artifact.cef.sourceAddress}}"
    - action: create_manual_task
      title: "Manual block required: {{artifact.cef.sourceAddress}}"
      assign_to: firewall_team
  retry:
    max_attempts: 3
    backoff_seconds: 30
```

**Rollback patterns**: For actions with side effects (account disables, firewall blocks), maintain a rollback log. Rollback playbooks can reverse changes if an action was taken in error:

```python
# Rollback: re-enable a disabled AD account
def rollback_account_disable(container, username):
    phantom.act("enable account",
                parameters=[{"username": username}],
                app="active_directory",
                name="rollback_enable")
    phantom.comment(container=container["id"],
                    comment=f"ROLLBACK: Re-enabled account {username}")
```

### Playbook Versioning and Testing

**Version Control**: Store all playbook definitions (YAML, JSON, or exported formats) in Git. Use branches for development, pull requests for peer review, and tags for production releases. Every production playbook deployment should be traceable to a specific Git commit.

```
main (production)
+-- develop (integration testing)
|   +-- feature/phishing-v2-url-detonation
|   +-- bugfix/malware-hash-timeout
+-- hotfix/critical-firewall-block-fix
```

**Testing Framework Levels**:
- **Unit Tests**: Test individual action logic with mocked API responses. Validate input/output data transformations.
- **Integration Tests**: Test against sandbox/staging instances of integrated tools with real API calls.
- **Regression Tests**: Run the full playbook against a library of historical test cases to ensure new changes do not break existing behavior.
- **Chaos Tests**: Inject deliberate failures (network timeouts, API 500 errors) to verify error handling paths execute correctly.

```python
# Example pytest-based playbook unit test
def test_ip_enrichment_malicious():
    mock_vt_response = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 45}}}
    }
    result = enrich_ip("185.220.101.1", vt_client=MockVTClient(mock_vt_response))
    assert result["verdict"] == "malicious"
    assert result["malicious_count"] == 45
```

### YAML/JSON Playbook Formats

Splunk SOAR exports playbooks as Python code (.py). XSOAR stores playbooks as YAML with a structured task graph. Tines exports stories as JSON. Sentinel playbooks are ARM templates (JSON) or Bicep.

```yaml
# XSOAR Playbook Task Structure (simplified)
id: "phishing-triage-v2"
version: 12
name: "Phishing Triage v2"
tasks:
  "1":
    id: "1"
    taskid: "check-url-present"
    type: condition
    conditions:
      - label: "yes"
        condition:
          - operator: isNotEmpty
            left:
              value: "incident.urls"
    continueonerror: false
  "2":
    id: "2"
    taskid: "detonate-url"
    type: playbook
    loop:
      forEach: true
      input: "incident.urls"
```

### CI/CD for Playbooks

A mature playbook CI/CD pipeline includes:

1. **Lint & Static Analysis**: Check syntax, undefined variables, unreachable branches
2. **Automated Validation**: `demisto-sdk validate` (XSOAR), custom schema validators (Tines JSON)
3. **Security Scanning**: Check for hardcoded credentials, injection vulnerabilities in custom code blocks
4. **Unit Test Execution**: Run mocked playbook tests
5. **Staging Deployment**: Auto-deploy to staging SOAR instance
6. **Integration Test Run**: Execute playbooks against test data in staging
7. **Approval Gate**: Require senior engineer sign-off for production promotion
8. **Production Deployment**: Automated deployment via SOAR API
9. **Post-Deploy Validation**: Smoke test with known-good test case

```yaml
# .github/workflows/playbook-ci.yml (excerpt)
name: Playbook CI
on: [pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install demisto-sdk
        run: pip install demisto-sdk
      - name: Validate content
        run: demisto-sdk validate -i Packs/PhishingTriage/
      - name: Run unit tests
        run: demisto-sdk test-content -i Packs/PhishingTriage/ --no-docker
```

### Approval Gates and Human-in-the-Loop

Not all response actions should be fully automated. Human-in-the-loop (HITL) design patterns:

- **Approval Workflows**: High-impact actions (blocking a /16 subnet, disabling a VIP executive account) pause and request explicit analyst approval via email, Slack, or SOAR UI notification before proceeding.
- **Confidence Thresholds**: Automate response when confidence score exceeds a threshold; route to analyst queue when confidence falls below.
- **Escalation Timers**: If no analyst response within N minutes, auto-escalate to a supervisor or apply a conservative default action.
- **Audit Logging**: Every automated action and every approval decision is logged with actor identity and timestamp for compliance and post-incident review.

```python
# Splunk SOAR approval pattern
def request_approval(container_id, message):
    phantom.prompt2(
        container=container_id,
        message=message,
        respond_in_mins=30,
        name="approval_gate",
        parameters=[{
            "data_type": "boolean",
            "required": True,
            "prompt": "Approve action?",
            "default": False
        }],
        callback=handle_approval_response
    )
```

### Playbook Metrics

| Metric | Description | Target |
|---|---|---|
| **Execution Time (p50/p95)** | Median and 95th-percentile playbook wall-clock time | p50 < 2 min, p95 < 10 min |
| **Success Rate %** | % of executions completing without errors | > 95% |
| **Action Failure Rate** | % of individual actions failing within executions | < 5% per action |
| **False Positive Rate** | % of automated actions later reversed as incorrect | < 2% |
| **Human Override Rate** | % of auto-decisions overridden by analysts | Monitor for trend |
| **Coverage %** | % of alert types with active playbook coverage | Target 80%+ for tier-1 |

---
## 3. Splunk SOAR (Phantom)

### Platform Architecture Overview
Splunk SOAR (formerly Phantom) is an on-premises, cloud, and hybrid SOAR platform. Its core architecture consists of:
- **Phantom Core**: Django-based web application and REST API server
- **App Runner**: Isolated execution environment for app actions (Python virtualenvs or containers)
- **Clustering**: Active-active cluster with shared PostgreSQL and NFS storage
- **Message Queue**: RabbitMQ for action distribution across cluster nodes
- **Search**: Elasticsearch for artifact and event search

### App Framework
Phantom apps are Python packages that wrap integrations with external tools. Each app contains:

```
my_connector/
+-- my_connector.py          # Main connector class
+-- my_connector.json        # App metadata and action definitions
+-- requirements.txt         # Python dependencies
+-- icon.png                 # App icon (PNG, 200x200)
+-- readme.html              # Documentation
```

**Connector Base Class**:
```python
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

class MyConnector(BaseConnector):

    def initialize(self):
        self._config = self.get_config()
        self._base_url = self._config.get("base_url")
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, response = self._make_rest_call("/api/health", action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        action = self.get_action_identifier()
        if action == "test_connectivity":
            return self._handle_test_connectivity(param)
        elif action == "lookup_ip":
            return self._handle_lookup_ip(param)
```

### Action Types

| Action Type | Description | Examples |
|---|---|---|
| **investigate** | Read-only data retrieval | get user info, lookup IP, get process list |
| **contain** | Isolate or restrict resources | block IP, disable user, quarantine endpoint |
| **correct** | Remediation actions | delete email, restore file, unlock account |
| **generic** | Multi-purpose | run query, execute script |
| **test connectivity** | Verify app configuration | ping API endpoint |

### Container and Artifact Model

**Containers** are the top-level objects (analogous to cases/incidents). Each container has:
- `id`, `name`, `description`, `severity`, `status`, `sensitivity`
- `label` (categorization tag, e.g., "events", "alerts")
- `tags`, `owner`, `due_time`, `close_time`
- Custom fields via container metadata

**Artifacts** are the data objects attached to containers. Each artifact contains:
- `cef` (Common Event Format) dictionary of key-value fields
- `cef_types` mapping field names to CEF data types (e.g., `{"sourceAddress": ["ip"]}`)
- `label`, `name`, `severity`, `type`
- Source data reference

```python
# Creating a container and artifact via REST API
import requests

PHANTOM_BASE = "https://phantom.company.com"
PHANTOM_HEADERS = {"ph-auth-token": PHANTOM_TOKEN}

container = {
    "name": "Phishing Alert - user@company.com",
    "label": "alert",
    "severity": "high",
    "tags": ["phishing", "email"]
}
resp = requests.post(f"{PHANTOM_BASE}/rest/container",
                     json=container, headers=PHANTOM_HEADERS, verify=False)
container_id = resp.json()["id"]

artifact = {
    "container_id": container_id,
    "name": "Email Artifact",
    "label": "email",
    "cef": {
        "fromEmail": "attacker@evil.com",
        "toEmail": "victim@company.com",
        "emailHeaders": "Received: from mx.evil.com...",
        "requestURL": "http://malicious.example.com/payload"
    },
    "cef_types": {
        "fromEmail": ["email"],
        "requestURL": ["url"]
    }
}
requests.post(f"{PHANTOM_BASE}/rest/artifact",
              json=artifact, headers=PHANTOM_HEADERS, verify=False)
```

### Phantom Python SDK Key Functions

```python
import phantom.app as phantom
import phantom.rules as ph_rules

# Execute an action
def run_ip_lookup(container):
    phantom.act(
        "lookup ip",
        parameters=[{"ip": "185.220.101.1"}],
        app_list=[{"app": "virustotal", "match_action": "lookup ip"}],
        callback=handle_vt_result,
        name="vt_lookup",
        parent_action_id=0,
        identifier=0,
        effective_user=None
    )

# Collect results from a previous action
def handle_vt_result(action=None, success=None, container=None,
                     results=None, handle=None):
    if not success:
        phantom.error("VirusTotal lookup failed")
        return

    data = phantom.collect2(
        container=container,
        datapath=["vt_lookup:action_result.data.*.attributes"
                  ".last_analysis_stats.malicious"],
        action_results=results
    )
    malicious_count = data[0][0] if data else 0

    if malicious_count > 5:
        phantom.tag(container=container["id"], tag="confirmed_malicious")
        phantom.severity(container=container["id"], severity="critical")

    phantom.comment(
        container=container["id"],
        comment=f"IP 185.220.101.1: {malicious_count} malicious detections on VT"
    )

# Container property management
phantom.severity(container=container["id"], severity="high")
phantom.status(container=container["id"], status="open")
phantom.sensitivity(container=container["id"], sensitivity="red")

# Create a note
phantom.note(
    container=container["id"],
    note_type="general",
    title="Enrichment Summary",
    content="Automated enrichment completed. See artifact data for details."
)
```

### REST API Reference

```bash
# Authentication: ph-auth-token header
curl -X GET https://phantom.company.com/rest/container/1   -H "ph-auth-token: YOUR_TOKEN"

# Key endpoints
POST /rest/container              # Create container
GET  /rest/container/{id}         # Get container details
POST /rest/artifact               # Create artifact
GET  /rest/artifact?_filter_container_id={id}  # List artifacts for container
POST /rest/playbook_run           # Execute a playbook
GET  /rest/app_run/{id}           # Get action run status
POST /rest/action_run             # Run an action directly
GET  /rest/action_run/{id}/app_runs/{id}/output  # Get action output
POST /rest/note                   # Add a note to container
GET  /rest/decided_list/{name}    # Read a custom list
POST /rest/decided_list           # Create/update custom list
GET  /rest/playbook?page_size=100 # List available playbooks
```

### Custom Functions
Custom functions in Splunk SOAR are reusable Python code blocks that can be called from multiple playbooks:

```python
# custom_functions/enrich_ip_composite.py
def enrich_ip_composite(container=None, handle=None, filtered_artifacts=None,
                         filtered_results=None, custom_function=None, **kwargs):
    """Aggregate enrichment from VT, AbuseIPDB, and Shodan into a verdict"""
    import phantom.rules as phantom
    import json

    inputs = phantom.get_current_scope(handle)
    source_ip = inputs.get("ip_address")

    vt_malicious = inputs.get("vt_malicious_count", 0)
    abuse_score = inputs.get("abuseipdb_score", 0)
    shodan_vulns = inputs.get("shodan_vuln_count", 0)

    score = (vt_malicious * 3) + (abuse_score * 0.5) + (shodan_vulns * 2)
    verdict = "malicious" if score > 20 else "suspicious" if score > 8 else "clean"

    outputs = {
        "composite_score": score,
        "verdict": verdict,
        "ip": source_ip,
        "recommendation": "isolate" if verdict == "malicious" else
                          "monitor" if verdict == "suspicious" else "allow"
    }
    phantom.save_run_data(value=json.dumps(outputs), key="composite_enrichment")
```

### Workbooks
Workbooks provide structured investigation checklists tied to incident types. Each workbook contains phases (Discovery, Analysis, Containment, Recovery), each with tasks that can be manual or automated. Workbooks enforce procedural consistency and track analyst completion of required steps.

### HUD (Heads Up Display)
The HUD is the analyst primary investigation console. It presents container details, artifacts, action results, and playbook status in a configurable panel layout. Analysts can run ad-hoc actions, add notes, change severity/status, and view related containers directly from the HUD.

### Cloud C2 and Mission Control
- **Cloud C2**: Phantom cloud connector that allows on-prem Phantom instances to reach out to Splunk Cloud and cloud-hosted apps without inbound firewall rules.
- **Mission Control**: The unified SOC operations view showing active incidents, workbook progress across the team, SLA status, and analyst workload distribution.

---
## 4. Palo Alto XSOAR

### Platform Architecture
Cortex XSOAR (formerly Demisto) is Palo Alto Networks' SOAR platform. Architecture components:
- **Server**: Golang-based server handling API, playbook engine, and UI
- **Elasticsearch**: Incident, indicator, and investigation data storage
- **Docker**: Each integration runs in an isolated Docker container
- **Cortex Data Lake**: Optional cloud storage and analytics integration
- **MSSP Layer**: Multi-tenant architecture for service providers

### Incident Types and Layouts

Incident types define the schema and behavior for different alert categories. Each incident type specifies:
- **Fields**: Custom fields (text, number, date, list, boolean, grid) mapped to this incident type
- **Layout**: UI layout defining which fields appear in which panels for this incident type
- **Playbooks**: Default playbooks that auto-trigger when an incident of this type is created
- **Close Reasons**: Valid closure classifications

```python
# Creating an incident via XSOAR REST API
import requests

incident = {
    "name": "Phishing Email - sales@company.com",
    "type": "Phishing",
    "severity": 3,            # 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
    "labels": [{"type": "Email/src", "value": "attacker@evil.com"}],
    "CustomFields": {
        "emailfrom": "attacker@evil.com",
        "emailto": "sales@company.com",
        "emailsubject": "Urgent: Invoice Payment Required",
        "phishingreporteremailaddress": "security@company.com"
    }
}
resp = requests.post(
    "https://xsoar.company.com/incident",
    json=incident,
    headers={"Authorization": API_KEY},
    verify=True
)
```

### Playbook Engine Task Types

| Task Type | Description | Use Case |
|---|---|---|
| **Automated** | Runs an integration command automatically | IP lookup, file hash check, firewall block |
| **Manual** | Requires analyst to mark complete or input data | Evidence review, executive approval |
| **Conditional** | Branches based on field values or previous outputs | If severity > High, escalate; else auto-close |
| **Data Collection** | Presents a form to collect analyst input | Ask analyst to classify incident |
| **Playbook** | Calls a sub-playbook | Modular reuse of common workflows |
| **Start/End** | Marks playbook flow boundaries | Every playbook has exactly one start and one end |

```yaml
# XSOAR Playbook Task (YAML definition)
tasks:
  "10":
    id: "10"
    taskid: "10-enrich-ip"
    type: regular
    task:
      id: "abc123"
      version: 1
      name: "Enrich Source IP"
      script: "|||ip"
    scriptarguments:
      ip:
        simple: "${incident.sourceip}"
    outputs:
      - contextPath: DBotScore.Score
        description: "Reputation score"
        type: Number
    continueonerror: true
    view: |-
      { "position": { "x": 450, "y": 195 } }
```

### Integrations as Docker Containers
Every XSOAR integration runs in its own Docker container, providing:
- **Isolation**: A buggy or vulnerable integration cannot affect the XSOAR server
- **Dependency Management**: Each integration pins its Python dependencies independently
- **Versioning**: Integration versions are tracked separately from the platform
- **Custom Containers**: Organizations can build custom Docker images for integrations with specialized dependencies

```dockerfile
# Example custom integration Dockerfile
FROM demisto/python3:3.10.12.63474
COPY requirements.txt .
RUN pip install -r requirements.txt
```

### demisto-sdk

The `demisto-sdk` is the CLI toolchain for XSOAR content development:

```bash
# Install
pip install demisto-sdk

# Initialize a new integration
demisto-sdk init --integration --name MyNewIntegration   --output Packs/MyPack/Integrations/

# Lint Python code
demisto-sdk lint -i Packs/MyPack/Integrations/MyNewIntegration/

# Validate content structure and metadata
demisto-sdk validate -i Packs/MyPack/

# Upload to XSOAR instance
demisto-sdk upload -i Packs/MyPack/Integrations/MyNewIntegration/   --insecure --url https://xsoar.company.com --api-key $XSOAR_API_KEY

# Run an integration command directly
demisto-sdk run -q "!ip ip=8.8.8.8" --insecure   --url https://xsoar.company.com --api-key $XSOAR_API_KEY

# Download content from XSOAR instance
demisto-sdk download -o Packs/MyPack -i MyNewIntegration

# Format content files to standard
demisto-sdk format -i Packs/MyPack/
```

### Content Pack Structure

```
Packs/PhishingTriage/
+-- pack_metadata.json           # Pack name, version, author, tags, dependencies
+-- README.md
+-- Integrations/
|   +-- PhishingAnalyzer/
|       +-- PhishingAnalyzer.py
|       +-- PhishingAnalyzer.yml
|       +-- PhishingAnalyzer_test.py
|       +-- Pipfile
+-- Playbooks/
|   +-- playbook-Phishing_Triage_v2.yml
|   +-- playbook-URL_Detonation.yml
+-- IncidentTypes/
|   +-- incidenttype-Phishing.json
+-- IncidentFields/
|   +-- incidentfield-Email_From.json
|   +-- incidentfield-Phishing_Score.json
+-- Layouts/
|   +-- layout-Phishing_Incident.json
+-- Scripts/
|   +-- script-ParseEmailHeaders/
|       +-- ParseEmailHeaders.py
|       +-- ParseEmailHeaders.yml
+-- TestPlaybooks/
    +-- playbook-Test_Phishing_Triage_v2.yml
```

### Indicator Lifecycle

XSOAR has a built-in Threat Intelligence Management (TIM) module for indicator management:

1. **Ingestion**: Indicators sourced from threat intel integrations (MISP, VirusTotal, feed integrations)
2. **Deduplication**: Exact-match dedup; relationships mapped between related indicators
3. **Enrichment**: Automated enrichment playbooks run on new indicators
4. **Scoring**: DBot Score (0=Unknown, 1=Good, 2=Suspicious, 3=Bad) aggregated from sources
5. **Expiry**: Configurable TTL per indicator type; expired indicators archived or deleted
6. **Export**: Push to TIP, firewall blocklists, DNS sinkholes via export integrations

```python
# XSOAR Python script: Create and enrich an indicator
import demistomock as demisto
from CommonServerPython import *

def create_indicator(value, indicator_type, score, source):
    demisto.executeCommand("createNewIndicator", {
        "value": value,
        "type": indicator_type,    # IP, Domain, URL, File SHA256, etc.
        "score": score,            # 0-3
        "source": source,
        "expirationPolicy": "indicatorType",
        "CustomFields": {
            "trafficlightprotocol": "AMBER",
            "tags": ["auto-enriched"]
        }
    })
```

### War Rooms
War Rooms are collaborative investigation workspaces providing:
- Real-time chat between analysts assigned to an incident
- Integration command execution directly from chat (e.g., `!ip ip=1.2.3.4`)
- Automatic logging of all actions and results in the War Room timeline
- Evidence pinning (pin important results for quick reference)
- @mentions and task assignments
- War Room entry export for post-incident documentation

### MSSP Multi-Tenant
XSOAR multi-tenant architecture allows MSSPs to manage multiple customer environments from a single XSOAR instance:
- **Account**: Each customer is an isolated Account with separate incidents, indicators, and playbooks
- **Main Account**: MSSP operators work from the Main Account; content can be pushed to child accounts
- **Propagation**: Playbooks, integrations, and incident types can be propagated from Main to child accounts
- **Isolation**: Cross-account data access is controlled; customers cannot see each other's data

### CI/CD Pipeline for Content

```yaml
# .gitlab-ci.yml example for XSOAR content
stages:
  - validate
  - test
  - deploy-staging
  - deploy-production

validate-content:
  stage: validate
  image: demisto/demisto-sdk:latest
  script:
    - demisto-sdk validate -i Packs/PhishingTriage/ --post-commit
    - demisto-sdk lint -i Packs/PhishingTriage/

unit-tests:
  stage: test
  script:
    - demisto-sdk test-content -i Packs/PhishingTriage/ --no-docker

deploy-staging:
  stage: deploy-staging
  script:
    - demisto-sdk upload -i Packs/PhishingTriage/         --url $STAGING_URL --api-key $STAGING_KEY

deploy-production:
  stage: deploy-production
  when: manual
  script:
    - demisto-sdk upload -i Packs/PhishingTriage/         --url $PROD_URL --api-key $PROD_KEY
```

---
## 5. Microsoft Sentinel Automation

### Automation Architecture Overview
Microsoft Sentinel automation stack has two layers:
1. **Automation Rules**: Lightweight, fast rules that trigger on incident creation/update to perform simple actions (change severity, assign owner, add tags, suppress alerts, trigger playbooks). Rules execute in order with a priority ranking.
2. **Playbooks (Logic Apps)**: Full workflow automation using Azure Logic Apps, triggered by Sentinel automation rules or directly by analytics rules. Logic Apps provide 200+ connectors and support complex branching, loops, and API calls.

### Analytics Rule to Playbook Flow

```
SIEM Log -> Analytics Rule fires -> Alert Created -> Incident Created
                                                          |
                                                Automation Rule evaluates
                                                conditions (e.g., severity=High)
                                                          |
                                                Action: Run Playbook
                                                          |
                                                Logic App: Enrich -> Contain -> Notify
```

### Logic App Connectors for Security

Sentinel playbooks leverage the Azure Logic Apps connector ecosystem (200+ built-in connectors):

| Connector | Actions | Use Case |
|---|---|---|
| **Microsoft Sentinel** | Get incident, update incident, add comment, add entity | Incident manipulation |
| **Microsoft Defender for Endpoint** | Isolate machine, run AV scan, get machine actions | Endpoint response |
| **Microsoft Teams** | Post message, post adaptive card, create channel | Analyst notification |
| **Azure AD** | Get user, revoke sign-in sessions, disable user, reset password | Identity response |
| **Office 365 Outlook** | Send email, get email, delete email | Email response |
| **Slack** | Post message, post interactive message | Analyst notification |
| **ServiceNow** | Create/update incident, get record | ITSM integration |
| **HTTP** | Generic HTTP call | Any REST API integration |
| **Azure Key Vault** | Get secret | Secrets management |
| **VirusTotal** | Scan URL, get report | Threat intel enrichment |

### Sentinel Playbook ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "PlaybookName": { "type": "string", "defaultValue": "Sentinel-BlockIP-Playbook" }
  },
  "resources": [
    {
      "type": "Microsoft.Logic/workflows",
      "apiVersion": "2017-07-01",
      "name": "[parameters('PlaybookName')]",
      "location": "[resourceGroup().location]",
      "identity": { "type": "SystemAssigned" },
      "properties": {
        "definition": {
          "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
          "triggers": {
            "Microsoft_Sentinel_incident": {
              "type": "ApiConnectionWebhook",
              "inputs": {
                "body": { "callback_url": "@{listCallbackUrl()}" },
                "path": "/incident-creation"
              }
            }
          },
          "actions": {
            "Add_comment_to_incident": {
              "type": "ApiConnection",
              "inputs": {
                "body": {
                  "incidentArmId": "@triggerBody()?['object']?['id']",
                  "message": "Playbook executed successfully"
                },
                "path": "/Incidents/Comment"
              }
            }
          }
        }
      }
    }
  ]
}
```

### Watchlist-Driven Automation
Azure Sentinel Watchlists store reference data (VIP users, trusted IPs, sensitive assets) that can be queried in KQL analytics rules and playbooks:

```kql
// KQL: Alert when VIP user signs in from suspicious country
let VIPUsers = _GetWatchlist("VIP-Users") | project UserPrincipalName;
SigninLogs
| where UserPrincipalName in (VIPUsers)
| where Location !in ("US", "GB", "CA")
| where ResultType == 0
| summarize count() by UserPrincipalName, Location, IPAddress
| where count_ > 3
```

Playbooks can dynamically look up watchlist entries via the Sentinel API:
```python
import requests

def check_watchlist(subscription_id, rg, workspace_id, watchlist_name, item_key, token):
    url = (f"https://management.azure.com/subscriptions/{subscription_id}"
           f"/resourceGroups/{rg}/providers/Microsoft.OperationalInsights"
           f"/workspaces/{workspace_id}/providers/Microsoft.SecurityInsights"
           f"/watchlists/{watchlist_name}/watchlistItems")
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    items = resp.json().get("value", [])
    return any(
        item["properties"]["itemsKeyValue"].get("UPN") == item_key
        for item in items
    )
```

### UEBA Integration
Microsoft Sentinel UEBA enriches incidents with:
- **Entity Behavior Score**: Anomaly score for users and hosts based on baseline deviation
- **Blast Radius**: Estimated impact of a compromised entity
- **Peer Group Comparisons**: How an entity's behavior compares to similar entities
- **Timeline**: Full activity timeline for an entity across Microsoft services

```kql
BehaviorAnalytics
| where UserPrincipalName == "suspect@company.com"
| where TimeGenerated > ago(7d)
| summarize
    AnomalyCount=countif(ActivityInsights contains "Anomaly"),
    MaxScore=max(InvestigationPriority)
    by UserPrincipalName
```

### Hunting Notebook Automation with MSTICPy

```python
from msticpy.data import QueryProvider
from msticpy.analysis import iocextract

# Connect to Sentinel workspace
qry_prov = QueryProvider("AzureSentinel")
qry_prov.connect(WorkspaceConfig())

# Run KQL from Python
suspicious_logins = qry_prov.run_query("""
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where RiskLevelDuringSignIn in ("high", "medium")
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskDetail
""")

# Extract IOCs from results
extractor = iocextract.IoCExtract()
iocs = extractor.extract(suspicious_logins["UserPrincipalName"].str.cat(sep=" "))
```

### Microsoft Graph Security API

```python
import requests

def get_graph_alerts(token, filter_query="severity eq 'high'"):
    headers = {"Authorization": f"Bearer {token}"}
    url = (f"https://graph.microsoft.com/v1.0/security/alerts"
           f"?$filter={filter_query}&$top=50")
    return requests.get(url, headers=headers).json().get("value", [])

def update_alert_status(token, alert_id, status, feedback):
    url = f"https://graph.microsoft.com/v1.0/security/alerts/{alert_id}"
    body = {
        "status": status,      # "resolved", "inProgress", "newAlert"
        "feedback": feedback,  # "truePositive", "falsePositive", "benignPositive"
        "assignedTo": "SOC-Analyst@company.com",
        "comments": ["Investigated via SOAR playbook"]
    }
    requests.patch(url, json=body, headers={"Authorization": f"Bearer {token}"})

def create_threat_intelligence_indicator(token, indicator_value, indicator_type):
    url = "https://graph.microsoft.com/v1.0/security/tiIndicators"
    body = {
        "action": "block",
        "activityGroupNames": [],
        "confidence": 85,
        "description": "Indicator from SOAR automation",
        "expirationDateTime": "2026-08-01T00:00:00Z",
        "indicatorType": indicator_type,  # "networkIPv4", "domainName", "url", "fileSha256"
        "networkIPv4": indicator_value,
        "severity": 3,
        "targetProduct": "Microsoft Defender ATP",
        "tlpLevel": "amber"
    }
    return requests.post(url, json=body,
                         headers={"Authorization": f"Bearer {token}"}).json()
```

### Logic App Consumption vs Standard

| Feature | Consumption | Standard |
|---|---|---|
| **Pricing** | Per execution + connector call | Fixed monthly + execution units |
| **Networking** | Shared multi-tenant | VNet integration, private endpoints |
| **State** | Stateful workflows | Stateful + stateless workflows |
| **Performance** | Shared resources | Dedicated compute |
| **Best For** | Low-to-medium volume SOC automation | High-volume, VNet-isolated, latency-sensitive |

### Microsoft Defender XDR AIR (Automated Investigation and Response)
Defender XDR native AIR capability provides automated investigation without SOAR:
- **Trigger**: Alert from Defender for Endpoint, Office 365, or Identity
- **Investigation Graph**: Automated expansion of the incident entity graph (related processes, files, network connections, emails, users)
- **Verdict**: AI assigns verdict to each entity (malicious, suspicious, no threats found)
- **Remediation Actions**: Automatically queued (quarantine file, block IP, soft-delete email, disable user)
- **Approval**: Remediation actions require SOC team approval (configurable: auto-approve for low risk)
- **Integration**: AIR results surfaced in Sentinel as incidents, triggering Sentinel playbooks for extended response

---
## 6. IBM QRadar SOAR

### Platform Overview
IBM QRadar SOAR (formerly IBM Resilient) is a mature SOAR platform with deep case management capabilities. The platform centers on a structured workflow engine and has strong compliance/privacy features. Architecture components:
- **Resilient Server**: Java-based application server
- **PostgreSQL**: Primary data store for cases, tasks, artifacts
- **Elasticsearch**: Search indexing
- **Message Queue**: Apache Kafka for action dispatcher
- **Integration Services**: Python-based function runners for app integrations

### Case Management Workflows

SOAR cases (called Incidents) in QRadar SOAR follow a structured lifecycle:
1. **Creation**: Incident created manually, via SIEM sync, or via API
2. **Classification**: Type, severity, owner, affected parties assigned
3. **Phases**: Configurable phases (Detect, Analyze, Respond, Post-Incident)
4. **Tasks**: Required tasks per phase, with due dates and owners
5. **Artifacts**: IOCs and evidence attached to the incident
6. **Notes**: Structured notes and timeline entries
7. **SLA Tracking**: Phase and task SLAs monitored with automated escalation
8. **Closure**: Closure code, report generation, lessons learned capture

### Rules Engine
QRadar SOAR rules engine fires automation based on incident conditions:

```python
# Function triggered by rule: Ransomware incident created
# Rule conditions: incident.type == "Ransomware" AND incident.severity >= 4

import time

def assign_ransomware_incident(incident_id, client):
    patch = {
        "owner_id": IR_TEAM_QUEUE_ID,
        "discovered_date": int(time.time() * 1000),
        "properties": {"ir_team_notified": True}
    }
    client.incidents.patch(incident_id, patch)
    client.incidents.tasks.create(incident_id, {
        "name": "Confirm ransomware family",
        "due_date": int((time.time() + 3600) * 1000),
        "phase_id": ANALYZE_PHASE_ID,
        "owner_id": MALWARE_ANALYST_ID
    })
```

### Custom Python Functions

Functions in QRadar SOAR are Python 3 scripts that execute in an isolated function runner:

```python
from resilient_lib import ResultPayload, validate_fields
from resilient_circuits import ResilientComponent, function, StatusMessage

class FunctionComponent(ResilientComponent):
    """Function: IP Reputation Check"""

    @function("fn_ip_reputation_check")
    def _fn_ip_reputation_check_function(self, event, *args, **kwargs):
        yield StatusMessage("Starting IP reputation check...")

        fn_inputs = event.message["inputs"]
        validate_fields(["ip_address"], fn_inputs)
        ip_address = fn_inputs.get("ip_address")

        rp = ResultPayload("fn_ip_reputation_check", **kwargs)
        score, details = check_ip_reputation(ip_address)

        results = rp.done(True, {
            "ip": ip_address,
            "reputation_score": score,
            "details": details,
            "verdict": "malicious" if score > 70 else "clean"
        })
        yield FunctionResult(results)
```

### REST API Reference

```python
import resilient, time

client = resilient.get_client({
    "host": "soar.company.com",
    "port": 443,
    "org": "My Org",
    "email": "api-user@company.com",
    "password": "SOAR_API_PASSWORD",
    "cafile": False
})

# Create an incident
new_incident = client.post("/incidents", {
    "name": "Ransomware Detection - Server01",
    "incident_type_ids": [RANSOMWARE_TYPE_ID],
    "severity_code": {"id": 4},
    "description": {"format": "html", "content": "<p>Automated detection</p>"},
    "discovered_date": int(time.time() * 1000),
    "properties": {
        "affected_hosts": "Server01.company.com",
        "detection_source": "CrowdStrike Falcon"
    }
})
incident_id = new_incident["id"]

# CRUD operations
incident = client.get(f"/incidents/{incident_id}")
client.patch(f"/incidents/{incident_id}", {"owner_id": IR_LEAD_ID,
                                           "phase_id": RESPOND_PHASE_ID})

# Add artifact
client.post(f"/incidents/{incident_id}/artifacts", {
    "type": {"name": "IP Address"},
    "value": "185.220.101.1",
    "description": {"format": "text", "content": "C2 IP from beacon traffic"},
    "properties": [{"name": "country_code", "value": "RU"}]
})

# Add note
client.post(f"/incidents/{incident_id}/comments", {
    "text": {"format": "html",
             "content": "<p>IP flagged as TOR exit node (AbuseIPDB score: 95)</p>"}
})

# Task management
tasks = client.get(f"/incidents/{incident_id}/tasks")
client.patch(f"/tasks/{tasks[0]['id']}", {"status": "C"})  # C = Completed
```

### Dynamic Playbooks

Dynamic Playbooks provide condition-based task generation:

```python
def should_escalate_to_ciso(incident, fields):
    return (
        incident.get("severity_code", {}).get("id", 0) >= 4
        or fields.get("pii_involved") is True
        or fields.get("estimated_records_affected", 0) > 1000
    )
```

### Privacy Module - GDPR/CCPA Breach Response

QRadar SOAR includes a purpose-built Privacy module for regulatory breach response:

**Breach Assessment Workflow**:
1. **Classification**: Is the incident a personal data breach? (PII types affected)
2. **Risk Assessment**: Score breach risk (sensitivity x volume x likelihood of harm)
3. **Regulatory Mapping**: Which regulations apply? (GDPR Article 33, CCPA, HIPAA, state laws)
4. **Notification Deadlines**: Auto-calculate notification deadlines (GDPR: 72 hours to DPA; CCPA: 30 days to AG)
5. **Authority Notification**: Track notification to Data Protection Authorities
6. **Subject Notification**: Track notification to affected data subjects
7. **Documentation**: Auto-generate regulatory documentation artifacts

```python
from datetime import datetime, timedelta

def calculate_gdpr_deadline(discovery_timestamp_ms):
    discovery_dt = datetime.utcfromtimestamp(discovery_timestamp_ms / 1000)
    dpa_deadline = discovery_dt + timedelta(hours=72)
    return {
        "dpa_notification_deadline": dpa_deadline.isoformat() + "Z",
        "hours_remaining": max(
            0, (dpa_deadline - datetime.utcnow()).total_seconds() / 3600
        )
    }
```

### SLA Tracking and Escalation

```python
sla_config = {
    "name": "Critical Incident SLA",
    "conditions": [
        {"field": "severity_code.id", "value": 5, "operator": "equals"}
    ],
    "phases": [
        {"phase_id": DETECT_PHASE_ID,  "hours": 1, "escalate_to": SIRT_LEAD_ID},
        {"phase_id": ANALYZE_PHASE_ID, "hours": 4, "escalate_to": CISO_ID},
        {"phase_id": RESPOND_PHASE_ID, "hours": 8, "escalate_to": CTO_ID}
    ]
}
```

### QRadar SIEM Bidirectional Sync

QRadar SOAR integrates natively with IBM QRadar SIEM:
- **Alert to Incident**: QRadar offenses auto-create SOAR incidents via the QRadar plugin
- **Incident to Offense**: SOAR incident status changes sync back to QRadar offense status
- **Artifact Enrichment**: SOAR incidents automatically pull network flows and log data from QRadar
- **Custom Properties**: Map QRadar offense fields to SOAR incident custom fields
- **Closed Loop**: When SOAR closes an incident as False Positive, QRadar offense is closed and analyst feedback is stored for tuning

### App Exchange
IBM QRadar App Exchange provides 300+ pre-built integrations and content packs including:
- Threat intelligence integrations (MISP, IBM X-Force, VirusTotal, Recorded Future)
- EDR integrations (CrowdStrike, Carbon Black, SentinelOne, Tanium)
- Ticketing integrations (ServiceNow, Jira, PagerDuty)
- Cloud integrations (AWS GuardDuty, Azure Security Center, GCP SCC)
- Compliance frameworks (NIST CSF, ISO 27001, PCI-DSS mapped tasks)

---
## 7. Phishing & Malware Triage Automation

### Phishing Response Playbook

**Complete Phishing Triage Workflow**:

```
Phishing Reported (via email/API/SIEM alert)
        |
Extract Artifacts (sender, URLs, attachments, headers)
        |
   +----+-------------------------------+
   |                                    |
URL Detonation                    Header Analysis
(sandbox/VTAPI)                   (SPF/DKIM/DMARC)
   |                                    |
   +--------------------+---------------+
                        |
                Verdict Determination
                +-- Malicious -> Block URLs + Quarantine + Notify + Escalate
                +-- Suspicious -> Analyst Queue + Soft-block
                +-- Benign -> Notify Reporter + Close
```

**Step 1: Extract Artifacts from Email**
```python
import email, re, hashlib
from email import policy

def parse_email(raw_email_bytes):
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
    artifacts = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "reply_to": msg.get("Reply-To"),
        "message_id": msg.get("Message-ID"),
        "received_headers": msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results"),
        "urls": [],
        "attachments": []
    }
    body = ""
    for part in msg.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            try:
                body += part.get_content()
            except Exception:
                pass
    artifacts["urls"] = list(set(re.findall(
        r'https?://[^\s<>"{}|\^`\[\]]+', body
    )))
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            artifacts["attachments"].append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest()
            })
    return artifacts
```

**Step 2: URL Detonation via VirusTotal API v3**
```python
import requests, base64, time

def detonate_url_vt(url, vt_api_key):
    headers = {"x-apikey": vt_api_key}
    submit_resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data={"url": url},
        headers=headers
    )
    analysis_id = submit_resp.json()["data"]["id"]

    for _ in range(12):
        time.sleep(5)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        ).json()
        if result["data"]["attributes"]["status"] == "completed":
            stats = result["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "verdict": "malicious" if malicious > 3 else
                           "suspicious" if suspicious > 2 else "clean"
            }
    return {"verdict": "timeout"}
```

**Step 3: M365 Defender Mailbox Remediation**
```python
def search_and_delete_phishing_emails(token, sender_email, subject):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    hunt_url = ("https://graph.microsoft.com/v1.0/security/"
                "microsoft.graph.security.runHuntingQuery")
    query = (f"EmailEvents | where SenderFromAddress == '{sender_email}'"
             f" | where Subject contains '{subject}'"
             f" | where Timestamp > ago(7d)"
             f" | project NetworkMessageId, RecipientEmailAddress, DeliveryLocation")
    emails = requests.post(hunt_url, json={"query": query},
                           headers=headers).json().get("results", [])
    deleted = 0
    for record in emails:
        if record.get("DeliveryLocation") == "Inbox":
            resp = requests.post(
                f"https://graph.microsoft.com/v1.0/users/{record['RecipientEmailAddress']}"
                f"/messages/{record['NetworkMessageId']}/move",
                json={"destinationId": "deleteditems"},
                headers=headers
            )
            if resp.status_code in [200, 201]:
                deleted += 1
    return {"emails_found": len(emails), "emails_deleted": deleted}
```

### Proofpoint TAP API Integration
```python
from datetime import datetime, timedelta

def get_proofpoint_threats(principal, secret, interval_seconds=3600):
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(seconds=interval_seconds)
    resp = requests.get(
        "https://tap-api-v2.proofpoint.com/v2/siem/all",
        params={
            "format": "json",
            "sinceTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "interval": f"PT{interval_seconds}S"
        },
        auth=(principal, secret)
    )
    data = resp.json()
    return {
        "clicks_blocked": data.get("clicksBlocked", []),
        "clicks_permitted": data.get("clicksPermitted", []),
        "messages_blocked": data.get("messagesBlocked", []),
        "messages_delivered": data.get("messagesDelivered", [])
    }
```

### Malware Triage Automation

**Hash Lookup Pipeline**:
```python
def triage_file_hash(sha256_hash, vt_key, mb_api_key):
    results = {}

    # VirusTotal hash lookup
    vt_resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
        headers={"x-apikey": vt_key}
    )
    if vt_resp.status_code == 200:
        attrs = vt_resp.json()["data"]["attributes"]
        results["vt_malicious"] = attrs["last_analysis_stats"]["malicious"]
        results["vt_names"] = attrs.get("names", [])
        results["vt_type"] = attrs.get("type_description")
        results["first_seen"] = attrs.get("first_submission_date")

    # MalwareBazaar lookup
    mb_resp = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": sha256_hash},
        headers={"API-KEY": mb_api_key}
    )
    if mb_resp.status_code == 200:
        mb_data = mb_resp.json()
        if mb_data.get("query_status") == "ok":
            results["mb_tags"] = mb_data["data"][0].get("tags", [])
            results["mb_signature"] = mb_data["data"][0].get("signature")

    results["verdict"] = "malicious" if results.get("vt_malicious", 0) > 5 else "unknown"
    return results
```

### CrowdStrike Falcon API - Endpoint Containment

```python
from falconpy import Hosts, RealTimeResponse, OAuth2

auth = OAuth2(client_id=CS_CLIENT_ID, client_secret=CS_CLIENT_SECRET)

def contain_host(hostname):
    hosts = Hosts(auth_object=auth)
    search_result = hosts.query_devices_by_filter(filter=f"hostname:'{hostname}'")
    if not search_result["body"]["resources"]:
        return {"error": f"Host {hostname} not found"}

    device_id = search_result["body"]["resources"][0]
    contain_result = hosts.perform_action(
        action_name="contain",
        body={
            "action_parameters": [{"name": "filter", "value": device_id}],
            "ids": [device_id]
        }
    )
    return {"device_id": device_id, "hostname": hostname,
            "contained": contain_result["status_code"] == 202}

def run_rtr_command(device_id, command):
    rtr = RealTimeResponse(auth_object=auth)
    session = rtr.init_session(body={
        "device_id": device_id,
        "origin": "SOAR-Automation",
        "queue_offline": True
    })
    session_id = session["body"]["resources"][0]["session_id"]
    return rtr.execute_admin_command(body={
        "base_command": "runscript",
        "command_string": command,
        "session_id": session_id,
        "id": 0
    })
```

### SentinelOne API - Isolation and Query

```python
S1_BASE = "https://company.sentinelone.net/web/api/v2.1"
S1_HEADERS = {"Authorization": f"ApiToken {S1_API_TOKEN}"}

def isolate_endpoint(hostname):
    agents = requests.get(f"{S1_BASE}/agents",
                          params={"computerName": hostname},
                          headers=S1_HEADERS).json()
    if not agents["data"]:
        return {"error": "Agent not found"}

    agent_id = agents["data"][0]["id"]
    result = requests.post(f"{S1_BASE}/agents/actions/disconnect",
                           json={"filter": {"ids": [agent_id]}},
                           headers=S1_HEADERS)
    return {"agent_id": agent_id, "isolated": result.status_code == 200}
```

### Carbon Black API - Process Investigation

```python
CB_BASE = "https://defense.conferdeploy.net"
CB_HEADERS = {"X-Auth-Token": f"{CB_API_KEY}/{CB_ORG_KEY}"}

def search_cb_processes(query, time_range="last_1_day"):
    body = {
        "query": query,
        "time_range": {"window": time_range},
        "rows": 100,
        "sort": [{"field": "device_timestamp", "order": "desc"}]
    }
    resp = requests.post(
        f"{CB_BASE}/api/investigate/v2/orgs/{CB_ORG_KEY}/processes/search_jobs",
        json=body, headers=CB_HEADERS
    )
    job_id = resp.json()["job_id"]
    for _ in range(10):
        time.sleep(3)
        result = requests.get(
            f"{CB_BASE}/api/investigate/v2/orgs/{CB_ORG_KEY}"
            f"/processes/search_jobs/{job_id}/results",
            headers=CB_HEADERS
        ).json()
        if result.get("contacted", 0) == result.get("completed", -1):
            return result.get("results", [])
    return []
```

---
## 8. Threat Intelligence Automation

### MISP Integration

MISP (Malware Information Sharing Platform) is the most widely used open-source threat intelligence platform. SOAR platforms integrate with MISP to pull threat events, create new events from incidents, and add attributes.

```python
from pymisp import PyMISP, MISPEvent

misp = PyMISP(url="https://misp.company.com", key=MISP_API_KEY, ssl=True)

def get_recent_misp_events(days=1, tags=None):
    search_params = {
        "last": f"{days}d",
        "published": True,
        "to_ids": True,
        "returnFormat": "json"
    }
    if tags:
        search_params["tags"] = tags
    return misp.search(controller="events", **search_params)

def create_misp_event_from_incident(incident_data):
    event = MISPEvent()
    event.info = f"SOAR Incident: {incident_data['name']}"
    event.distribution = 0       # Organization only
    event.threat_level_id = 2    # Medium
    event.analysis = 1           # Ongoing
    event.add_tag("source:soar-automation")
    event.add_tag("tlp:amber")

    for ip in incident_data.get("malicious_ips", []):
        event.add_attribute("ip-dst", ip, to_ids=True,
                            comment="C2 IP from SOAR IR playbook")
    for domain in incident_data.get("malicious_domains", []):
        event.add_attribute("domain", domain, to_ids=True,
                            comment="Malicious domain from playbook")
    for sha256 in incident_data.get("malicious_hashes", []):
        event.add_attribute("sha256", sha256, to_ids=True,
                            comment="Malicious file hash from sandbox")

    result = misp.add_event(event)
    return result["Event"]["uuid"]

def add_attribute_to_misp_event(event_uuid, attr_type, value, comment=""):
    misp.add_attribute(
        event_uuid,
        {"type": attr_type, "value": value, "to_ids": True, "comment": comment}
    )
```

### OpenCTI GraphQL API

```python
from pycti import OpenCTIApiClient

opencti = OpenCTIApiClient(url="https://opencti.company.com", token=OPENCTI_TOKEN)

def search_opencti_indicators(search_value):
    return opencti.indicator.list(
        filters=[{"key": "value", "values": [search_value], "operator": "eq"}],
        first=10
    )

def create_opencti_indicator(pattern, pattern_type, name, confidence=75):
    return opencti.indicator.create(
        name=name,
        description="Created by SOAR automation",
        pattern=pattern,           # e.g., "[ipv4-addr:value = '185.220.101.1']"
        pattern_type=pattern_type, # "stix", "sigma", "yara", "snort"
        x_opencti_score=confidence,
        x_opencti_main_observable_type="IPv4-Addr"
    )
```

### VirusTotal API v3 Automation

```python
import requests

VT_BASE = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY}

def vt_enrich_ip(ip_address):
    resp = requests.get(f"{VT_BASE}/ip_addresses/{ip_address}", headers=VT_HEADERS)
    if resp.status_code == 404:
        return {"verdict": "unknown", "ip": ip_address}
    data = resp.json()["data"]["attributes"]
    malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
    return {
        "ip": ip_address,
        "asn": data.get("asn"),
        "as_owner": data.get("as_owner"),
        "country": data.get("country"),
        "reputation": data.get("reputation", 0),
        "malicious_detections": malicious,
        "categories": data.get("categories", {}),
        "last_analysis_date": data.get("last_analysis_date"),
        "verdict": "malicious" if malicious > 3 else "clean"
    }

def vt_enrich_domain(domain):
    resp = requests.get(f"{VT_BASE}/domains/{domain}", headers=VT_HEADERS)
    data = resp.json()["data"]["attributes"]
    return {
        "domain": domain,
        "registrar": data.get("registrar"),
        "creation_date": data.get("creation_date"),
        "malicious_detections": data.get("last_analysis_stats", {}).get("malicious", 0),
        "categories": data.get("categories", {}),
        "whois": data.get("whois", "")[:500]
    }

def vt_livehunt_create_rule(yara_rule, rule_name, notification_email):
    return requests.post(
        f"{VT_BASE}/intelligence/hunting_rulesets",
        headers={**VT_HEADERS, "Content-Type": "application/json"},
        json={"data": {"type": "hunting_ruleset", "attributes": {
            "name": rule_name,
            "rules": yara_rule,
            "enabled": True,
            "limit": 100,
            "notification_emails": [notification_email]
        }}}
    ).json()
```

### Shodan API Integration

```python
import shodan

api = shodan.Shodan(SHODAN_API_KEY)

def shodan_enrich_ip(ip_address):
    try:
        host = api.host(ip_address)
        return {
            "ip": ip_address,
            "organization": host.get("org"),
            "isp": host.get("isp"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "open_ports": [item["port"] for item in host.get("data", [])],
            "hostnames": host.get("hostnames", []),
            "last_update": host.get("last_update"),
            "vulns": list(host.get("vulns", {}).keys()),
            "banners": [item.get("data", "")[:200] for item in host.get("data", [])[:3]]
        }
    except shodan.APIError as e:
        return {"error": str(e), "ip": ip_address}
```

### AbuseIPDB Check

```python
def abuseipdb_check(ip_address, api_key):
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
    )
    if resp.status_code != 200:
        return {"error": resp.text}
    data = resp.json()["data"]
    score = data["abuseConfidenceScore"]
    return {
        "abuse_confidence_score": score,
        "total_reports": data["totalReports"],
        "country_code": data["countryCode"],
        "isp": data["isp"],
        "is_tor": data.get("isTor", False),
        "verdict": "malicious" if score > 75 else
                   "suspicious" if score > 25 else "clean"
    }
```

### AlienVault OTX Integration

```python
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2(OTX_API_KEY)

def otx_enrich_ip(ip_address):
    try:
        details = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
        pulses = details.get("general", {}).get("pulse_info", {}).get("pulses", [])
        return {
            "ip": ip_address,
            "pulse_count": len(pulses),
            "tags": list({tag for p in pulses for tag in p.get("tags", [])}),
            "adversaries": [p["adversary"] for p in pulses if p.get("adversary")],
            "verdict": "malicious" if len(pulses) > 0 else "unknown"
        }
    except Exception as e:
        return {"error": str(e), "ip": ip_address}
```

### IOC Enrichment Pipeline - Parallel Multi-Source

```python
import concurrent.futures

def full_ioc_enrichment(ip_address):
    enrichment = {"ip": ip_address, "sources": {}}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(vt_enrich_ip, ip_address): "virustotal",
            executor.submit(shodan_enrich_ip, ip_address): "shodan",
            executor.submit(abuseipdb_check, ip_address, ABUSEIPDB_KEY): "abuseipdb",
            executor.submit(otx_enrich_ip, ip_address): "otx",
        }
        for future in concurrent.futures.as_completed(futures):
            source = futures[future]
            try:
                enrichment["sources"][source] = future.result()
            except Exception as e:
                enrichment["sources"][source] = {"error": str(e)}

    malicious_sources = sum(
        1 for s in enrichment["sources"].values()
        if s.get("verdict") == "malicious"
    )
    enrichment["aggregate_verdict"] = (
        "malicious" if malicious_sources >= 2 else
        "suspicious" if malicious_sources >= 1 else "clean"
    )
    enrichment["confidence"] = min(100, malicious_sources * 33)
    return enrichment
```

### Automated Blocking

```python
# Palo Alto Firewall: Block IP via Dynamic Address Group
def palo_alto_block_ip(panorama_ip, api_key, ip_address, dag_name="SOAR-Blocked-IPs"):
    payload = (f"<uid-message><type>update</type><payload>"
               f"<register><entry ip='{ip_address}'>"
               f"<tag><member>{dag_name}</member></tag>"
               f"</entry></register></payload></uid-message>")
    resp = requests.post(
        f"https://{panorama_ip}/api/",
        params={"type": "user-id", "key": api_key},
        data={"cmd": payload},
        verify=False
    )
    return resp.status_code == 200

# EDR Block Hash - CrowdStrike
def crowdstrike_block_hash(sha256_hash, comment="SOAR automated block"):
    from falconpy import IOC as CsIOC
    ioc_api = CsIOC(auth_object=auth)
    result = ioc_api.indicator_create_v1(body={
        "comment": comment,
        "indicators": [{
            "type": "sha256",
            "value": sha256_hash,
            "action": "prevent",
            "severity": "high",
            "platforms": ["windows", "mac", "linux"],
            "description": "SOAR automated block"
        }]
    })
    return result["status_code"] == 200

# AWS Security Group: Block IP via boto3
import boto3

def aws_block_ip_egress(security_group_id, ip_address, region="us-east-1"):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        ec2.authorize_security_group_egress(
            GroupId=security_group_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": f"{ip_address}/32",
                              "Description": "SOAR C2 egress block"}]
            }]
        )
        return True
    except Exception as e:
        return {"error": str(e)}
```

### STIX/TAXII with Python

```python
from taxii2client.v21 import Server, Collection

def get_taxii_indicators(taxii_url, collection_id, api_root_path,
                         user=None, pwd=None):
    server = Server(taxii_url, user=user, password=pwd)
    api_root_obj = next(
        r for r in server.api_roots if api_root_path in r.url
    )
    collection = Collection(
        f"{api_root_obj.url}collections/{collection_id}/",
        user=user, password=pwd
    )
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    bundle = collection.get_objects(added_after=since)
    return [obj for obj in bundle.get("objects", []) if obj["type"] == "indicator"]

def extract_ioc_from_stix_pattern(pattern):
    import re
    match = re.search(r"= '([^']+)'", pattern)
    return match.group(1) if match else None
```

### Indicator Deduplication and Scoring

```python
def deduplicate_and_score_indicators(raw_indicators):
    dedup = {}
    for ioc in raw_indicators:
        key = (ioc["type"], ioc["value"].lower().strip())
        if key not in dedup:
            dedup[key] = {"type": ioc["type"], "value": ioc["value"],
                          "sources": [], "scores": []}
        dedup[key]["sources"].append(ioc.get("source", "unknown"))
        dedup[key]["scores"].append(ioc.get("confidence", 50))

    results = []
    for (ioc_type, value), data in dedup.items():
        source_count = len(set(data["sources"]))
        avg_score = sum(data["scores"]) / len(data["scores"])
        composite = min(100, avg_score * (1 + 0.15 * (source_count - 1)))
        results.append({
            "type": ioc_type,
            "value": value,
            "sources": list(set(data["sources"])),
            "source_count": source_count,
            "composite_score": round(composite, 1),
            "verdict": "malicious" if composite > 75 else
                       "suspicious" if composite > 40 else "benign"
        })
    return sorted(results, key=lambda x: x["composite_score"], reverse=True)
```

---
## 9. IR Automation by Incident Type

### Ransomware Response Playbook

**Phase 1: Detect and Validate**
```python
def ransomware_detection_validation(alert_data):
    indicators = []
    ransomware_extensions = [
        ".locked", ".encrypted", ".crypted", ".ransom", ".pay2decrypt"
    ]
    if any(ext in alert_data.get("file_extensions_modified", [])
           for ext in ransomware_extensions):
        indicators.append("known_ransomware_extension")

    ransom_notes = [
        "README.txt", "HOW_TO_DECRYPT", "RECOVERY_INSTRUCTIONS",
        "YOUR_FILES_ARE_ENCRYPTED", "DECRYPT_MY_FILES"
    ]
    if any(note in alert_data.get("files_created", []) for note in ransom_notes):
        indicators.append("ransom_note_detected")

    vss_patterns = ["vssadmin delete shadows", "wmic shadowcopy delete",
                    "bcdedit /set recoveryenabled no"]
    if any(pattern in cmd.lower()
           for cmd in alert_data.get("commands_executed", [])
           for pattern in vss_patterns):
        indicators.append("vss_deletion_detected")

    confidence = len(indicators) / 3 * 100
    return {
        "indicators": indicators,
        "confidence": confidence,
        "verdict": "ransomware" if confidence >= 67 else "suspicious"
    }
```

**Phase 2: Isolate Affected Systems**
```python
def isolate_ransomware_affected_hosts(affected_hosts):
    results = []
    for host in affected_hosts:
        # CrowdStrike network containment
        cs_result = contain_host(host["hostname"])

        # Disable service accounts on affected host
        ad_accounts = get_service_accounts_on_host(host["hostname"])
        for account in ad_accounts:
            disable_ad_account(account["samAccountName"])

        # Firewall emergency block
        fw_result = palo_alto_block_ip(
            PA_PANORAMA, PA_API_KEY,
            host["ip_address"], dag_name="RANSOMWARE-QUARANTINE"
        )
        results.append({
            "hostname": host["hostname"],
            "cs_contained": cs_result.get("contained"),
            "fw_blocked": fw_result,
            "ad_accounts_disabled": len(ad_accounts)
        })
    return results
```

**Phase 3: Snapshot and Preserve Evidence**
```python
import boto3, time

def snapshot_ec2_instance(instance_id, region="us-east-1"):
    ec2 = boto3.client("ec2", region_name=region)
    instance = ec2.describe_instances(InstanceIds=[instance_id])
    volumes = [
        bdm["Ebs"]["VolumeId"]
        for r in instance["Reservations"]
        for i in r["Instances"]
        for bdm in i.get("BlockDeviceMappings", [])
        if "Ebs" in bdm
    ]
    snapshot_ids = []
    for volume_id in volumes:
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"SOAR-IR-{instance_id}-ransomware-{int(time.time())}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "Purpose", "Value": "IR-Evidence"},
                {"Key": "InstanceId", "Value": instance_id},
                {"Key": "CreatedBy", "Value": "SOAR-Automation"}
            ]}]
        )
        snapshot_ids.append(snapshot["SnapshotId"])
    return snapshot_ids
```

**Phase 4: Notify Stakeholders**
```python
def notify_ransomware_stakeholders(incident_id, affected_systems, ransom_family):
    # Slack notification
    requests.post(SLACK_WEBHOOK_URL, json={
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": (f"*RANSOMWARE INCIDENT DETECTED*
"
                      f"*Incident ID*: {incident_id}
"
                      f"*Ransomware Family*: {ransom_family}
"
                      f"*Systems Affected*: {len(affected_systems)}")}},
            {"type": "actions", "elements": [{"type": "button",
             "text": {"type": "plain_text", "text": "View Incident"},
             "url": f"https://soar.company.com/incidents/{incident_id}"}]}
        ]
    })
    # PagerDuty critical page
    requests.post("https://events.pagerduty.com/v2/enqueue", json={
        "routing_key": PD_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"Ransomware: {ransom_family} - {len(affected_systems)} systems",
            "severity": "critical",
            "source": "SOAR-Automation",
            "custom_details": {"incident_id": incident_id,
                               "affected_hosts": affected_systems}
        }
    })
```

### Business Email Compromise (BEC) Playbook

```python
def bec_response_playbook(incident_data, token):
    """
    BEC Workflow:
    1. Anomalous login detected (impossible travel, new country, new device)
    2. Disable the compromised account immediately
    3. Revoke all active sessions (OAuth tokens, refresh tokens)
    4. Search mailbox for forwarding rules and external forwards
    5. Search for financial request emails sent in last 48 hours
    6. Notify user, manager, and finance team
    """
    upn = incident_data["user_principal_name"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    graph_base = "https://graph.microsoft.com/v1.0"

    # Step 1: Disable account
    requests.patch(f"{graph_base}/users/{upn}",
                   json={"accountEnabled": False}, headers=headers)

    # Step 2: Revoke all sessions
    requests.post(f"{graph_base}/users/{upn}/revokeSignInSessions", headers=headers)

    # Step 3: Check for and remove malicious inbox rules
    rules_resp = requests.get(
        f"{graph_base}/users/{upn}/mailFolders/Inbox/messageRules",
        headers=headers
    )
    rules = rules_resp.json().get("value", [])
    suspicious = [r for r in rules
                  if r.get("actions", {}).get("forwardTo")
                  or r.get("actions", {}).get("delete")]
    for rule in suspicious:
        requests.delete(
            f"{graph_base}/users/{upn}/mailFolders/Inbox/messageRules/{rule['id']}",
            headers=headers
        )

    return {
        "account_disabled": True,
        "sessions_revoked": True,
        "malicious_rules_removed": len(suspicious)
    }
```

### DDoS Response Playbook

```python
def ddos_response_playbook(alert_data):
    target_ip = alert_data["target_ip"]
    traffic_gbps = alert_data.get("traffic_gbps", 0)
    attack_vectors = alert_data.get("attack_vectors", [])
    geo_blocks_applied = 0

    # Tier 1: CDN under-attack mode
    if traffic_gbps > 10:
        cloudflare_enable_under_attack_mode(target_ip)

    # Tier 2: Geographic blocks for volumetric attacks
    if "UDP_FLOOD" in attack_vectors or "AMPLIFICATION" in attack_vectors:
        top_countries = get_top_attack_source_countries(alert_data.get("flow_data", []))
        for country in top_countries[:3]:
            apply_geo_block(country, target_ip)
        geo_blocks_applied = min(3, len(top_countries))

    # Tier 3: Rate limiting on edge
    apply_edge_rate_limit(target_ip, max_rps=1000)

    # Tier 4: ISP null route for massive attacks
    isp_escalated = traffic_gbps > 100
    if isp_escalated:
        notify_isp_for_upstream_null_route(target_ip)

    return {
        "cdn_protection_enabled": traffic_gbps > 10,
        "geo_blocks_applied": geo_blocks_applied,
        "rate_limit_applied": True,
        "isp_escalated": isp_escalated
    }
```

### Insider Threat Response Playbook

```python
def insider_threat_playbook(incident_data, token):
    """
    IMPORTANT: Do not alert the subject. Preserve evidence covertly.
    1. Apply legal hold on email and cloud storage
    2. Silently restrict external sharing
    3. Collect forensic artifacts from audit logs
    4. Notify CISO, HR, and Legal via secure channel only
    """
    employee = incident_data["employee"]
    risk_score = incident_data.get("dlp_risk_score", 0)

    # Apply legal hold (silent, no notification to user)
    apply_legal_hold(employee["email"],
                     case_name=f"IT-INVESTIGATION-{incident_data['id']}")

    # Silent restrictions for high-risk subjects
    if risk_score > 80:
        restrict_sharepoint_external_sharing(employee["email"])
        restrict_email_external_forwarding(employee["email"])

    # Collect 30-day audit trail
    forensic_collection = {
        "file_access": get_audit_log(employee["email"], "FileAccessed", days=30),
        "external_shares": get_audit_log(employee["email"], "SharingSet", days=30),
        "cloud_uploads": get_cloud_activity(employee["email"], days=30),
        "usb_events": get_dlp_events(employee["email"], "USB", days=30)
    }

    evidence_id = create_evidence_package(
        forensic_collection, employee, incident_data["id"]
    )

    # Notify on need-to-know basis only
    notify_leadership_secure(
        recipients=["ciso@company.com", "hr-legal@company.com"],
        subject=f"[CONFIDENTIAL] Insider Investigation - {employee['employee_id']}",
        incident_id=incident_data["id"],
        evidence_id=evidence_id
    )

    return {
        "evidence_preserved": True,
        "access_restricted": risk_score > 80,
        "evidence_id": evidence_id
    }
```

### Containment Automation - Multi-Platform

```python
# Fortinet FortiGate REST API: Block IP
def fortinet_block_ip(fortigate_host, api_key, ip_address):
    headers = {"Authorization": f"Bearer {api_key}"}
    addr_name = f"SOAR-BLOCK-{ip_address.replace('.', '-')}"
    requests.post(
        f"https://{fortigate_host}/api/v2/cmdb/firewall/address",
        json={"name": addr_name, "type": "ipmask",
              "subnet": f"{ip_address}/255.255.255.255",
              "comment": "SOAR automated block"},
        headers=headers, verify=False
    )
    requests.put(
        f"https://{fortigate_host}/api/v2/cmdb/firewall/addrgrp/SOAR-BLOCKED-IPS",
        json={"member": [{"name": addr_name}]},
        headers=headers, verify=False
    )

# Azure NSG: Block IP via ARM API
def azure_block_ip_nsg(subscription_id, rg, nsg_name, ip_address, token):
    from datetime import datetime
    rule_name = f"SOAR-BLOCK-{ip_address.replace('.', '-')}"
    url = (f"https://management.azure.com/subscriptions/{subscription_id}"
           f"/resourceGroups/{rg}/providers/Microsoft.Network"
           f"/networkSecurityGroups/{nsg_name}/securityRules/{rule_name}"
           f"?api-version=2023-04-01")
    requests.put(url, json={"properties": {
        "priority": 100,
        "protocol": "*",
        "access": "Deny",
        "direction": "Inbound",
        "sourceAddressPrefix": ip_address,
        "sourcePortRange": "*",
        "destinationAddressPrefix": "*",
        "destinationPortRange": "*",
        "description": f"SOAR block - {datetime.utcnow().isoformat()}"
    }}, headers={"Authorization": f"Bearer {token}"})

# Active Directory: Disable account and reset password
def disable_ad_account_powershell(samaccountname, run_remote_ps):
    cmds = [
        f"Disable-ADAccount -Identity '{samaccountname}' -Confirm:$false",
        (f"Set-ADAccountPassword -Identity '{samaccountname}' "
         f"-Reset -NewPassword (ConvertTo-SecureString -AsPlainText "
         f"'SOAR-Temp-{samaccountname[:4]}!9#' -Force)")
    ]
    results = [run_remote_ps(cmd) for cmd in cmds]
    return {"account_disabled": True, "password_reset": True, "ps_results": results}
```

---
## 10. SOAR Metrics & Operations

### Key Performance Indicators (KPIs)

| KPI | Definition | Calculation | Target |
|---|---|---|---|
| **Automation Rate %** | % of alerts handled without analyst intervention | Auto Closures / Total Alerts x 100 | > 70% |
| **MTTR Reduction %** | Improvement in mean time to respond vs baseline | (Baseline - Current) / Baseline x 100 | > 50% |
| **Alert-to-Ticket Ratio** | Ratio of raw alerts to actionable incidents | Total Alerts / Incidents Created | < 10:1 |
| **False Positive Rate %** | % of automated actions reversed as incorrect | Reversed / Total Automated x 100 | < 3% |
| **Playbook p50 Exec Time** | Median playbook wall-clock time | 50th percentile of execution duration | < 2 min |
| **Playbook p95 Exec Time** | 95th-percentile execution time | 95th percentile of execution duration | < 10 min |
| **Analyst Hours Saved** | Estimated analyst time saved by automation | (Avg Manual x Vol) - (SOAR Time x Vol) | Maximize |
| **Playbook Success Rate** | % of executions completing without error | Successful / Total x 100 | > 95% |
| **Coverage %** | % of alert types with active playbook | Types with Playbook / Total Types x 100 | > 80% tier-1 |
| **SLA Compliance %** | % of incidents meeting SLA targets | SLA Met / Total Incidents x 100 | > 98% |

### SOC Efficiency Dashboard

```python
import statistics

def collect_soar_metrics(soar_client, period_days=30):
    """Aggregate SOAR operational metrics for dashboard reporting"""

    total_alerts = soar_client.count_containers(
        filter=f"create_time > now-{period_days}d"
    )
    auto_closed = soar_client.count_containers(
        filter=(f"create_time > now-{period_days}d "
                f"AND status=closed AND close_reason=automated")
    )
    automation_rate = auto_closed / total_alerts * 100 if total_alerts else 0

    exec_times = soar_client.get_playbook_execution_times(days=period_days)
    p50 = statistics.median(exec_times) if exec_times else 0
    p95 = sorted(exec_times)[int(len(exec_times) * 0.95)] if exec_times else 0

    total_runs = soar_client.count_playbook_runs(days=period_days)
    failed_runs = soar_client.count_playbook_runs(days=period_days, status="failed")
    success_rate = (total_runs - failed_runs) / total_runs * 100 if total_runs else 0

    closed_incidents = soar_client.get_closed_incidents(days=period_days)
    mttrs = [(i["close_time"] - i["create_time"]) / 60 for i in closed_incidents]
    current_mttr = sum(mttrs) / len(mttrs) if mttrs else 0

    return {
        "period_days": period_days,
        "total_alerts": total_alerts,
        "automation_rate_pct": round(automation_rate, 1),
        "p50_exec_time_sec": round(p50, 1),
        "p95_exec_time_sec": round(p95, 1),
        "playbook_success_rate_pct": round(success_rate, 1),
        "avg_mttr_minutes": round(current_mttr, 1)
    }
```

### Playbook Effectiveness Scoring

```python
def score_playbook_effectiveness(playbook_id, metrics_db):
    m = metrics_db.get_playbook_metrics(playbook_id, days=90)

    # Score each dimension 0-100
    execution_score = 100 - m.get("failure_rate_pct", 0)
    speed_score = max(0, 100 - (m.get("p95_exec_seconds", 0) / 6))
    fp_score = max(0, 100 - (m.get("false_positive_rate_pct", 0) * 5))
    total_types = m.get("total_alert_types", 1)
    coverage_score = min(100, m.get("alert_types_handled", 0) / total_types * 100)
    adoption_score = max(0, 100 - m.get("analyst_override_rate_pct", 0))

    weights = {
        "execution": 0.25,
        "speed": 0.20,
        "false_positive": 0.30,
        "coverage": 0.15,
        "adoption": 0.10
    }
    composite = (
        execution_score * weights["execution"] +
        speed_score * weights["speed"] +
        fp_score * weights["false_positive"] +
        coverage_score * weights["coverage"] +
        adoption_score * weights["adoption"]
    )

    return {
        "playbook_id": playbook_id,
        "composite_score": round(composite, 1),
        "grade": ("A" if composite >= 90 else "B" if composite >= 75
                  else "C" if composite >= 60 else "D"),
        "dimensions": {
            "execution": round(execution_score, 1),
            "speed": round(speed_score, 1),
            "false_positive": round(fp_score, 1),
            "coverage": round(coverage_score, 1),
            "adoption": round(adoption_score, 1)
        },
        "recommended_action": (
            "IMPROVE: High false positive rate" if fp_score < 60 else
            "OPTIMIZE: Slow execution at p95" if speed_score < 60 else
            "INVESTIGATE: High failure rate" if execution_score < 60 else
            "MAINTAIN: Performing well"
        )
    }
```

### Capacity Planning

| Parameter | Warning | Critical | Action |
|---|---|---|---|
| **Concurrent Executions** | > 80% of license limit | > 95% | Scale out cluster nodes |
| **Queue Depth** | > 500 queued runs | > 2000 queued runs | Add execution workers |
| **API Rate Limits** | > 70% of API quota | > 90% of API quota | Implement request queuing |
| **Action Failure Rate** | > 5% per app | > 15% per app | Investigate integration health |
| **Database Size Growth** | > 10 GB/month | > 50 GB/month | Archive old containers |
| **API Response Time p95** | > 5 sec | > 15 sec | Review infrastructure sizing |

```python
def check_soar_health(soar_metrics):
    alerts = []
    if soar_metrics.get("queue_depth", 0) > 500:
        alerts.append({
            "severity": "warning",
            "message": f"High queue depth: {soar_metrics['queue_depth']} pending executions",
            "action": "Review slow playbooks; add execution workers"
        })
    for app, rate in soar_metrics.get("app_failure_rates", {}).items():
        if rate > 10:
            alerts.append({
                "severity": "critical",
                "message": f"{app} failure rate {rate}% - likely rate-limited",
                "action": "Implement exponential backoff; check API quota and credentials"
            })
    return alerts
```

### Maintenance Procedures

**App/Integration Updates**:
- Test updated app versions in staging SOAR instance before production deployment
- Review release notes for breaking API changes with every version update
- Rotate authentication credentials when API keys expire or are cycled
- Run full regression playbook tests after every app update

**Quarterly Playbook Audit Checklist**:
```
For each production playbook:
1. Verify all integrated apps are functional and at current versions
2. Review false positive reports from last 90 days
3. Identify alert type coverage gaps (new detection rules without playbooks)
4. Validate approval gate logic aligns with current response policy
5. Review analyst override logs (high override rate indicates logic needs revision)
6. Confirm incident type field mappings still match source alert formats
7. Test error handling paths with synthetic failure injection
8. Verify secrets and API credentials are not expiring within 30 days
```

**Secrets Rotation Schedule**:
```python
from datetime import datetime

SECRETS_ROTATION_DAYS = {
    "soar_api_keys": 90,
    "integration_api_keys": 180,
    "service_account_passwords": 90,
    "oauth_client_secrets": 365,
    "ssl_certificates": 365
}

def check_secret_expiry(vault_client, secret_path, rotation_days):
    meta = vault_client.secrets.kv.v2.read_secret_metadata(path=secret_path)
    last_rotated = meta["data"]["updated_time"]
    days_since = (
        datetime.utcnow() - datetime.fromisoformat(last_rotated.rstrip("Z"))
    ).days
    return {
        "needs_rotation": days_since > rotation_days,
        "days_since_rotation": days_since,
        "days_until_expiry": max(0, rotation_days - days_since)
    }
```

### MITRE ATT&CK Aligned Playbook Catalog

Map playbooks to MITRE ATT&CK techniques to ensure comprehensive coverage and identify gaps:

| ATT&CK Technique | Tactic | SOAR Playbook | Coverage |
|---|---|---|---|
| T1566 - Phishing | Initial Access | Phishing Triage v2 | Full |
| T1078 - Valid Accounts | Initial Access, Persistence | BEC Response | Full |
| T1486 - Data Encrypted for Impact | Impact | Ransomware Response | Full |
| T1059 - Command & Scripting Interpreter | Execution | Suspicious Script Execution | Partial |
| T1071 - Application Layer Protocol (C2) | Command & Control | C2 Beacon Triage | Partial |
| T1048 - Exfiltration Over Alt Protocol | Exfiltration | DLP Alert Response | Partial |
| T1110 - Brute Force | Credential Access | Auth Anomaly Response | Full |
| T1136 - Create Account | Persistence | Rogue Account Detection | Partial |
| T1098 - Account Manipulation | Privilege Escalation | Privilege Escalation Response | Partial |
| T1190 - Exploit Public-Facing Application | Initial Access | Vulnerability Exploit Alert | Limited |
| T1021 - Remote Services | Lateral Movement | Lateral Movement Detection | Partial |
| T1003 - OS Credential Dumping | Credential Access | Credential Theft Response | Partial |

### SOAR Vendor Evaluation RFP Template

**Section 1 - Functional Requirements**
- Integration catalog size and coverage for current tool stack (require list of 20 key tools)
- Custom integration development framework (SDK language, documentation quality, community)
- Playbook building interface (visual canvas, code-based, or hybrid approach)
- Case management features (SLA enforcement, approval workflows, full audit trail)
- Threat intelligence management (built-in TIP, indicator scoring, expiry management)

**Section 2 - Technical Requirements**
- Deployment models supported (on-prem, cloud SaaS, hybrid, air-gapped)
- High availability and clustering architecture and documented failover behavior
- API-first design (full REST API coverage for all platform functions)
- Data residency options (US, EU, multi-region with data sovereignty controls)
- RBAC granularity (field-level permissions, role-based playbook access controls)

**Section 3 - Performance and Scale**
- Maximum concurrent playbook executions (licensed limit and architectural ceiling)
- Alert ingestion rate (events per second at sustained load)
- Playbook execution throughput (runs per hour under load)
- API rate limits per integration (document per-app limits)
- Data retention limits and archival/export options

**Section 4 - Operational Requirements**
- Playbook CI/CD and version control support (Git integration, export formats)
- Dedicated testing and staging environment support
- Upgrade process documentation (downtime window, rollback procedures)
- Monitoring and observability (built-in dashboards, Prometheus/Grafana export support)
- Support SLA tiers and escalation paths with named contacts

**Section 5 - Commercial**
- Licensing model (per user, per alert volume, per execution, flat fee, hybrid)
- Integration and app licensing (included vs separately licensed add-ons)
- Professional services scope and cost for initial deployment and onboarding
- Reference customers in same industry vertical willing to provide reference calls

### Community Resources

| Resource | Description |
|---|---|
| **Splunk SOAR Apps (github.com/splunk-soar-connectors)** | 500+ open-source SOAR app connectors with Python source |
| **XSOAR Marketplace (marketplace.xsoar.pan.dev)** | 1000+ content packs, integrations, playbooks, scripts |
| **Tines Community Library (library.tines.com)** | Pre-built Tines stories for common security use cases |
| **Sigma Rules (github.com/SigmaHQ/sigma)** | Detection rules convertible to SOAR alert triggers |
| **MITRE ATT&CK Navigator** | Coverage mapping tool for playbook-to-technique alignment |
| **Awesome-SOAR (github.com/correlatedsecurity/Awesome-SOAR)** | Curated SOAR resources, tools, blog posts, vendors |
| **CISA IR Playbooks (cisa.gov)** | Federal government incident response playbook templates |
| **OpenCTI Platform (github.com/OpenCTI-Platform/opencti)** | Open-source CTI platform with SOAR integration APIs |
| **The DFIR Report (thedfirreport.com)** | Real-world IR case studies with detailed TTPs for tuning |
| **FIRST CSIRT Services Framework (first.org)** | IR process frameworks and service category definitions |
| **OASIS CTI TC (oasis-open.org)** | STIX/TAXII standards documentation and working groups |

---

*Reference Library Version: 1.0.0 | Last Updated: 2026-05-06 | Maintained by TeamStarWolf Security Engineering*
*Classification: INTERNAL USE - SOC Engineering and Incident Response Teams*
