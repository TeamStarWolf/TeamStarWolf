# 🧭 Guides — Step-by-Step How-To's

> **The references tell you *what*; the guides tell you *how*.** Each guide is a self-contained, start-to-finish procedure with prerequisites, numbered steps, checkpoints you can verify, and links back into the library's reference docs for the depth behind each move. Pick the task you need to do today.

Every guide follows the same shape: a promise and a "who this is for" up top, an **at-a-glance** table (time, difficulty, what you need, what you'll produce), a **before you start** checklist, numbered steps with a **Checkpoint** after each, a **what good looks like** section, and a **go deeper** list of references. Commands are verified against current official documentation — still confirm them against the live docs before production use.

**Related:** [How to Use This Library](HOW_TO_USE_THIS_LIBRARY.md) · [Reference Index](../INDEX.md) · [Discipline Paths](../disciplines/README.md)

---

## Start here

| Guide | You'll walk away with |
|---|---|
| [How to Use This Library](HOW_TO_USE_THIS_LIBRARY.md) | A mental map of the whole library and three worked entry paths (student, SOC analyst, security lead) |

---

## Vulnerability & exposure management

| Guide | You'll walk away with |
|---|---|
| [Triage a New CVE in 30 Minutes](TRIAGE_A_CVE.md) | A defensible Track / Attend / Act decision on a fresh CVE, with an SLA, using KEV + EPSS + SSVC |
| [Start a Vulnerability Management Program (First 90 Days)](START_A_VULN_MGMT_PROGRAM.md) | A running VM program: inventory, authenticated scanning, KEV-first SLAs, and a leadership metrics pack |
| [Run an ATT&CK Coverage Gap Assessment](RUN_A_COVERAGE_GAP_ASSESSMENT.md) | A ranked, owned list of detection/mitigation gaps against a real threat model |

## Detection & hunting

| Guide | You'll walk away with |
|---|---|
| [Build and Deploy Your First Detection](BUILD_YOUR_FIRST_DETECTION.md) | A tuned Sigma rule live in your SIEM, from telemetry choice to promotion |
| [Onboard a Log Source the Right Way](ONBOARD_A_LOG_SOURCE.md) | A log source that actually powers detections — use-case-first, normalized, retention-planned |
| [Hunt for Living-off-the-Land Activity](HUNT_FOR_LOTL_ACTIVITY.md) | A hypothesis-driven hunt for abused built-in tools, converted into detections |

## Incident response & resilience

| Guide | You'll walk away with |
|---|---|
| [Respond to a Ransomware Incident](RESPOND_TO_RANSOMWARE.md) | The first 24–72 hours as a numbered procedure, keyed to the CISA #StopRansomware Guide |
| [Run a Ransomware Tabletop Exercise](RUN_A_RANSOMWARE_TABLETOP.md) | A facilitated CISA CTEP tabletop and a corrective-action plan with owners and dates |
| [Investigate a Phishing Report](INVESTIGATE_A_PHISHING_EMAIL.md) | A verdict and containment action on a reported email, from headers to purge |

## Hardening & assessment

| Guide | You'll walk away with |
|---|---|
| [Harden a Windows Baseline](HARDEN_A_WINDOWS_BASELINE.md) | A hardened Windows baseline via CIS/Microsoft policy, ASR, and audited command-line logging |
| [Harden a macOS Fleet with mSCP](HARDEN_A_MACOS_FLEET.md) | A compliant macOS fleet built with the NIST macOS Security Compliance Project |
| [Assess Your M365 Tenant with ScubaGear](ASSESS_M365_WITH_SCUBAGEAR.md) | A scored M365 tenant against CISA SCuBA baselines with a safe remediation plan |

## Offense-informed defense

| Guide | You'll walk away with |
|---|---|
| [Run Your First Purple-Team Exercise](RUN_A_PURPLE_TEAM_EXERCISE.md) | Validated (or disproven) detection coverage for five techniques, and a detection backlog |
| [Threat Model an Application](THREAT_MODEL_AN_APPLICATION.md) | A STRIDE threat model with ranked, mitigated findings in your backlog |

## Learning & lab

| Guide | You'll walk away with |
|---|---|
| [Build a Detection Home Lab](BUILD_A_DETECTION_HOMELAB.md) | A weekend detection lab: victim VM, SIEM, and safe technique validation |

---

*Guides are procedures, not policy. Verify every command against current official documentation before running it in production, and never test techniques against systems you are not authorized to touch.*
