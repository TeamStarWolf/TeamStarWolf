# Vendor Tool Pages

Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.

> One page per platform in a representative enterprise security stack: what the product does, where it fits in vulnerability mitigation, how to confirm it is deployed and producing telemetry, and where its official documentation and repositories are. The pages describe products; they do not endorse them.

## What is here

| Area | Pages |
|---|---|
| Endpoint and EDR | [Tanium](/tools/tanium.md), [Microsoft Defender for Endpoint and Vulnerability Management](/tools/microsoft-defender-endpoint.md), [CrowdStrike Falcon](/tools/crowdstrike-falcon.md) |
| Web application firewall and edge | [Akamai App and API Protector](/tools/akamai-app-api-protector.md), [AWS WAF](/tools/aws-waf.md), [Citrix NetScaler WAF](/tools/netscaler-waf.md) |
| Network and secure access | [Check Point Quantum and Infinity](/tools/check-point.md), [Zscaler Zero Trust Exchange](/tools/zscaler.md) |
| Cloud | [AWS native security](/tools/aws-native-security.md), [Microsoft Defender for Cloud](/tools/microsoft-defender-for-cloud.md), [Wiz](/tools/wiz.md), [Chainguard](/tools/chainguard.md) |
| Vulnerability management and application security | [Tenable](/tools/tenable.md), [Zafran Security](/tools/zafran.md), [Invicti](/tools/invicti.md), [Snyk](/tools/snyk.md), [HackerOne](/tools/hackerone.md) |
| SIEM | [Splunk Enterprise Security](/tools/splunk.md) |
| Identity and privileged access | [Microsoft Entra ID](/tools/entra-id.md), [Cisco Duo](/tools/cisco-duo.md), [CyberArk](/tools/cyberark.md) |

Each page follows the same outline: capabilities and architecture, the vulnerability-mitigation role, validation and telemetry (log sources, a control-presence check, example queries), documentation and repositories, and the current state of the product. [Security Tool Documentation](/SECURITY_TOOL_DOCUMENTATION.md) is the index of official documentation, API references, and GitHub organizations for the same platforms.

## How it is generated

No script generates these pages; they are maintained by hand. They were drafted with an AI assistant from web-assisted research into vendor documentation (vendor state as of 2025 and 2026); some deep links were not re-checked against the live vendor sites at the time. The Link Check workflow tests every outbound link a change adds and scans all of them weekly.

## How to use it

- Use a page to orient yourself on a product and to find its primary documentation; confirm product names, editions, licensing, and API details on the vendor's current site before you rely on them.
- The example queries in "Validation and telemetry" show the shape of a check. Field and table names change between product versions, so test each one against your own tenant.
- For how these products map to NIST SP 800-53 controls and ATT&CK coverage, see [Controls Mapping](/CONTROLS_MAPPING.md) and [scores/](/scores/README.md); those mappings are this library's editorial assessments.
- For in-depth integration studies checked against official documentation, see [Tools Research](/tools-research/README.md).
