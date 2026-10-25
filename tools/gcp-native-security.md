# GCP Native Security (Security Command Center, Cloud Armor, VPC Service Controls)

*Google Cloud · Native posture, threat detection, vulnerability findings, perimeter, and edge controls*

Google Cloud splits the same jobs AWS and Azure split. Security Command Center (SCC) is the organization-level finding store. Cloud Audit Logs are the control-plane record. Organization Policy is the preventive guardrail. VPC Service Controls are the API perimeter. Cloud Armor is the edge WAF and DDoS control. VM Manager and Artifact Analysis feed vulnerability findings. Google Security Operations (formerly Chronicle) is the SIEM, and it is a separate product from SCC. Confirm tier names on the product page before you buy: Google has sold SCC as a free tier and as paid tiers (Premium, and an Enterprise tier that adds Mandiant intelligence and a closer tie to Security Operations). Detector coverage is not the same in every tier.

## Capabilities and architecture

**What each service is for**

| Service | Job | What it is not |
|---|---|---|
| Security Command Center | Assets, Security Health Analytics misconfigurations, threat detectors, vulnerability and compliance findings, attack exposure on paid tiers | A SIEM with a long hot store |
| Event Threat Detection | Rules over Cloud Logging and other telemetry (compromised credentials, cryptomining, malware on a VM) | A packet broker |
| Container Threat Detection and VM Threat Detection | Runtime signals on GKE and Compute Engine, on the tiers that include them | A host EDR you deploy yourself |
| Web Security Scanner | Managed scans of App Engine, GKE, and Compute Engine web apps for XSS, outdated libraries, and similar classes | An authenticated application-penetration test |
| VM Manager (OS Config API) | OS inventory and patch jobs on Compute Engine | A scanner of images you have not inventoried |
| Artifact Analysis | On-push vulnerability scanning of container images when the Container Scanning API is on | A runtime admission decision. That is Binary Authorization. |
| Organization Policy | Constraints that deny classes of configuration (external IPs, service-account keys, public buckets) | An IAM allow |
| VPC Service Controls | A perimeter: which projects may call which Google APIs, independent of IAM | A VPC firewall |
| Cloud Armor | WAF policies and DDoS controls on an external Application Load Balancer | An IAM control |
| Cloud KMS and Secret Manager | Keys and secrets. CMEK is a choice per service, not a default on every product. | A substitute for IAM |
| Binary Authorization | Admit a container image to GKE or Cloud Run only with an attestor signature | An image scanner |
| Sensitive Data Protection | Discovery and de-identification of built-in infoTypes in storage, BigQuery, and streams | A full copy of every table unless the job is configured that way |
| Identity-Aware Proxy | An identity check in front of a backend, including TCP forwarding for SSH and RDP | A site-to-site VPN |
| Google Security Operations | SIEM and SOAR. Ingest SCC findings and Cloud Audit Logs. | Included with every SCC tier |

**How it is wired.** Turn SCC on at the organization. Findings live in the SCC API (`organizations/ORG/sources/SOURCE`). Export to Pub/Sub if a ticket system or Google Security Operations must see them. Cloud Audit Logs Admin Activity is always on. Data Access logs are off until you enable them, and they are the log that records object reads. Organization Policy constraints inherit from organization to folder to project unless a child overrides them. VPC Service Controls perimeters are explicit lists of projects and services. A valid IAM grant does not cross a perimeter unless an ingress or egress rule allows the call.

**Constraints worth setting before the first workload**

- `constraints/iam.disableServiceAccountKeyCreation` so workloads use attached service accounts, not downloaded keys
- `constraints/storage.publicAccessPrevention` so buckets cannot be made public
- `constraints/compute.vmExternalIpAccess` so VMs do not grow public IPs by default
- `constraints/compute.skipDefaultNetworkCreation` so new projects do not get the default network
- `constraints/iam.allowedPolicyMemberDomains` so IAM grants stay inside your Cloud Identity domains

**What you pay for.** SCC's free tier is a subset of Security Health Analytics and limited Web Security Scanner. Threat detectors, vulnerability findings, and attack exposure sit on paid tiers. Cloud Armor WAF rules and its DDoS SKU are priced apart from SCC. Data Access audit logs are a logging bill. VM Manager has its own fee once you leave the free inventory operations. Read the current pricing page. Do not assume Premium and Enterprise include the same detectors they included last year.

## Vulnerability-mitigation role

GCP's native vulnerability findings are inventory-driven. VM Manager records packages on a Compute Engine instance. Artifact Analysis records packages in a container image. SCC joins those to a CVE and, on the tiers that include it, to whether the asset is exposed. That is a different input from a network scanner, which only sees an open port.

Prioritize a finding that is internet-reachable, in a project that holds sensitive data, or on a service account that can leave the VPC Service Controls perimeter. A critical CVE on a private test VM with no route out is a lower mobilization target than a medium CVE on the public load balancer's backend.

Mobilization is a patch job in VM Manager, a rebuilt image that passes Binary Authorization, or an Organization Policy that stops the class of misconfiguration from being created again. Security Health Analytics going quiet is the close of a misconfiguration. A vulnerability finding closing is the close of a CVE. Neither is proof that detection would have fired. That proof is an Event Threat Detection or VM Threat Detection finding during a controlled test, which is the validation stage in the [CTEM reference](/CTEM_REFERENCE.md).

**In a critical CVE.** List SCC vulnerability findings for that CVE at the organization. Split them by exposure. Block the path with Cloud Armor, an ingress firewall rule, or by removing the external IP while the image is rebuilt. Require the new digest in Binary Authorization. Re-query findings until the vulnerable package version is gone. Preserve the Admin Activity log of who changed IAM or the firewall during the window.

## Validation and telemetry

**Logs and finding stores**

- Admin Activity audit logs: always on. `SetIamPolicy`, firewall changes, org-policy changes.
- Data Access audit logs: off by default. Enable them on Cloud Storage, BigQuery, and Secret Manager if you need to know who read data.
- SCC findings: source, category, state (`ACTIVE` or `INACTIVE`), severity, and the resource name.
- VPC Flow Logs: sampled, and off until you enable them on a subnet.
- Cloud Armor: request logs on the load balancer backend, including the WAF rule that matched. They are not SCC findings unless you build that export.

**Presence checks**

APIs that must be enabled in the security project and, for scanning, in workload projects:

```bash
gcloud services list --enabled --project=PROJECT_ID \
  --filter="config.name:(securitycenter.googleapis.com OR containeranalysis.googleapis.com OR containerscanning.googleapis.com OR osconfig.googleapis.com OR binaryauthorization.googleapis.com)"
```

A service-account-key constraint at the organization:

```bash
gcloud org-policies describe constraints/iam.disableServiceAccountKeyCreation --organization=ORG_ID
```

SCC findings (replace the organization and confirm the source id in your tenant; the filter grammar is the SCC API filter):

```bash
gcloud scc findings list organizations/ORG_ID --location=global \
  --filter='state="ACTIVE" AND severity="CRITICAL"'
```

OS inventory for one VM, which vulnerability findings depend on:

```bash
gcloud compute instances os-inventory describe INSTANCE_NAME --zone=ZONE
```

An IAM change in the last day:

```bash
gcloud logging read 'logName:"clouactivity_log" AND protoPayload.methodName="SetIamPolicy"' \
  --project=PROJECT_ID --limit=20 --freshness=1d
```

**What "working" means**

- Configured: the API is enabled, the org policy is enforced (not dry-run), SCC shows the source, Data Access logs are enabled on the resources you claimed to watch.
- Effective for a vulnerability: the finding state moves off `ACTIVE` after the package version changes, and OS inventory or the image digest agrees.
- Effective for a guardrail: an API call that should fail returns a constraint violation, and that denial is in the audit log. A policy in dry-run does not count.
- Effective for detection: Event Threat Detection emits a finding for a technique you staged in a lab project. An empty finding list on a quiet project does not prove the detector is subscribed.

`gcloud scc findings list` syntax has changed across gcloud versions. If the command rejects `--location` or `--filter`, use the example on the current [list-findings](https://cloud.google.com/security-command-center/docs/how-to-api-list-findings) page rather than the line above.

**Logging gaps that look like a quiet organization**

- Admin Activity is always on. Data Access is off until you enable it, and it is the log of object reads. A bucket policy review that only reads Admin Activity cannot see who downloaded the object.
- VPC Flow Logs are sampled and off until you enable them on the subnet. Cloud Armor matches live on the load balancer request log, not in SCC, unless you export them.
- An Organization Policy that shows only a dry-run spec does not deny the call. The enforced spec is the one that returns a constraint violation. Keep that denial from the audit log with the finding you close.
- SCC at the organization does not scan a project whose Container Scanning API or OS Config API is disabled. The empty finding list is a coverage gap. The presence check above is how you show the API state.
- Web Security Scanner is an unauthenticated managed scan of a URL you configure. It is not an authenticated application test, and a custom scan does not exist until someone creates it.

## Differentiators

- Organization Policy is preventive and inherited. A workload project does not get a public IP, a service-account key, or a public bucket when the constraint is enforced above it.
- VPC Service Controls are independent of IAM. A valid grant does not cross the perimeter unless an ingress or egress rule allows the call.
- Artifact Analysis records the image. Binary Authorization is the admission decision. Scanning without admission still lets the cluster run the digest you just flagged.
- SCC is the finding store. Google Security Operations is the SIEM, and it is a separate product. Export findings to Pub/Sub if that SIEM, or a ticket system, must see them.

## Limitations

- Detector coverage follows the tier you bought. The free tier is a subset of Security Health Analytics and a limited Web Security Scanner. Threat detectors, vulnerability findings, and attack exposure are paid. Tier names (Premium, Enterprise, and any Mandiant bundle) move. Read the pricing page before you write a detector into a runbook.
- CMEK is a per-service choice. Turning on Cloud KMS does not encrypt every product.
- VM Manager inventory is the package list vulnerability findings depend on. An instance with the OS Config agent stopped, or the API disabled, drops out of that list.
- Sensitive Data Protection inspects what the job was pointed at. It does not, by itself, copy or classify every table in the organization.
- IAP TCP forwarding replaces a public SSH port. It does not replace a VPN for site-to-site traffic.

## A reading against the frameworks

This mapping is the page's own reading, for routing a control to a catalog. It is not a Google attestation.

| Catalog | Where these services sit |
|---|---|
| NIST CSF 2.0 | Identify: Cloud Asset Inventory and SCC assets. Protect: Organization Policy, VPC Service Controls, Binary Authorization. Detect: Event Threat Detection and the runtime detectors on the tier you bought. Respond: the Pub/Sub export into the ticket system or Google Security Operations. |
| CIS Controls v8 | 1 and 2 inventory, 4 secure configuration, 7 continuous vulnerability management, 8 audit logs |
| ATT&CK mitigations | M1051 Update Software (VM Manager patch jobs and rebuilt images), M1030 Network Segmentation (VPC firewall, Cloud Armor, the perimeter), M1047 Audit (Cloud Audit Logs) |

## Documentation and repositories

- [Security Command Center overview](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- [Event Threat Detection](https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview)
- [Web Security Scanner](https://cloud.google.com/security-command-center/docs/concepts-web-security-scanner-overview)
- [List findings](https://cloud.google.com/security-command-center/docs/how-to-api-list-findings)
- [Organization Policy Service](https://cloud.google.com/resource-manager/docs/organization-policy/overview)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls/docs/overview)
- [Cloud Armor](https://cloud.google.com/armor/docs/cloud-armor-overview)
- [Cloud KMS](https://cloud.google.com/kms/docs)
- [Secret Manager](https://cloud.google.com/secret-manager/docs/overview)
- [Binary Authorization](https://cloud.google.com/binary-authorization/docs/overview)
- [Artifact Analysis container scanning](https://cloud.google.com/artifact-analysis/docs/container-scanning-overview)
- [VM Manager](https://cloud.google.com/compute/docs/vm-manager)
- [Sensitive Data Protection](https://cloud.google.com/sensitive-data-protection/docs)
- [Identity-Aware Proxy](https://cloud.google.com/iap/docs/concepts-overview)
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [Google Security Operations](https://cloud.google.com/security/products/security-operations)

The attack techniques and IAM model are in [GCP Security](/CLOUD_SECURITY_REFERENCE.md). The landing-zone shape those services plug into is in [Cloud Architecture](/CLOUD_ARCHITECTURE_REFERENCE.md).

## Current state

Service names and the split between SCC tiers were checked against Google Cloud documentation titles in October 2026. Which detectors ship in the free tier, in Premium, and in Enterprise is a pricing-page fact, and this page does not freeze it. Data Access logs, VPC Flow Logs, and Web Security Scanner custom scans are off until someone enables them. An organization with only the free tier does not have the threat detectors described above.
