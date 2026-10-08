# Cloud Architecture

> In one minute: Cloud architecture is the discipline of composing a provider's managed services into a system that meets business, operational, security, and cost goals — not a pile of VMs with a public IP. The industry has converged on a small set of durable ideas: a **well-architected** baseline (AWS's six pillars, Azure's five, Google Cloud's five plus cross-cutting *perspectives*), a **landing zone** that stamps out governed, isolated accounts/subscriptions/projects from day one, **hub-and-spoke** networking with centralized egress and inspection, **identity as the new perimeter** (short-lived federated credentials, least privilege, no long-lived keys), and **security, cost, and resilience designed in — not bolted on**. This reference gives you the reference architectures, the trade-off decisions, and the threat-informed controls to build cloud systems that are hard to misconfigure and hard to pivot through. For control-level depth, pair it with [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md).

| Read this when… | Start at |
|---|---|
| You're setting up a brand-new cloud footprint (greenfield org) | [Landing zones & org design](#2-reference-architectures--patterns) |
| You need to justify an account/subscription/project boundary | [ADR-01](#key-design-decisions--trade-offs-adr-style) |
| You're designing the network and don't know hub-and-spoke from a VPC peer | [Networking reference](#networking-hub-and-spoke--transit) |
| You're choosing serverless vs. containers vs. Kubernetes | [ADR-04](#key-design-decisions--trade-offs-adr-style) + [Compute](#compute-serverless-containers-kubernetes) |
| You must hit an RTO/RPO or survive a region loss | [Resilience & DR](#resilience-ha--dr) |
| Finance is asking why the bill tripled | [Cost architecture (FinOps)](#cost-architecture-finops) |
| You're doing a threat model / security review of a cloud design | [Security-by-design](#security-by-design-integration) |
| You want a go/no-go checklist before production | [Maturity & checklist](#maturity--checklist) |
| You inherited a mess and want to name the smells | [Anti-patterns & pitfalls](#anti-patterns--pitfalls) |

---

## 1. Principles & drivers

Cloud architecture optimizes against forces that pull in different directions. Name them explicitly so trade-offs are deliberate, not accidental.

**Business & operational drivers**
- **Speed to value** — teams self-serve infrastructure instead of filing tickets.
- **Elasticity** — capacity tracks demand; you pay for what you use, not peak.
- **Operability** — observable, automatable, recoverable without heroics.
- **Compliance & data residency** — where data lives and who can reach it is a design input, not an afterthought.
- **Cost efficiency** — unit economics (cost per request / tenant / transaction) stay sane as you scale.

**Enduring architectural principles**

| Principle | What it means in cloud | Why it matters |
|---|---|---|
| **Design for failure** | Everything fails; assume AZ/region/service loss. No single points of failure. | Cloud SLAs are per-component, not end-to-end — composition is your job. |
| **Immutable infrastructure** | Rebuild, don't patch in place. Golden images / IaC define state. | Eliminates config drift; recovery = redeploy. ATT&CK persistence has nowhere to hide. |
| **Everything as code** | IaC (Terraform/OpenTofu, CloudFormation, Bicep, Pulumi), policy as code, pipelines as code. | Reviewable, versioned, testable, reproducible. A PR is your change control. |
| **Least privilege & zero standing access** | Short-lived, scoped, just-in-time credentials; no shared root; no long-lived keys. | Identity is the primary attack surface in cloud (see [ATT&CK integration](#tie-to-mitre-attck)). |
| **Defense in depth** | Network, identity, workload, data layers each enforce policy independently. | One misconfig shouldn't be game over. |
| **Automate governance (guardrails, not gates)** | Preventive + detective controls in code; let teams move fast inside a safe box. | Scales better than review boards; closes the window attackers exploit. |
| **Loose coupling** | Async messaging, well-defined APIs, bulkheads. | Blast radius containment; independent scaling and deploy. |
| **Data gravity awareness** | Compute moves to data more cheaply than data moves to compute. | Egress is expensive and slow; placement drives both cost and latency. |
| **Mechanical sympathy for the pricing model** | Understand what each service actually charges for (requests, GB-months, egress, provisioned capacity). | Architecture *is* cost architecture in the cloud. |

**The Well-Architected frameworks** — all three majors publish one; learn the pillars, use the review questions as a design checklist. *(Pillar names verified 2026-10-08; re-check the vendor docs for additions.)*

| Provider | Framework | Pillars |
|---|---|---|
| **AWS** | Well-Architected Framework | Operational Excellence · Security · Reliability · Performance Efficiency · Cost Optimization · **Sustainability** (6th pillar, added late 2021). Plus domain *Lenses* (Serverless, SaaS, ML, etc.). |
| **Azure** | Well-Architected Framework (WAF) | Reliability · Security · Cost Optimization · Operational Excellence · Performance Efficiency (5). |
| **Google Cloud** | (Well-)Architected Framework | Operational Excellence · Security, Privacy & Compliance · Reliability · Cost Optimization · Performance Optimization (5), plus cross-pillar **perspectives** (e.g., AI & ML). *Verify whether Sustainability is now a formal pillar/perspective in current docs.* |

> Treat the Well-Architected review not as a certification exercise but as a recurring, structured self-interrogation. The Security pillar in each maps cleanly onto [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md).

---

## 2. Reference architectures & patterns

### Landing zone & organization design

A **landing zone** is a pre-configured, governed, multi-account (AWS) / multi-subscription (Azure) / multi-project (GCP) environment that new workloads land in with security, networking, identity, logging, and guardrails already wired. Building workloads *before* the landing zone is the single most common and most expensive greenfield mistake.

**Canonical org hierarchy (vendor terms differ, shape is the same):**

```
                         ┌──────────────────────────┐
                         │   Org root / Tenant root  │   (billing, break-glass)
                         └────────────┬──────────────┘
          ┌───────────────────────────┼───────────────────────────┐
   ┌──────┴───────┐            ┌───────┴────────┐          ┌────────┴────────┐
   │  Platform /  │            │   Workloads     │          │   Sandbox /     │
   │  Foundation  │            │  (prod/nonprod) │          │   Decommission  │
   └──────┬───────┘            └───────┬─────────┘          └─────────────────┘
   ┌──────┴─────────────┐      ┌───────┴─────────────────────┐
   │ Log Archive        │      │ App-A-prod   App-A-nonprod   │   ← one account/sub/
   │ Security Tooling    │      │ App-B-prod   App-B-nonprod   │     project per
   │ Shared Networking   │      │ Data-platform  ...           │     workload×env
   │ Identity            │      └──────────────────────────────┘
   └────────────────────┘
```

| Provider | Hierarchy primitives | Opinionated accelerator | Policy engine |
|---|---|---|---|
| **AWS** | Organizations → OUs → **Accounts** | Control Tower; Landing Zone Accelerator (LZA); AWS SRA (Security Reference Architecture) | Service Control Policies (SCPs), declarative policies, `cloudtrail`, Config |
| **Azure** | Management Groups → Subscriptions → Resource Groups | Azure Landing Zones (part of the Cloud Adoption Framework) | Azure Policy, Blueprints (deprecating → use Deployment Stacks + Policy) |
| **GCP** | Organization → Folders → **Projects** | Cloud Foundation Toolkit; Fabric FAST; Assured Workloads | Organization Policy Service, IAM |

**Why one account/subscription/project per workload×environment is the default blast-radius boundary:** it's the strongest native isolation plane (separate IAM trust, API rate limits, billing, and control-plane policy). Resource groups / namespaces are *organizational*, not *security*, boundaries.

**Landing-zone non-negotiables (the foundation stamps these before any workload):**
1. **Centralized, immutable logging** — org-wide trail (CloudTrail / Azure Activity + Diagnostic / Cloud Audit Logs) shipped to a dedicated, write-once log-archive account the workload teams cannot alter. *(NIST AU-9, ATT&CK T1562.008 "Disable/Modify Cloud Logs" mitigation.)*
2. **Preventive guardrails** — SCPs/Azure Policy/Org Policy deny high-risk actions (disabling logging, opening `0.0.0.0/0` to sensitive ports, creating IAM users with long-lived keys, leaving a region un-restricted).
3. **Centralized identity** — federation to one IdP; no local users. Break-glass accounts hardware-MFA'd, sealed, monitored.
4. **Network baseline** — shared connectivity hub, standard address plan, no default VPC/VNet left in place.
5. **Security tooling account** — CSPM/CNAPP, GuardDuty/Defender for Cloud/SCC, delegated admin.

### Networking: hub-and-spoke & transit

The default WAN topology for anything beyond a single app. A central **hub** holds shared services (egress firewall, DNS, inbound ingress, hybrid connectivity); **spokes** are per-workload networks that cannot talk to each other except through the hub.

```
          on-prem / other clouds
                  │
          ┌───────┴────────┐
          │  Hybrid link    │  (Direct Connect / ExpressRoute / Cloud Interconnect
          │  (private)      │   or Site-to-Site VPN)
          └───────┬────────┘
   ┌──────────────┴───────────────────────────────────────┐
   │                      HUB VPC/VNet                      │
   │   ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
   │   │ Egress    │  │ Central  │  │ Inbound ingress /  │   │
   │   │ firewall  │  │ DNS      │  │ WAF / LB           │   │
   │   │ (inspect) │  │ resolver │  │                    │   │
   │   └──────────┘  └──────────┘  └───────────────────┘   │
   └───┬───────────────────┬───────────────────┬───────────┘
       │ (transit gw /      │                   │
       │  vWAN / NCC)       │                   │
   ┌───┴────┐          ┌────┴───┐          ┌────┴───┐
   │ Spoke  │          │ Spoke  │          │ Spoke  │   ← no spoke↔spoke
   │ App A  │          │ App B  │          │ Shared │     by default
   └────────┘          └────────┘          │ data   │
                                           └────────┘
```

| Provider | Transit fabric | Centralized egress/inspection | Private service access |
|---|---|---|---|
| **AWS** | Transit Gateway (TGW), or Cloud WAN | Inspection VPC + Network Firewall / 3rd-party NGFW; centralized NAT | VPC endpoints (Gateway/Interface, PrivateLink) |
| **Azure** | Virtual WAN (vWAN) hub, or hub-spoke VNet peering | Azure Firewall / NVA in the hub; forced tunneling | Private Endpoint / Private Link, Service Endpoints |
| **GCP** | VPC Network Peering, Network Connectivity Center (NCC), or **Shared VPC** | Cloud NAT + firewall; NGFW in a hub project | Private Service Connect, Private Google Access |

**Design rules**
- **No default routes to the internet from workload subnets.** Egress goes through an inspected, logged NAT/firewall in the hub (ATT&CK T1048 exfil-over-alternative-protocol and C2 egress get a chokepoint).
- **Private endpoints over public service URLs.** Reach managed services (object storage, databases, secrets) over the provider backbone, not the internet. Shrinks the attack surface and kills a whole class of data-exfil-via-public-endpoint paths.
- **Address plan up front.** Non-overlapping CIDRs across clouds and on-prem; reserve space for growth. Overlap is a multi-year tax.
- **DNS is architecture.** Centralized private resolver + conditional forwarding for hybrid; split-horizon for internal vs. external names.
- **Micro-segmentation inside the spoke** with security groups / NSGs / firewall rules — default-deny east-west.

### Three-tier / N-tier (managed, cloud-native)

```
Internet → WAF/CDN → Load Balancer → [ Web / API tier (autoscaling, stateless) ]
                                       │
                                       ▼
                              [ App / service tier ]
                                       │
                           ┌───────────┴───────────┐
                           ▼                        ▼
                   Managed SQL (Multi-AZ)    Cache / Queue / Object store
```
Stateless tiers autoscale horizontally; state lives in managed, replicated data services. This is still the right answer for most line-of-business apps.

### Event-driven & serverless

```
Source → Event bus / Queue → Function(s) → Managed store
  (API GW, object-put, stream, schedule)        │
                                   DLQ ◄─────────┘  (poison messages)
```
Favor for spiky, glue, and async workloads. Decoupling via a durable bus (EventBridge / Event Grid / Pub/Sub, or SQS/Service Bus/Cloud Tasks) gives you bulkheads, retries, and replay. Always design the **dead-letter path** and **idempotency** — at-least-once delivery means handlers must tolerate duplicates.

### Microservices on Kubernetes (platform pattern)

```
Ingress → API gateway → [ service mesh: mTLS, retries, circuit-breaking ]
                              │          │          │
                           svc A       svc B       svc C   (each: HPA, PDB,
                              │                             resource limits,
                           per-svc datastore                network policy)
```
Choose only when you have enough services and platform-engineering maturity to justify the operational weight (see [ADR-04](#key-design-decisions--trade-offs-adr-style)). A managed control plane (EKS/AKS/GKE) is table stakes; GKE Autopilot / EKS-Fargate remove node management.

### Data / analytics (lakehouse)

```
Ingest (batch + stream) → Landing (raw, object storage)
   → Curated / cleansed zone → Serving (warehouse / query engine)
        │                                     │
   governance & lineage catalog        BI / ML / reverse-ETL
```
Medallion (bronze/silver/gold) zoning on object storage, open table formats (Iceberg/Delta/Hudi), a governed catalog, and separation of storage from compute. Classify and tag data at the landing zone so downstream access controls and residency rules are enforceable.

### Multi-region active/passive and active/active

```
Active/Passive (warm standby)          Active/Active
 Region A (live) ──repl──► Region B      Region A ◄──bidirectional──► Region B
   │ DNS/Global LB ─────────┘              └──── global data layer ────┘
   failover on health check               traffic split by latency/geo
```
Active/active maximizes availability and spends it in complexity (conflict resolution, global data consistency). Most systems want active/passive with tested, automated failover — see [Resilience](#resilience-ha--dr).

---

## 3. Building blocks / domains

### Identity & access architecture

Identity is the control plane. Get this wrong and the network, encryption, and logging barely matter.

- **Human access:** federate to a single IdP (Entra ID, Okta, Google Workspace) → SSO into the cloud. **No IAM users, no console passwords for humans, no long-lived access keys.** Use permission sets / PIM / short-lived role assumption. Just-in-time elevation with approval for privileged roles.
- **Workload access:** workloads assume roles / use workload identity federation / managed identities — never embedded static keys. Pod → cloud IAM via IRSA (AWS), Workload Identity (GKE), or Azure Workload Identity.
- **Guardrails:** permission boundaries / deny policies cap the maximum privilege any role can grant itself; prevents privilege-escalation via policy editing (ATT&CK T1098 Account Manipulation, T1548 Abuse Elevation Control).
- **Secrets:** a managed secrets store (Secrets Manager / Key Vault / Secret Manager) with rotation; never in env vars in code, repos, or AMIs.

| Decision | Good default |
|---|---|
| Human login | Federated SSO + hardware MFA; zero standing admin |
| Service-to-service | Workload identity / IAM roles; mTLS in-mesh |
| CI/CD → cloud | OIDC federation (GitHub Actions / GitLab OIDC → short-lived role), **not** stored cloud keys |
| Break-glass | 2+ sealed, hardware-MFA accounts, heavily alerted, used only in a declared incident |

### Data architecture

- **Storage tiers:** object (cheap, durable, the default landing place) · block (low-latency, attached) · file (shared POSIX) · managed relational/NoSQL/warehouse. Match the access pattern, not the habit.
- **Encryption:** at rest (provider-managed KMS keys by default; customer-managed CMKs where key custody/revocation matters; HYOK/external KMS for the highest assurance) and in transit (TLS everywhere, mTLS inside the mesh).
- **Classification & residency:** tag data domains; pin regions for regulated data; use provider residency controls (Assured Workloads, EU Data Boundary, data-residency regions). Residency is an architecture constraint, not a toggle you add later.
- **Lifecycle:** tiering to cold/archive, retention + legal hold, and object-lock/immutability for logs and backups (ransomware resilience — ATT&CK T1486 Data Encrypted for Impact, T1485 Data Destruction).

### Compute: serverless, containers, Kubernetes

```
         ◄── less you manage / more opinionated          more control / more ops ──►
 Functions   →   Containers-as-a-service   →   Managed Kubernetes   →   VMs
 (Lambda,         (Fargate, Cloud Run,          (EKS/AKS/GKE)           (EC2, VMSS,
  Functions,       Container Apps)                                       Compute Engine)
  Cloud Functions)
```

| Model | Choose when | Watch out for |
|---|---|---|
| **Functions (FaaS)** | Event glue, spiky/async, low-to-medium steady throughput | Cold starts, execution limits, per-invoke cost at high volume, state externalization |
| **Containers-as-a-service** | Standard web/API services, you want containers without node ops | Less knob-level control; per-service networking limits |
| **Managed Kubernetes** | Many services, portability, complex orchestration, platform team exists | Operational weight, upgrade cadence, RBAC + supply-chain + node security (ATT&CK Containers matrix) |
| **VMs** | Lift-and-shift, licensing, specialized/stateful or GPU, legacy | You own patching, images, scaling, hardening — the most to secure |

Default modern greenfield: **containers-as-a-service or functions first; Kubernetes only when the service count and portability needs justify it.**

### Integration & messaging
Durable queues (SQS/Service Bus/Cloud Tasks), event buses (EventBridge/Event Grid/Pub/Sub), streams (Kinesis/Event Hubs/Pub/Sub, or managed Kafka). Choose by ordering, replay, fan-out, and delivery-guarantee needs. Always define DLQs, backoff, and idempotency.

### Observability
Three pillars — **metrics, logs, traces** — plus events. Centralize into a platform (CloudWatch / Azure Monitor / Cloud Operations, or OpenTelemetry → your SIEM/observability stack). Define SLIs/SLOs and error budgets; alert on symptoms (user-facing SLO burn), not just causes. Security telemetry (audit logs, flow logs, DNS logs) flows to the SIEM in the security/log-archive account.

### Edge & delivery
CDN + WAF + DDoS protection at the edge (CloudFront+AWS WAF+Shield / Front Door+Azure WAF+DDoS / Cloud CDN+Cloud Armor). Terminate TLS, cache, and filter L7 attacks before traffic hits origin.

---

## Key design decisions & trade-offs (ADR-style)

Each ADR: **Context → Options → Decision (default) → Consequences.** Adapt to your drivers.

### ADR-01 — Account/subscription/project granularity
- **Context:** How finely to split the org hierarchy.
- **Options:** (a) few big accounts, many resource groups/namespaces; (b) one account/sub/project per workload×environment; (c) per-team.
- **Decision:** **(b)** as the default isolation boundary; group into OUs/management-groups/folders by environment and sensitivity.
- **Consequences:** Strong blast-radius and IAM isolation, cleaner cost attribution, independent quotas; costs you automation discipline (you *must* have a landing zone and IaC or the sprawl is unmanageable). (a) is tempting early and painful later.

### ADR-02 — Centralized vs. distributed egress & inspection
- **Options:** per-spoke NAT/internet gateways vs. centralized inspected egress in the hub.
- **Decision:** **Centralized, inspected, logged egress** for anything with sensitive data or compliance scope.
- **Consequences:** One chokepoint to monitor (good for detection and exfil prevention) and fewer public IPs; adds hub throughput/cost and a potential bottleneck — size and HA the firewall accordingly. Pure-serverless, low-sensitivity apps may accept per-spoke egress for simplicity.

### ADR-03 — Networking model: private endpoints vs. public service endpoints
- **Decision:** **Private endpoints/links** to managed services as the default; public endpoints only for genuinely public content, fronted by WAF/CDN.
- **Consequences:** Removes internet exposure of data services (mitigates public-bucket / public-DB classes, ATT&CK T1530 Data from Cloud Storage); adds per-endpoint cost and DNS complexity.

### ADR-04 — Serverless vs. containers vs. Kubernetes
- **Decision:** Start at the **highest-abstraction option that fits** (functions → CaaS → K8s). Adopt Kubernetes only when service count, portability, or orchestration complexity clears the bar *and* you have a platform team.
- **Consequences:** Higher abstraction = less to secure and operate, more provider coupling, some ceiling on control/cost at scale. Kubernetes buys portability and control at a large, ongoing operational and security cost (cluster, RBAC, supply chain, node, mesh).

### ADR-05 — Managed service vs. self-hosted
- **Decision:** **Prefer the managed service** (database, queue, cache, search) unless a hard requirement (licensing, feature, data-sovereignty, extreme cost at scale) forces self-hosting.
- **Consequences:** Offloads patching/HA/backup (shrinks your ATT&CK surface and ops load) and accelerates delivery; increases provider lock-in and sometimes unit cost. Self-hosting re-acquires all of that undifferentiated heavy lifting.

### ADR-06 — IaC tool & state strategy
- **Options:** Terraform/OpenTofu (multi-cloud, huge ecosystem) · provider-native (CloudFormation/Bicep/Deployment Manager→Config Connector) · Pulumi/CDK (general-purpose languages).
- **Decision:** A single declarative IaC standard org-wide; remote, locked, encrypted state; **no click-ops in shared/prod**. Policy-as-code (OPA/Conftest, Sentinel, Checkov) gates the pipeline.
- **Consequences:** Reproducibility, review-as-change-control, drift detection; learning curve and state-management discipline. Native tools reduce lock-in risk of the *tool* but increase lock-in to the *provider*.

### ADR-07 — Multi-cloud posture
- **Options:** single-cloud · best-of-breed multi-cloud · portable-everywhere (K8s + abstraction).
- **Decision:** **Single primary cloud** for most orgs; go multi-cloud only for concrete drivers (regulatory, acquisition, specific best-of-breed service, resilience mandate). Don't pay the abstraction tax for a hypothetical.
- **Consequences:** Single-cloud = deeper service use, lower complexity, real lock-in. Multi-cloud = negotiating leverage and resilience at the cost of lowest-common-denominator design, doubled operational/security surface, and egress between clouds. See [multi-cloud & hybrid](#multi-cloud--hybrid).

### ADR-08 — Resilience target (RTO/RPO) → topology
- **Decision:** Derive topology from RTO/RPO, not the reverse. Backup/restore → pilot-light → warm-standby → active/active as targets tighten. Most systems: **multi-AZ by default, multi-region warm-standby for tier-1**.
- **Consequences:** Each step up multiplies cost and complexity (especially data replication and failover testing). Active/active only where seconds of RTO and near-zero RPO are truly required.

---

## Security-by-design integration

This is a security library: architecture decisions *are* security decisions. Good architecture reduces vulnerability exposure by shrinking attack surface, containing blast radius, and making misconfiguration hard. For control depth, operational detail, and provider-specific hardening, go to **[CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md)**.

### The shared responsibility model is an architecture input
You always own: identity & access config, data classification & encryption choices, network exposure, OS/runtime patching for IaaS, and application security. The provider owns the substrate. The line moves left as you move up the abstraction ladder (IaaS → PaaS → FaaS/SaaS) — which is itself a security argument for higher abstraction.

### How each architectural choice reduces exposure

| Architectural choice | Exposure it removes | Threat-informed mapping |
|---|---|---|
| Landing zone with preventive guardrails | Whole classes of misconfig never happen | CIS Benchmarks; NIST CM-2/CM-6/CM-7; prevents T1562 (Impair Defenses) |
| One account/sub/project per workload | Lateral movement & blast radius | NIST SC-7, AC-4; ATT&CK T1021/TA0008 (Lateral Movement) contained |
| Federated SSO + no long-lived keys | Credential theft & reuse | NIST IA-2/IA-5; ATT&CK T1078 (Valid Accounts), T1552 (Unsecured Credentials) |
| Least privilege + permission boundaries | Privilege escalation | NIST AC-6; ATT&CK T1098, T1548 |
| Private endpoints / no public data services | Internet-exposed data stores | ATT&CK T1530 (Data from Cloud Storage), T1619 (Cloud Storage Object Discovery) |
| Centralized inspected egress | C2 & exfil channels | ATT&CK TA0011 (C2), T1048 (Exfil Over Alternative Protocol) |
| Immutable logging in a sealed account | Attacker covering tracks | NIST AU-9; ATT&CK T1562.008 (Disable/Modify Cloud Logs) |
| Encryption + CMK with revocation | Data-at-rest compromise, insider | NIST SC-12/SC-13/SC-28 |
| Immutable infra + IaC | Persistence & drift | ATT&CK TA0003 (Persistence) hard to hold; drift detectable |
| WAF/CDN/DDoS at edge | L7 attacks, volumetric DoS | ATT&CK T1499 (Endpoint DoS); OWASP Top 10 at the edge |
| Backup immutability / object-lock | Ransomware, destruction | ATT&CK T1486, T1485, T1490 (Inhibit System Recovery) |

### Tie to MITRE ATT&CK
Threat-model cloud designs against the **ATT&CK Cloud** matrices (IaaS, Identity/EntraID, SaaS, Office/Google Workspace) and the **Containers** matrix. The dominant cloud kill chain is **identity-centric**: Initial Access via Valid Accounts (T1078) or a phished/SSO token → Discovery of cloud resources (T1580 Cloud Infrastructure Discovery, T1526 Cloud Service Discovery) → Privilege Escalation via IAM manipulation (T1098, T1548) → Lateral Movement across accounts/roles → Collection/Exfil from storage (T1530) → Impact (T1486/T1485/T1496 Resource Hijacking, e.g., cryptomining). Map each stage to a preventive and a detective control, and verify your landing-zone guardrails close the preventive side. **Containers** adds T1610 (Deploy Container), T1611 (Escape to Host), T1613 (Container/Resource Discovery) — mitigated by admission control, least-privilege RBAC, non-root/read-only workloads, and network policy.

### CSPM / CNAPP — continuous architecture validation
Posture management watches your *as-built* state against your *as-designed* intent and the benchmarks. As of the 2025 Gartner Market Guide, buyers strongly prefer a **CNAPP** (Cloud-Native Application Protection Platform) that unifies:

```
CNAPP ⊇  CSPM   (posture / misconfig / compliance across AWS/Azure/GCP/K8s)
      +  CWPP   (workload runtime protection: VMs, containers, serverless)
      +  CIEM   (entitlement management → least privilege, over-permission detection)
      +  DevSecOps / IaC scanning (shift-left: catch misconfig in the pipeline)
      (+ KSPM, DSPM in some products — verify per vendor)
```
Native equivalents: AWS Security Hub + GuardDuty + Inspector + IAM Access Analyzer; Microsoft Defender for Cloud; Google Security Command Center. The architectural point: **design so posture tooling has a sealed log/security account to run from and preventive guardrails to enforce** — detection without prevention just tells you how you were breached.

### Guardrails pattern (preventive + detective)
```
Developer PR ──► IaC policy-as-code (Checkov/OPA) ──► blocked if non-compliant   [SHIFT-LEFT]
   │                                                                              │
   ▼ merged & deployed                                                           │
Org policy (SCP/Azure Policy/Org Policy) ──► denies prohibited API calls         [PREVENT]
   │
   ▼ runtime
CSPM/CNAPP + native findings ──► auto-remediate or alert SIEM                     [DETECT]
```

---

## Standards & frameworks

*(Numbers/versions current as of 2026-10-08; re-verify before citing in an audit.)*

| Standard / framework | What it gives cloud architects |
|---|---|
| **AWS/Azure/Google Well-Architected** | The design-review baseline (see [Principles](#1-principles--drivers)). |
| **NIST SP 800-53 Rev. 5** | The control catalog most US/enterprise cloud baselines map to. |
| **NIST SP 800-145** | The canonical definition of cloud (service & deployment models). |
| **NIST SP 800-144 / 800-146** | Guidance on security/privacy in public cloud and cloud synopsis. |
| **CIS Benchmarks** (AWS, Azure, GCP Foundations; Kubernetes; Docker) | Prescriptive, testable configuration baselines — wire into CSPM. |
| **CIS Controls v8.1** | Prioritized safeguards; maps to cloud guardrails. |
| **CSA Cloud Controls Matrix (CCM) + CAIQ** | Cloud-specific control framework and vendor-assessment questionnaire. |
| **CSA STAR** | Provider assurance registry. |
| **ISO/IEC 27001 / 27002** | ISMS and control set. |
| **ISO/IEC 27017** | Cloud-specific security controls. |
| **ISO/IEC 27018** | Protection of PII in public cloud. |
| **ISO/IEC 22301** | Business continuity (feeds DR targets). |
| **SOC 2 (AICPA TSC)** | Trust-services attestation most SaaS buyers expect. |
| **FedRAMP** | US gov cloud authorization (Low/Moderate/High; and the modernization/"20x" direction — verify current state). |
| **PCI DSS v4.0.1** | Cardholder-data environments in cloud. |
| **NIST CSF 2.0** | Govern/Identify/Protect/Detect/Respond/Recover — program-level framing (adds *Govern*). |
| **MITRE ATT&CK** (Cloud, Identity, Containers, SaaS) | Threat-informed design & detection coverage. |
| **MITRE D3FEND** | Defensive-technique counterpart to ATT&CK — maps controls to techniques. |
| **OWASP** (Top 10, API Top 10, Kubernetes Top 10, Serverless, IaC Security) | Application- and platform-layer risk. |
| **SLSA / supply-chain (SSDF SP 800-218)** | Build & artifact integrity for container/serverless pipelines. |

---

## Anti-patterns & pitfalls

| Anti-pattern | Why it hurts | Do instead |
|---|---|---|
| **Workloads before the landing zone** | Every later guardrail is a retrofit fight; drift and exposure accrue | Stamp the foundation first; land workloads into it |
| **Lift-and-shift and call it "cloud"** | You inherit all the ops burden and gain little elasticity or managed-service benefit; worst unit economics | Rehost to stabilize, then *replatform/refactor* to managed services |
| **The one giant account/VNet** | No blast-radius isolation; IAM and network become a single failure/compromise domain | Isolate by account/subscription/project; hub-and-spoke |
| **Long-lived access keys in code/CI** | #1 cloud breach cause; keys leak and never expire | OIDC federation, workload identity, short-lived creds, secret scanning |
| **Public buckets / public databases** | Direct data exfil (T1530); recurring headline breach | Private by default; private endpoints; block-public-access org-wide |
| **`0.0.0.0/0` to admin ports (SSH/RDP)** | Internet-facing brute-force & exploit surface | Bastion/SSM/Bastion-as-a-service, zero inbound, JIT access |
| **Over-permissive IAM (`*:*`, admin for apps)** | Massive privilege-escalation & lateral-movement surface | Least privilege, permission boundaries, CIEM to right-size |
| **Click-ops in production** | Undocumented drift, irreproducible, no change control | IaC + policy-as-code + pipelines; deny console writes in prod |
| **Logging you can't trust** | Attackers disable/alter logs (T1562.008); no forensics | Immutable, org-wide, sealed log-archive account |
| **Single-region "HA"** | AZ redundancy ≠ region redundancy; one region event = outage | Multi-AZ by default; multi-region per RTO/RPO; *test failover* |
| **No egress control** | C2/exfil have an open door; no detection chokepoint | Centralized inspected egress; default-deny |
| **Chatty synchronous microservices** | Latency, cascading failure, cost; a distributed monolith | Async where possible; bulkheads, timeouts, circuit breakers |
| **Kubernetes as a default** | Operational & security weight no one budgeted for | Highest-abstraction-that-fits; K8s only when justified |
| **DR plan that's never tested** | "Backups" that don't restore; untested failover fails in the incident | Game-day/chaos drills; restore tests; measured RTO/RPO |
| **Egress-cost blindness** | Cross-AZ/region/internet data transfer silently dominates the bill | Data-gravity-aware placement; private peering; model egress |
| **Tagging/ownership vacuum** | Can't attribute cost, can't do incident response | Mandatory tagging policy enforced at create time |
| **Ignoring sustainability/efficiency** | Over-provisioned, idle, oversized = cost + carbon | Right-size, autoscale, decommission; the Sustainability pillar |

---

## Maturity & checklist

### Maturity model

| Level | Foundation | Networking | Identity | Delivery | Security posture |
|---|---|---|---|---|---|
| **0 — Ad hoc** | Single shared account, click-ops | Flat, default VPC, public IPs | Root/long-lived keys | Manual deploys | No CSPM; reactive |
| **1 — Managed** | Multi-account, manual landing zone | Hub-spoke emerging | SSO for humans | Some IaC + CI | Benchmarks run, some guardrails |
| **2 — Defined** | Automated landing zone, OUs | Centralized egress, private endpoints | Federated, least-priv, no static keys | Full IaC + policy-as-code | CSPM/CNAPP, preventive SCPs |
| **3 — Quantified** | Self-service governed platform | Micro-segmented, documented address plan | JIT elevation, CIEM right-sizing | GitOps, progressive delivery | SLO-driven, auto-remediation, threat-modeled |
| **4 — Optimizing** | Golden paths, internal dev platform | Zero-trust network, continuous verification | Zero standing access | Chaos/game-days, DR tested | ATT&CK coverage measured, FinOps + sustainability optimized |

### Pre-production go/no-go checklist

**Foundation & governance**
- [ ] Landing zone deployed; workloads land in governed accounts/subs/projects (not root/management)
- [ ] Preventive guardrails (SCP/Azure Policy/Org Policy) enforce: logging can't be disabled, no public data by default, region restrictions, no IAM users with static keys
- [ ] Everything defined in IaC; remote locked encrypted state; no click-ops in prod
- [ ] Mandatory tagging (owner, env, cost-center, data-class) enforced at create time

**Identity**
- [ ] Human access via federated SSO + MFA; no console users/passwords
- [ ] Workloads use roles/workload identity; zero long-lived keys; secrets in a managed store with rotation
- [ ] Least privilege with permission boundaries; privileged roles are JIT with approval
- [ ] Break-glass accounts sealed, hardware-MFA'd, alerted

**Network**
- [ ] Non-overlapping address plan documented
- [ ] Hub-and-spoke; no spoke↔spoke by default; centralized inspected, logged egress
- [ ] Private endpoints for managed services; no public data stores; no `0.0.0.0/0` to admin ports
- [ ] Default-deny micro-segmentation; WAF/CDN/DDoS at the edge

**Data**
- [ ] Data classified; residency pinned where required
- [ ] Encryption at rest (CMK where custody matters) and TLS/mTLS in transit
- [ ] Backups automated, tested-restore, and immutable (object-lock) for tier-1 and logs

**Resilience**
- [ ] Multi-AZ by default; multi-region per RTO/RPO for tier-1
- [ ] RTO/RPO defined per workload; failover automated and *tested* (game-day)
- [ ] No single points of failure; graceful degradation; DLQs and idempotency on async paths

**Observability & security ops**
- [ ] Metrics/logs/traces centralized; SLIs/SLOs + burn-rate alerts
- [ ] Immutable org-wide audit trail to a sealed log-archive account
- [ ] CSPM/CNAPP active; findings route to SIEM; auto-remediation for known-bad
- [ ] Design threat-modeled against ATT&CK Cloud/Containers; detections cover the identity kill chain

**Cost**
- [ ] Budgets + anomaly alerts; cost attributable by tag
- [ ] Right-sizing, autoscaling, commitment/savings strategy decided
- [ ] Egress modeled; idle/orphaned resources reaped

---

## Resilience, HA & DR

Derive the topology from the **RTO** (how fast you must recover) and **RPO** (how much data you can lose). Don't buy active/active to protect a reporting dashboard.

| Strategy | RTO | RPO | Cost | Use for |
|---|---|---|---|---|
| **Backup & restore** | Hours–day | Hours | $ | Dev/test, tier-3 |
| **Pilot light** | 10s of min | Minutes | $$ | Tier-2; core minimal stack warm |
| **Warm standby** | Minutes | Seconds–min | $$$ | Tier-1 default |
| **Active/active (multi-site)** | ~0 / seconds | ~0 | $$$$ | Mission-critical, global |

**Layering of failure domains:** instance → **Availability Zone** → **Region** → provider. Multi-AZ is the cheap default and covers the common case (hardware/AZ failure). Multi-region covers regional events and is where cost and data-consistency complexity jump. Design for graceful degradation (shed load, serve stale, read-only mode) and **test failover regularly** — an untested DR plan is a hope, not a control (ties to ATT&CK T1490 Inhibit System Recovery — immutable, tested backups defeat it).

---

## Cost architecture (FinOps)

In the cloud, **the architecture is the cost model.** Treat cost as a first-class non-functional requirement with the FinOps lifecycle: **Inform → Optimize → Operate.**

**Where the money actually goes (and the architectural lever):**

| Cost driver | Architectural lever |
|---|---|
| Compute (always-on, over-provisioned) | Autoscaling, right-sizing, serverless/scale-to-zero, Graviton/ARM & spot |
| Commitment discounts | Savings Plans / Reserved Instances / Committed Use for steady baseline |
| **Data egress / cross-AZ/region transfer** | Data-gravity-aware placement, private peering, caching/CDN, co-locate chatty services |
| Storage tiering | Lifecycle policies to cold/archive; delete orphans & old snapshots |
| Managed-service premiums | Justify vs. self-host at scale (ADR-05); pick the right pricing dimension |
| Idle & zombie resources | Tag-driven reaping; non-prod shutdown schedules |

**Practices:** show-back/charge-back via mandatory tagging; budgets + anomaly detection; unit-cost metrics (cost per request/tenant) tracked like an SLI; cost-as-code checks in the pipeline (flag an expensive instance type in a PR). The **Cost Optimization** and **Sustainability/efficiency** pillars reinforce each other — an idle, oversized fleet wastes money *and* carbon.

---

## Multi-cloud & hybrid

**Be honest about the driver before paying the tax.**

| Pattern | Driver | Reality |
|---|---|---|
| **Single-cloud (go deep)** | Simplicity, velocity, best use of managed services | Default for most orgs; accept and manage lock-in |
| **Hybrid (cloud + on-prem)** | Data gravity, latency, regulation, sunk hardware, migration-in-flight | Private connectivity (Direct Connect/ExpressRoute/Interconnect), consistent identity & network plane, hybrid control planes (Anthos/Arc/Outposts/Stacks — verify current names) |
| **Multi-cloud — best-of-breed** | A specific service only one cloud does well | Integrate at the edges; don't force a lowest-common-denominator design |
| **Multi-cloud — resilience/regulatory** | Mandate to survive a provider or avoid concentration risk | Expensive: doubled ops & security surface, inter-cloud egress, portability constraints |
| **Portable (K8s + abstraction)** | Genuine need to move workloads | Real but costly abstraction tax; you forgo deep managed services |

**Architectural truths:** identity and network are the hardest things to make consistent across clouds — standardize them first (one IdP, non-overlapping address plan, one policy-as-code standard). Inter-cloud **egress is a real and recurring cost**. Security posture must be unified (a single CNAPP across AWS/Azure/GCP/K8s is precisely the market's answer here). Don't adopt multi-cloud for a hypothetical; adopt it for a signed requirement.

---

## Tools & further reading

**Landing zones / foundations:** AWS Control Tower · Landing Zone Accelerator · AWS Security Reference Architecture · Azure Landing Zones (Cloud Adoption Framework) · GCP Cloud Foundation Toolkit / Fabric FAST.

**IaC & policy-as-code:** Terraform / OpenTofu · AWS CloudFormation / CDK · Azure Bicep · Pulumi · Open Policy Agent (OPA/Conftest) · HashiCorp Sentinel · Checkov · tfsec/Trivy · KICS.

**Posture & workload security (CSPM/CNAPP):** AWS Security Hub + GuardDuty + Inspector + IAM Access Analyzer · Microsoft Defender for Cloud · Google Security Command Center · plus third-party CNAPPs (verify current Gartner-named vendors).

**Networking:** AWS Transit Gateway / Cloud WAN · Azure Virtual WAN / Firewall · GCP Network Connectivity Center / Shared VPC · PrivateLink / Private Endpoint / Private Service Connect.

**Observability:** OpenTelemetry · CloudWatch · Azure Monitor · Google Cloud Operations · plus your SIEM.

**Resilience/chaos:** AWS Fault Injection Service · Azure Chaos Studio · Chaos Mesh / LitmusChaos (K8s).

**Frameworks & reference docs:** the three Well-Architected Frameworks · NIST SP 800-53 Rev. 5, 800-145, CSF 2.0 · CIS Benchmarks & Controls v8.1 · CSA Cloud Controls Matrix & STAR · ISO/IEC 27017 / 27018 / 27001 · MITRE ATT&CK (Cloud, Identity, Containers) & D3FEND · OWASP Top 10 / API / Kubernetes / IaC · SLSA & NIST SSDF (SP 800-218).

**Within this library:** **[CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md)** (control-level and provider-specific cloud security depth) · the Security, Networking, AI, and general Architecture references for the layers this document references.

---

*Maintenance note: framework pillar names, standard version numbers, and vendor service/product names drift. Items marked "verify" and all version numbers were accurate at the last review (2026-10-08) — web-verify against primary vendor/standards-body sources before relying on them in an audit or design authority context. Do not assert a version you have not checked.*
