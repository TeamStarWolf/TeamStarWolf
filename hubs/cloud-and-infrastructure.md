<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Cloud and infrastructure

> Securing cloud platforms, SaaS, containers, Kubernetes, and the virtualization layer under them.

Part of the [domain hubs](/hubs/README.md). 8 reference documents in this domain; reading time is the page's words at 230 words a minute.

## References

| Reference | What it covers | Reading time |
|---|---|---|
| [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) | AWS/Azure/GCP security services, IAM attacks, SSRF to IMDS, Pacu/ROADtools/AzureHound, CSPM, K8s security, cloud IR | 32 min |
| [Cloud Security Benchmark](/CLOUD_SECURITY_BENCHMARK.md) | CIS Benchmarks for AWS, Azure, and GCP with automated remediation and detection queries | 8 min |
| [Cloud Network Security](/CLOUD_NETWORK_SECURITY.md) | Network security controls across AWS, Azure and GCP: architecture, firewall policy, WAF, private connectivity, DDoS protection, flow logs, compliance mappings | 11 min |
| [Cloud Architecture Reference](/CLOUD_ARCHITECTURE_REFERENCE.md) | Composing managed cloud services into systems: well-architected pillars, landing zones, and the trade-offs between business, operations, security and cost | 20 min |
| [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) | OAuth consent abuse, token theft, shadow SaaS, Midnight Blizzard/Storm-0558/Okta case studies, CISA SCuBA (ScubaGear/ScubaGoggles), SSPM, M365/GWS/Salesforce/GitHub hardening | 21 min |
| [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md) | Docker/container security, image hardening, runtime protection (Falco/seccomp/AppArmor), container escape defense, registry security, secrets management, SBOM, MITRE ATT&CK containers | 11 min |
| [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md) | K8s RBAC attacks, container escape, Pod Security Standards, NetworkPolicy, secrets management, Falco, kube-bench | 4 min |
| [Hypervisor & Virtualization Hardening](/HYPERVISOR_SECURITY_REFERENCE.md) | ESXi/vCenter/Hyper-V/Proxmox hardening; the ESXi ransomware kill chain; exploited hypervisor CVEs; management-plane isolation & immutable backups | 10 min |

## Learning paths

- [Cloud Security](/disciplines/cloud-security.md)
- [Container & Kubernetes Security](/disciplines/container-kubernetes-security.md)

## How-to guides

Time and difficulty are quoted in full from each guide's header table.

| Guide | Time | Difficulty |
|---|---|---|
| [Harden a Kubernetes Cluster](/guides/HARDEN_A_KUBERNETES_CLUSTER.md) | A day for a non-prod pilot; 2-4 weeks to roll a production cluster through every step | Advanced |
| [Investigate a Cloud Account Compromise](/guides/INVESTIGATE_A_CLOUD_COMPROMISE.md) | First hour is containment; full investigation 1-5 days by scope | Advanced: cross-provider, and the evidence ages by the hour |
| [Assess Your M365 Tenant with ScubaGear](/guides/ASSESS_M365_WITH_SCUBAGEAR.md) | 2-4 hours for the first full run and report review | Intermediate |

## See also

- [Cloud attack reference](/CLOUD_ATTACK_REFERENCE.md)
- [Vendor tool pages](/tools/README.md)

<!-- hub:end -->
