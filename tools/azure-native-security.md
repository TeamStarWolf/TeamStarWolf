# Azure Native Security (Defender for Cloud, Sentinel, Policy, Firewall)

*Microsoft Azure · Native control plane for posture, detection, policy, network inspection, secrets, and patching*

Azure does not ship one security product. The native stack is a set of services that share Entra ID, Azure Resource Manager, and Log Analytics. [Microsoft Defender for Cloud](/tools/microsoft-defender-for-cloud.md) is the CNAPP (CSPM, workload plans, attack paths, and the integrated vulnerability scanner). [Microsoft Entra ID](/tools/entra-id.md) is the identity plane. This page is the rest of the control plane those two sit in, and how the pieces map onto vulnerability management and CTEM. Product names and SKUs move. Confirm the current name on the linked Microsoft Learn page before you buy or automate.

## Capabilities and architecture

**What each service is for**

| Service | Job | What it is not |
|---|---|---|
| Microsoft Defender for Cloud | Posture, workload alerts, attack paths, agentless and agent-based vulnerability assessment | The SIEM. Export alerts onward. |
| Microsoft Sentinel | Analytics rules, incidents, hunting, and Logic Apps playbooks on a Log Analytics workspace | A patching tool |
| Azure Policy | Deny, Audit, Modify, DeployIfNotExists, and AuditIfNotExists against Resource Manager | A runtime EDR |
| Azure Firewall | Hub firewall. Threat intelligence filtering on Standard. IDPS and TLS inspection on Premium. | A WAF. Application Gateway and Front Door carry the WAF. |
| Azure DDoS Protection | Volumetric protection for public IPs. A per-IP plan and a virtual-network plan. | An application-layer WAF |
| Azure Key Vault | Keys, secrets, and certificates. Prefer the Azure RBAC data-plane permission model. Turn on purge protection. | A general database |
| Azure Update Manager | Assess and install OS updates on Azure VMs and Arc-enabled machines | An application-dependency scanner |
| Defender EASM | Internet-facing asset discovery from seeds you supply | A substitute for an internal CMDB |
| Azure Bastion | RDP and SSH through the control plane, with no public IP on the VM | A user VPN |
| Azure Private Link | A private IP in your VNet for a PaaS service | A firewall rule |

**How it is wired.** Management groups hold Policy and Defender plans. Subscriptions hold resources. Diagnostic settings on the subscription ship the Activity Log to a Log Analytics workspace the workload team does not own. Sentinel is that workspace plus the SecurityInsights solution. Defender for Cloud continuous export sends alerts and recommendations to the same workspace or to an Event Hub. Arc extends Update Manager, Policy guest configuration, and Defender for Servers to machines outside Azure.

**What you pay for.** Foundational CSPM in Defender for Cloud is free. Defender plans, Sentinel ingestion, Firewall SKUs, DDoS plans, and Update Manager on Arc machines are billed separately. Defender for Servers Plan 2 includes Update Manager for those Arc servers, as the Defender for Cloud page records. Model the bill before you enable every plan in every subscription.

**Integrations.** Entra ID for the identities Policy and Defender CIEM reason about. GitHub Advanced Security and Azure DevOps for the code-to-cloud path inside Defender CSPM. ServiceNow and Jira through Logic Apps. AWS and GCP connectors plus Arc for resources that are not Azure.

## Vulnerability-mitigation role

The native VM loop on Azure is: discover with Defender for Cloud inventory, Defender EASM, and Resource Graph; assess with the integrated vulnerability assessment and agentless scanning; prioritize with attack-path analysis and secure score, not with CVSS alone; mobilize with Update Manager for the OS fix and with Policy `DeployIfNotExists` or `Deny` for the misconfiguration; validate by a sub-assessment moving to Healthy and, for a control that should block, by an alert or a denied ARM call in the Activity Log.

A Healthy recommendation means the control is present. It does not mean an attacker tried it. That distinction is the CTEM validation stage, and it is written up in the [CTEM reference](/CTEM_REFERENCE.md).

**In a critical CVE.** Identify affected VMs and images from Defender vulnerability sub-assessments. Rank the ones on an attack path or with a public IP. Cut reachability with JIT VM access, an NSG change, or Firewall rules while Update Manager deploys the fix. Re-run the assessment. Close the finding only when the vulnerable package is gone.

## Validation and telemetry

**Logs that prove the control ran**

- Activity Log: control-plane writes (`Microsoft.Authorization/policyAssignments/write`, `Microsoft.Security/pricings/write`, Key Vault management). Retained in the portal for 90 days. Diagnostic settings extend that.
- `securityresources` in Azure Resource Graph: assessments and sub-assessments. `properties.status.code` is Healthy, Unhealthy, or NotApplicable.
- SecurityAlert in the Log Analytics workspace, after Defender continuous export or the Sentinel connector.
- Sentinel: the SecurityInsights solution on the workspace, then analytics rules and incidents.
- Azure Firewall diagnostic logs (AzureFirewallApplicationRule, AzureFirewallNetworkRule, and the IDPS log on Premium) once you enable them. They are off until a diagnostic setting exists.
- Key Vault diagnostic logs for secret access. Management-plane Activity Log does not show data-plane reads.

**Presence checks**

Defender plans:

```bash
az security pricing list --query "[].{name:name, tier:pricingTier}" -o table
```

`Standard` means the paid plan is on. `Free` means only foundational CSPM for that resource type.

Policy assignments (enforcement mode Default means the effect is on; DoNotEnforce is a dry run):

```bash
az policy assignment list --query "[].{name:displayName, enforcement:enforcementMode}" -o table
```

Sentinel is present when the workspace carries the SecurityInsights solution:

```bash
az graph query -q "resources | where type =~ 'microsoft.operationsmanagement/solutions' | where name startswith 'SecurityInsights' | project name, resourceGroup"
```

Key Vault purge protection:

```bash
az keyvault show -n VAULT -g RG --query "{rbac:properties.enableRbacAuthorization, purge:properties.enablePurgeProtection, softDelete:properties.enableSoftDelete}"
```

Firewall SKU:

```bash
az network firewall show -g RG -n FW --query "{sku:sku.tier, threatIntel:threatIntelMode}"
```

**What "working" means**

- Configured: the plan tier is Standard, the Policy assignment enforcement mode is Default, the diagnostic setting exists.
- Effective for a vulnerability: the sub-assessment leaves Unhealthy after the patch, and Update Manager reports the machine compliant for that update.
- Effective for a guardrail: a denied deployment appears in the Activity Log (`status` Failed, Policy as the caller). An Audit effect that stays green while the bad configuration exists is not enforcement.
- Effective for detection: a SecurityAlert or a Sentinel incident for the technique you expected. No alert during a quiet week does not prove the rule works.

Field names on SecurityAlert differ by workspace schema. Check them against the table in your workspace before you alert on a column.

## Documentation and repositories

- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/overview)
- [Azure Firewall](https://learn.microsoft.com/en-us/azure/firewall/overview)
- [Azure DDoS Protection](https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview)
- [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)
- [Azure Update Manager](https://learn.microsoft.com/en-us/azure/update-manager/overview)
- [Defender EASM](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/overview)
- [Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)
- [Azure Private Link](https://learn.microsoft.com/en-us/azure/private-link/private-link-overview)
- [Azure Landing Zones](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/)

Plan-level telemetry and the KQL for assessments are on the [Defender for Cloud tool page](/tools/microsoft-defender-for-cloud.md). Identity is on the [Entra ID tool page](/tools/entra-id.md).

## Current state

Checked against Microsoft Learn page titles in October 2026. SKU names for DDoS Protection and Firewall, and which Defender plan includes Update Manager, have changed before and will change again. Read the pricing page for the service you enable. This page does not claim a feature is in a given plan unless the Defender for Cloud page already records it.
