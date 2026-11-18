# Slide plan: Cloud Hopper / APT10

- Study: case-studies/CLOUD_HOPPER_APT10.md
- Cover title: Cloud Hopper / APT10 / Provider access, customer exposure
- Subtitle: The MSP supply-chain espionage campaign disclosed in 2017, with provider exposure, customer access and verified theft kept as separate findings.
- Published: 18 November 2026
- Notes: The cover frames a delegated-access espionage case where provider compromise reached customers, and keeps attribution and theft claims bounded.

## EXECUTIVE SUMMARY | Delegated access becomes shared exposure
- A managed-service provider administers systems for many customers, so the customer's security boundary includes the provider's identities, tools and practices.
- The public record describes espionage through MSPs and their customers, followed by government attribution and criminal charges.
- Provider compromise can create customer exposure, but exposure, access and verified theft stay different findings.
- Recovery means restoring the delegated trust relationship, not only cleaning the host where the first alert appeared.
Caption: Evidence grade: Reported
Notes: This sets the delegated-access thesis and signals that scope discipline governs every later claim.

## SCOPE | Five sources, five different jobs
- The case centers on 2016 to 2018, when Cloud Hopper became publicly documented and attributed; earlier APT10 activity is context, not a reason to relabel every operation.
- Research reports describe observations and assessments; a government announcement records an official judgment; an indictment contains allegations.
- The report and technical annex cover more than the MSP campaign, including directly targeted Japanese organizations.
- No provider systems, customer records, stolen data or malware samples were accessed for this study.
Caption: Evidence grade: Confirmed (publication facts)
Notes: Naming each source's purpose prevents a reader from treating an assessment, a judgment and an allegation as one kind of proof.

## HISTORICAL RECORD | The record in five bounded accounts
The reviewed sources each establish something specific, with its own limit.

| Account | Source | What it establishes | Limit on interpretation |
|---|---|---|---|
| April 2017 research | PwC UK & BAE | Provider access and shared credentials as paths to customers | Visible activity is only part of the operations |
| Technical annex | PwC UK & BAE | Foothold vs sustained-access tool categories, two campaigns | Not every listed tool appeared at each victim |
| UK attribution | NCSC, 20 Dec 2018 | APT10 responsible since at least 2016 | Dated official assessment, not reproduced here |
| US charges | DOJ, 20 Dec 2018 | MSP theft plus broader technology theft | Allegations; defendants presumed innocent |
| Indictment | US v Zhu Hua, Zhang Shilong | MSP campaign beginning at least around 2014 | Charging allegations with a defined legal source |
Caption: Evidence grade: Confirmed (publication), Reported (assessments)
Notes: The table keeps each source's contribution and its ceiling together so neither is dropped in later slides.

## TIMELINE | Three clocks: operation, publication, attribution
A public date is not automatically a first-compromise date or an eradication date.

| Period or date | Record | Limit on interpretation |
|---|---|---|
| Earlier than 2016 | Research and charging materials discuss preceding activity | Not every earlier APT10 operation is Cloud Hopper |
| 2016 to 2017 | Research describes increased scale and MSP-focused activity | Visibility is incomplete, not a census of customers |
| April 2017 | Main report and technical annex published | Annex scope includes more than one campaign |
| 20 December 2018 | UK attribution announcement | Official assessment keeps its source and qualification |
| 20 December 2018 | US charges announced | Allegations are not convictions; wider counts need their scope |
Caption: Evidence grade: Confirmed (dates), Reported (scope)
Notes: Separating the activity clock, the investigation clock and the publication clock answers a customer asking about a specific contract period.

## ATTRIBUTION | Layered, not a single verdict
The sources attribute the campaign in different forms that should not be merged.

| Evidence form | Source | What it is | Weight to keep |
|---|---|---|---|
| Research assessment | PwC & BAE, April 2017 | Observations plus analyst assessment | Seen activity distinguished from assessed activity |
| Government attribution | UK NCSC, December 2018 | Official judgment with stated confidence | Not independently reproduced by this study |
| Criminal allegation | US indictment, December 2018 | Charges tied to a named state bureau | Not a conviction; no present disposition claimed |
Caption: Evidence grade: Reported (assessment and attribution), allegations noted
Notes: APT10 aliases Stone Panda and menuPass belong to the attribution layer, not to the technical root facts.

## RISK MODEL | Delegation extends your trust boundary
- An MSP relationship delegates capability: accounts, remote-management software, support infrastructure, automation and access to backups become part of the customer's administrative system.
- The consequential question is not whether a provider can be compromised, but what a compromise of one provider component would allow elsewhere.
- Analysis should start with delegated tasks, not supplier names: what can the provider do, which identities permit it, who else shares the dependency, who can revoke it.
- A product inventory is insufficient; the security property belongs to the whole service design, not the brand of a tool.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: This reframes third-party risk as an inspectable trust relationship the people running the service can test.

## MISREADING | Not a cloud-platform escape
- The campaign name can suggest a hypervisor exploit or a tenant escape; the reviewed material centers on managed-service access and abuse of trusted relationships.
- This study does not claim a cloud platform's underlying isolation mechanism was the central entry route.
- The delegation sits between two assumptions: a customer trusting the provider connection by definition, a provider treating its support systems as outside customer scope.
- The same concentration of administrative capability exists for internal shared-services teams and systems integrators, so the lesson is broader than a sourcing decision.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: Correcting the name's implication keeps the audience focused on trusted-access abuse rather than a platform vulnerability.

## TENANT SEPARATION | Separation includes identity and operations
- Network segmentation helps, but a shared credential with authority across environments can undermine an otherwise sensible topology.
- A tenant-boundary review should map every administrative identity for the service: named human accounts, service accounts, emergency access and automation, each with its task and scope.
- Operations matter because exceptions accumulate: emergency access outlives the outage, a temporary shared account becomes normal at shift handover.
- Customers need enough visibility to judge their own exposure without demanding another client's confidential data.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: Identity and operating practice, not just topology, decide whether one customer's authority can reach another's work.

## FINDINGS | Exposure, access and theft are separate
Left: What each finding means
- Potential exposure: a trust path could be reached.
- Observed access: a successful connection is evidenced.
- Data involvement: specific records assessed with their evidence and uncertainty.
Right: What a finding does not mean
- Exposure alone does not prove theft.
- A broad provider account does not prove every tenant lost data.
- No familiar indicator is not a definitive no-impact claim.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: A customer-impact matrix with separate fields keeps a notice honest about what is known and what is still open.

## EVIDENCE | Independent records, joint containment
- A customer should not depend entirely on the possibly affected provider environment to understand its own exposure; a single administrative failure should not erase every investigative record.
- A logging agreement should define what events the customer can obtain, how long they remain, who can preserve them, and how timestamps and identifiers correlate.
- When a support path becomes suspect, a joint-containment record names the affected capability, the risk of continued access, the consequence of restriction and the approved alternative.
- A global announcement of complete containment is premature while some customer boundaries remain unresolved.
Caption: Evidence grade: Inferred (analysis), Demonstrated (tabletop)
Notes: Independent evidence and a named decision structure let the parties reduce risk without leaving a customer unmanaged.

## RECOVERY | Rebuild the delegated trust relationship
- Cleaning an infected host does not restore confidence in every account, tool and connection that supported the service.
- An acceptance process pairs a provider evidence package (scope, remediation, validation, remaining limits) with a customer acceptance decision against the service's requirements.
- The acceptance decision can be bounded: a restricted capability resumes while other controls hold, with a named owner and review condition.
- After access resumes, monitor for both security recurrence and functional problems, and review temporary credentials and emergency exceptions.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: Recovery is an authorization decision about the relationship, not only technical cleanup of one machine.

## KEY FACTS | Dated facts, kept traceable
Stat: 2017 | April PwC UK and BAE report
Stat: 2018 | 20 Dec UK and US actions
Stat: 2 | defendants named in the indictment
Stat: 45+ | US-charged firms, a wider count
- The 45+ figure spans multiple campaigns over a longer period and is not a count of Cloud Hopper MSP customers.
- The UK said APT10 was responsible since at least 2016; the indictment alleges an MSP campaign from at least around 2014, and both formulations should be preserved.
Caption: Evidence grade: Confirmed (publication facts)
Notes: These numbers stay tied to their original scope so the deck never invents a single global loss figure.

## WORKSHEET | A provider-customer evidence worksheet
This original planning worksheet makes the evidence needed for a consequential decision explicit.

| Question | Evidence to request | Overstatement to avoid |
|---|---|---|
| What authority crosses the boundary? | Approved task and identity map | A contract alone proves technical separation |
| Can one customer affect another? | Bounded tenant-separation assurance | Different network labels prove full independence |
| Was this support action authorized? | Task context linked to access records | A successful login proves legitimate intent |
| Which customers may be affected? | Impact matrix with scope and uncertainty | Every reachable customer suffered confirmed theft |
| What permits normal access to resume? | Provider evidence and customer acceptance | One cleaned host proves the relationship is trusted |
Caption: Evidence grade: Demonstrated (planning worksheet)
Notes: It certifies no provider; it names the questions whose answers a procurement or incident decision can actually test.
