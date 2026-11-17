# NotPetya 2017: A Trusted Update Becomes a Destructive Outage

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Malware Analysis Reference](/MALWARE_ANALYSIS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Incident responders, identity and endpoint engineers, supply-chain risk teams and business-continuity leaders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 29 min (6,611 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 NotPetya outbreak, you need to separate a trusted update path from network propagation or technical recovery from service restoration, or you are reading its financial and attribution record carefully

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the attack had more than one beginning](#part-1-the-attack-had-more-than-one-beginning), [Part 8: the defender and vulnerability-management view](#part-8-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md), [Bad Rabbit, 2017](/case-studies/BAD_RABBIT_2017.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

On 27 June 2017, NotPetya turned a software-distribution relationship into a destructive international incident. Microsoft observed the legitimate M.E.Doc updater initiating malicious execution in a subset of infections [1]. Subsequent research connected compromised application modules with manipulation of the supplier's update infrastructure [8][10]. The initial foothold and the later spread were different problems. Inside a network, the malware could use credentials and administrative facilities as well as vulnerable SMB services [2][4].

The visible demand for money did not establish a functioning recovery business. Kaspersky found that the disk ransom screen's installation identifier could not convey the information needed by the expected decryption mechanism [3]. Later forensic research demonstrated recovery possibilities for particular disk states, with substantial limitations [17][18]. Both findings belong in the history: payment was not a validated restoration path, but a universal claim that nothing could ever be recovered is also too strong.

The effects outlasted the visible outbreak. Company disclosures described lost business, restoration expense and manufacturing disruption, with different periods and accounting measures [5][9][12][13]. In February 2018 the UK attributed the operation to the Russian military. U.S. prosecutors announced charges against six GRU officers in October 2020 [6][7]. Attribution assessments, allegations and laboratory observations must not be collapsed into a single undifferentiated claim of proof.

### Key facts at a glance

| Question | Bounded answer |
|---|---|
| What happened? | A destructive June 2017 outbreak associated with a compromised software-update path, followed by network propagation [1][2][10]. |
| Was this simply another missing-patch incident? | No. Exploitation and credential-enabled administration were separate propagation mechanisms [2][4]. |
| Did all affected organizations necessarily run M.E.Doc? | This study does not establish that. Initial delivery and subsequent spread require separate evidence. |
| Did the ransom screen prove payment would work? | No. Published analysis identified a broken disk-key recovery relationship [3]. |
| Did later research establish universal recoverability? | No. Recovery research was conditional and did not validate every affected device or file [17][18]. |
| Who attributed the operation? | The UK made a high-confidence state attribution; U.S. prosecutors later alleged individual GRU involvement [6][7]. |
| What is the worldwide loss total? | Not independently established here. The financial examples below are deliberately not added together. |

### The five findings that matter most

1. **A trusted delivery path is not an assurance of safe behavior.** Approval of an application and approval of everything its updater can execute are different decisions.
2. **Patch state and administrative reach answer different questions.** Closing a vulnerable service path does not make an already-authorized credential harmless.
3. **The exposure window begins before the destruction window.** Supplier compromise, customer installation, malicious activation and discovery need distinct dates.
4. **Recovery is a chain of evidence, not a successful reboot.** Restored files, restored identity, functioning applications and reconciled business transactions are separate milestones.
5. **Precision improves the story.** Narrow claims about observed systems are more useful than global claims that the underlying evidence cannot support.

These findings are this study's interpretation of the cited record, not an independent forensic examination or a tested guarantee of protection.

## Scope and method

This investigation follows the supplier and endpoint evidence, selected financial disclosures, and public attribution through October 2020. Later ATT&CK pages provide a vocabulary for retrospective analysis, not a claim that their present identifiers existed in 2017. Historical vendor pages can contain later edits; the date in a page heading does not prove that every sentence was published on that day.

| Evidence label | Meaning here |
|---|---|
| **Observed research** | A security researcher reports telemetry, reverse engineering, laboratory work or incident-response findings. This study did not reproduce those observations. |
| **Company reporting** | A victim describes its own operations or financial effects. Estimates retain their reporting period and basis. |
| **Official assessment** | A government states an attribution or judgment. Its public statement is not its complete intelligence evidence. |
| **Alleged** | A charging document or prosecutor describes conduct. This is not a conviction or a present case-status determination. |
| **Inferred / proposed** | This study's analysis, mapping, exercise or recommendation, distinguished from the historical record. |

The aim is an accountable reconstruction, not an exhaustive malware manual. No sample was downloaded or executed; no victim network, supplier server or recovery tool was examined directly. No exploit instructions, runnable payloads or production detection rules are supplied. Financial reports were read for relevant incident passages, not audited in full. These limits matter most where a confident headline is easier to write than a defensible conclusion.

## Part 1: the attack had more than one beginning

### The earliest observed supplier changes

ESET examined M.E.Doc updates and identified a backdoored component in releases dated 14 April, 15 May and 22 June 2017. Some releases between those dates did not contain that component. Its analysis described collection of organization identifiers and application-held proxy and email credentials, with communication embedded in requests to the official update service [8] (**Observed research**).

That history changes the investigation's starting question. “Was this machine encrypted on 27 June?” is too narrow for determining whether a credential was exposed earlier. A machine can be in scope for one consequence and outside the observed population for another. The investigation should therefore distinguish at least three populations: systems that received a suspect update, systems where the backdoor executed, and systems affected by the destructive payload. None can automatically substitute for the others (**Inferred**).

A later clean version is useful evidence about the files present at that later time. It does not retroactively erase what an earlier component may have accessed. Conversely, a historical version match does not prove that every capability ran or every credential was taken. Version history, execution evidence and credential exposure deserve their own confidence fields rather than one affected/unaffected flag.

### What the supplier investigation added

Cisco's incident responders obtained access to M.E.Doc personnel, logs and code. Talos reported compromised administrator credentials and changes to the update server's NGINX configuration that proxied traffic to an attacker-controlled host. The overwritten configuration itself was not recovered; upstream error records helped reconstruct the routing. The team also found a web shell and corroborated the modified application component [10] (**Observed research**).

This is stronger supplier-side evidence than an endpoint process tree alone, but it still has boundaries. A log can establish a request or a configuration error without revealing every earlier action. A file timestamp is not automatically the intruder's arrival time. A missing historical log is not evidence of a clean period. These distinctions prevent an investigator from turning a useful reconstruction into an invented complete account (**Inferred**).

The supplier and application findings are complementary. One describes a component capable of receiving instructions; the other describes manipulation of the service with which it communicated. Neither should be reduced to the vague phrase “the website was hacked.” The relevant trust boundaries included software content, distribution infrastructure, administrative identities and customer execution.

### What the public supplier record does not close

The observed distribution window is not a remediation certificate. This study did not verify a complete supplier rebuild, complete credential rotation, a clean development environment or an independently validated later release. A restored configuration or an apparently normal update response would not, by itself, establish those outcomes. The supplier's incident-response assistance and a customer's safe return to using its software are different evidence questions.

### The legal record is another kind of evidence

The 2020 indictment alleges access to M.E.Doc code and malicious update changes on or about 14 April, 15 May and 21 June. It alleges a June 27 delivery interval of approximately 12:14–15:31 Moscow time and traffic rerouting to a France-based server [19, paragraphs 34–38] (**Alleged**).

The June 21 allegation and June 22 researcher release date are retained rather than silently normalized. Modification, publication, download and observation can have different timestamps. The public records reviewed here do not resolve every date boundary. That is an uncertainty to record, not a reason to select whichever date makes a cleaner graphic.

## Part 2: a chronology with explicit clocks

The table separates incident dates from publication dates. Times are reproduced in the source's stated zone; no source is treated as a global clock for every victim.

| Date or interval | What the record supports | Interpretation limit |
|---|---|---|
| 14 March 2017 | Microsoft publishes MS17-010 [14]. | Patch availability is not evidence of installation on a specific asset. |
| April–June 2017 | Backdoored M.E.Doc releases identified [8]. | Not a complete supplier-intrusion timeline. |
| 27 June, 09:11:59–12:31:12 UTC | Talos describes update-server error-log bounds correlated with its endpoint observations [10]. | Its observed delivery interval, not the end of all internal propagation. |
| 27 June, around 10:12 UTC | FireEye reports observed lateral movement in victim networks [4]. | A downstream observation, not necessarily initial entry. |
| 27 June, around 10:30 GMT | Microsoft observes malicious execution by the updater in its telemetry [1]. | A subset of observed infections, not the first infection worldwide. |
| 28 June 2017 | Kaspersky publishes the disk-identifier analysis [3]. | A technical finding about the analyzed mechanism. |
| 4–5 July 2017 | ESET and Talos publish deeper supplier-path findings [8][10]. | Later reconstruction, not knowledge every responder had on June 27. |
| 23 August and 17 October 2017 | CrowdStrike publishes recovery research [17][18]. | Later research does not establish an immediately available June recovery route. |
| 7 November 2017 | Maersk's Q3 report quantifies profitability impact [5]. | A financial reporting milestone. |
| 15 February 2018 | UK attribution statement [6]. | Official assessment. |
| October 2020 | U.S. indictment and announcement [7][19]. | Allegations, not a trial outcome. |

The apparent 10:12/10:30 conflict disappears once the measured event and observed population are retained. The earlier record concerns lateral activity seen by one team; the later record concerns updater execution seen by another. There is no basis for assuming the first machine visible to a researcher was the first machine infected (**Inferred**).

Nor does a delivery service returning to normal imply that the danger ended. A payload already inside an organization does not need a new supplier download for every subsequent step. In an incident record, use separate fields for the last observed supplier delivery, last internal propagation, containment confirmation and service restoration. That prevents a narrow external window from prematurely closing an internal hunt.

A useful timeline also records when a conclusion became available. The July supplier investigation can inform a retrospective explanation without being attributed to the first hour of response. Good history preserves the uncertainty responders faced; otherwise it teaches hindsight rather than decision-making.

## Part 3: from one endpoint to an enterprise problem

### A foothold is not the same thing as its reach

The M.E.Doc evidence explains an initial execution route. It does not independently explain each remote system reached afterward. Those systems may have had different patch states, privileges and relationships. The analytical task is to reconstruct transitions: which system could contact another, which identity could authenticate, which action was authorized, and which executable actually ran (**Inferred**).

Think of the enterprise as a set of permitted relationships rather than a flat list of machines. A regional application may have a small user base yet sit on a workstation where a widely privileged account has recently operated. A patched server may still accept administrative activity from that identity. A separate business unit may share the same management infrastructure. These are illustrative failure paths, not asserted configurations of a named victim.

This model explains why an inventory-only response is incomplete. Knowing where the supplier's software is installed is necessary for scoping delivery. Knowing where those installations can administer other systems is necessary for scoping consequences. The two inventories overlap but are not interchangeable.

### Discovery and credentials

Microsoft's October analysis describes network discovery, attempts to reach administrative shares, and authentication using the current context or recovered credentials. Remote execution could follow successful access. Its laboratory observations included specific limits on which recovered users were tried, so the report should not be rewritten as a claim that every credential in memory was necessarily used [2] (**Observed research**).

Talos likewise described several credential sources and cautioned that the credential-recovery component resembled Mimikatz without being exactly the standard tool. Its contemporary analysis did not identify an external scanning component comparable to the one it discussed for WannaCry [11] (**Observed research**).

For a defender, tool naming is less important than authority. An alert labeled “credential dumping” should lead to questions about the process, the accessed material, the account's reach and subsequent authentication. A filename match cannot establish the full sequence. Equally, a different filename does not make the behavior benign. Investigation should use relationships among events rather than treating a familiar tool name as either a conviction or an exemption (**Inferred**).

### Administration became an execution route

The published record identifies administrative shares, PsExec and WMI as part of propagation [2][4]. These mechanisms can support legitimate operations. Their presence alone is therefore a poor binary classifier. The distinguishing context includes the originating system, account, timing, target set and payload provenance (**Inferred**).

Consider two superficially similar observations: a managed deployment server starts a documented maintenance job on an approved set of endpoints, while an accounting workstation initiates rapid administrative activity across unfamiliar systems. Both may contain recognized utilities and successful authentication. The second demands investigation because its role and relationships differ, not because the utility has become intrinsically malicious.

This also limits simplistic recommendations to “block the tool.” Removing one executable may leave equivalent administrative mechanisms available. A better review asks why a business workstation can initiate that action, whether the identity should possess the required rights, and whether the management path can be constrained without breaking necessary service. Those are architectural questions, not merely signature questions.

### An early hypothesis that should not survive unqualified

FireEye explicitly rejected a reported connection to a CVE-2017-0199 Office-document campaign after finding no correlation with the NotPetya victims it examined [4]. The correction matters: a generic phishing-origin story would direct attention away from the supplier evidence. It does not prove that no affected user ever received malicious email; it rejects that specific proposed explanation for this outbreak.

### Exploitation remained relevant

MS17-010 addressed multiple SMBv1 vulnerabilities; Microsoft published it on 14 March 2017 [14]. FireEye's incident research identified modified EternalBlue and EternalRomance use alongside credential-enabled spread [4]. The correct conclusion is not that patching was irrelevant. It is that one control addressed one class of transition.

In an authorized validation exercise, test exploit exposure and administrative access independently. A successful patch check closes the first question only to the extent of its coverage and freshness. An account-access test closes the second only for the identities and routes actually examined. Reporting both results under a single “NotPetya protected” label hides the residual risk (**Proposed analysis**).

The same principle applies to segmentation. A diagram with separate colors is not evidence of isolation if the same credentials and management services span the boundaries. Conversely, not every cross-segment connection is an unacceptable risk. The review must connect a required business function to an explicitly permitted path and an accountable owner.

## Part 4: destruction, ransom presentation and recoverability

### The visible story was not the full mechanism

CrowdStrike's June analysis distinguishes file encryption from boot-stage handling of disk structures. It describes AES-based file encryption, RSA protection of associated key material, and separate MFT processing using a Salsa20 implementation. It also describes reboot behavior and log clearing [20] (**Observed research**).

These distinctions matter because “the disk was encrypted” can conceal several states. A device may have lost bootability, file-system metadata, access to selected files or some combination. A diagnosis that treats those conditions as identical can produce the wrong recovery expectation. It can also confuse an algorithm name with a recovery result: the presence of recognizable cryptography does not establish whether all required keys or metadata survived (**Inferred**).

The MBR, MFT and individual files are not interchangeable terms. The MBR relates to boot structures; the MFT records essential NTFS file-system information. A summary should not say that a single RSA operation encrypted everything simply because an RSA key appears in a technical report. Component-level language is less dramatic but more useful.

### Why paying was not a demonstrated solution

Kaspersky's June 28 analysis found that the displayed disk installation ID was random rather than a container for the expected recovery information. The researchers concluded that the attacker could not use that identifier to recover the disk through the described mechanism [3]. This is a technical reason not to infer recoverability from a payment demand.

That statement should remain tied to the analyzed mechanism. It does not demonstrate that every separate file-encryption path had identical key handling, that all storage was overwritten, or that no independent forensic technique could help. It also does not require accepting every claim made by the malicious interface. A ransom screen is attacker-controlled content, not a reliable service contract or an authoritative damage assessment (**Inferred**).

Operational decisions should be made from trustworthy evidence about the machine's state, available backups and service requirements. A fictional recovery promise can consume scarce time even without a payment. The incident commander should separate any legal or commercial consideration of demands from technical decisions about preserving evidence and restoring service. This study does not provide transaction or legal advice.

### Later recovery research changes the wording, not the attribution

In August 2017, CrowdStrike described exploiting weaknesses in the malware's specific Salsa20 implementation to recover MFT information. Its evaluation used a Windows XP analysis VM and reported recovery results against known ground truth. The authors explicitly distinguished an implementation weakness from a general break of Salsa20 [17] (**Observed research**).

Its October follow-up reported broader recovery on a synthetic test disk and several real-world drives. It also warned that some files could have been encrypted twice, that real-world integrity checks lacked ground truth, and that manual intervention remained necessary; the broader tool was not publicly released at that point [18] (**Observed research**).

The defensible lesson is neither “all data was permanently gone” nor “a universal decryptor existed.” A particular recovery method can work for particular data structures and states without restoring every application file or producing a trusted running system. Laboratory success, field recovery and enterprise restoration are different claims.

This also explains why technical intent and accidental weakness can coexist. Malware may be designed to cause destruction and still contain implementation errors that permit partial recovery. Discovering such an error does not convert the incident into ordinary, reliable ransomware. It changes what a qualified recovery team may investigate, subject to evidence preservation and validation (**Inferred**).

### Recovery evidence must remain separate from clean-operation evidence

Suppose a specialist extracts a usable database file from an affected drive. That is valuable, but it does not establish that the database is transactionally consistent, that its credentials are safe, or that the original operating system should be reconnected. The recovery record should identify what was recovered, the method, verification performed and unresolved uncertainty.

For critical data, retain an untouched source image where feasible and perform analysis on copies under an approved forensic process. Compare recovered records with independent business evidence, not only whether the file opens. A shipping manifest, a payment ledger and a clinical application each require different owner-led checks. These are proposed safeguards, not claims about procedures used by the named victims.

## Part 5: impact measured on different clocks

### What organizations actually reported while recovering

Contemporaneous notices show why “contained,” “open” and “restored” were not synonyms. These are the companies' descriptions at the time, not independently reconstructed restoration logs.

**Maersk, 28 June.** The company reported shutting systems down to contain the incident and working on a technical recovery plan. It said vessels remained maneuverable and able to communicate, crews were safe, and several business units were not operationally affected, while some APM Terminals ports were affected [21] (**Company reporting**). This is a materially different picture from a claim that every ship or every Maersk business stopped operating.

**Maersk's subsequent reconstruction.** Its Q2 report identifies precautionary shutdowns at Maersk Line, APM Terminals and Damco because of global interfaces. It dates containment to June 28 and the ability to accept bookings from existing customers to June 29. It describes more normalized operations during July 3–9 and a systematic return of users and applications across 500 locations [22] (**Company reporting**). Those are staged milestones, not a single instant when the whole business was back to its prior state.

The sequence separates three kinds of action: restricting the affected environment, reintroducing a customer function, and expanding the restored service population. The report does not provide enough technical detail to certify the effectiveness of every containment measure or the completeness of every recovery check. Its statement that Windows and antivirus updates did not prevent this incident should not be generalized into a claim that patching or endpoint protection cannot help [22] (**Inferred**).

**TNT, 30 June and 6 July.** Its notices described continuing pickup/delivery and intra-European linehaul, using both TNT and FedEx Express networks as part of contingency arrangements. By July 6, facilities were open and most services available, but some customers still faced delays and limited package information [23] (**Company reporting**). Physical operations and information availability were recovering on different schedules.

**TNT, 17 July.** FedEx reported widespread service and invoicing delays and manual processes supporting a significant share of operations and customer service. It could not yet estimate full restoration and warned that complete recovery of systems and critical data might not be possible. It also said other FedEx companies were unaffected and that no insurance in place covered this attack [24] (**Company reporting**).

Read alongside the later annual report, the July warning is not evidence that the later restoration statement was false. One describes unresolved risk during recovery; the other reports the later outcome. An accurate history preserves both rather than retrospectively giving responders certainty they did not have. The July statement that no loss to third parties was known also concerns disclosure/exfiltration knowledge, not a guarantee that internally stored data was undamaged (**Inferred**).

**Merck, 28 July.** Its results announcement said packaging was largely restored, formulation partly restored, and active-pharmaceutical-ingredient operations still being restored without bulk production yet resumed. External manufacturing was unaffected, and the company continued shipping product while anticipating some order delays [25] (**Company reporting**). “Manufacturing recovery” therefore covered multiple processes at different stages, not one binary switch.

These accounts show concrete continuity measures and concrete uncertainty. They do not reveal every recovery dependency, credential action or backup decision. This study deliberately does not fill those gaps with commonly repeated anecdotes whose original supporting records were not checked.

### A compact impact register

These rows are different measurements, not components of a sum.

| Entity / record | Period and measure | Reported amount | Important boundary |
|---|---|---|---|
| Maersk Q3 report [5] | Profitability effect from June attack, largely Q3 | USD 250–300 million | Not ransom or hardware-only expense. |
| FedEx FY2018 [9] | First-half fiscal-year negative results impact | USD 400 million | Includes TNT; overlaps DOJ victim grouping. |
| Merck FY2017 [12] | Adverse sales effect | About USD 260 million | Different measure from expense. |
| Merck FY2017 [12] | Manufacturing/remediation expense | About USD 285 million | Net of about USD 45 million insurance. |
| Merck FY2018 [13] | Residual sales effect | About USD 150 million | Later outcome, not additive to earlier forecast for the same period. |
| DOJ 2020 [7] | Three-victim loss subtotal | Nearly USD 1 billion | Not worldwide total; no independent audit here. |

### Maersk: profitability, not a ransom bill

Maersk's Q3 2017 report put the June attack's effect on profitability at USD 250–300 million, largely associated with Maersk Line in Q3. Its guidance connected much of the impact with temporarily lost business in July and August [5] (**Company reporting**).

That measure is not a payment to the attacker, a computer replacement invoice or a count of permanently lost customers. Nor should unrelated impairments elsewhere in the same report be folded into it. A sound incident summary preserves the company's chosen measure instead of converting every large nearby number into “cyber losses” (**Inferred**).

For continuity planning, the important implication is that restoring infrastructure does not instantly restore commercial activity. Customers may have rerouted work, backlogs may remain, and staff may need to reconcile manual processes. These are planning considerations, not a claim that each occurred in exactly the same way at Maersk.

### TNT Express: services, systems and financial results

FedEx's fiscal 2018 annual report dates the TNT incident to 27 June 2017. It says substantially all services were restored during fiscal Q1, with all critical operational systems restored by fiscal Q2. It estimates a USD 400 million negative effect during the first half of that fiscal year, primarily reduced shipments and restoration costs [9] (**Company reporting**).

The fiscal label does not relocate the attack to calendar 2018. The service milestone does not mean every supporting system had already recovered. The financial effect does not become a new incident merely because it appears in a later filing. Those distinctions make the account more accurate and more useful to a continuity team (**Inferred**).

A recovery dashboard should therefore avoid one green light for the entire enterprise. It should distinguish customer-facing availability, normal capacity, supporting-system restoration, data reconciliation and financial stabilization. The distinction is especially important when teams have reopened services with temporary workarounds that cannot be sustained indefinitely.

### Merck: separate actual effects from forecasts

Merck's 2017 Form 10-K describes worldwide operational disruption, while noting external manufacturing was not affected. It reports approximately USD 260 million in adverse sales effects and USD 285 million of manufacturing/remediation expenses, the latter net of about USD 45 million in insurance recoveries. It also explains that production interruption and higher demand contributed to borrowing vaccine doses from a CDC stockpile [12] (**Company reporting**).

Its next annual report records approximately USD 150 million in 2018 sales effects, compared with the earlier forecast of approximately USD 200 million [12][13]. A forecast and its subsequent reported outcome are not additive losses. Nor does an expense measure net of insurance have the same basis as gross operational damage.

The manufacturing account warrants precision. It supports a conclusion that a cyber incident affected production and supply planning. It does not, without additional evidence, establish a patient injury count, nationwide shortage, product-quality failure or universal shutdown. Those are consequential claims requiring their own sources, not rhetorical extensions of the cost figures (**Inferred**).

### Healthcare consequences do not fit neatly into a dollar total

The DOJ announcement describes Heritage Valley losing access to important clinical systems for approximately a week and administrative systems for almost a month. It also reports nearly USD 1 billion in combined losses for three victims identified in the indictment, including TNT [7] (**Prosecutor's account**).

The affected services matter even when the financial estimate is incomplete. At the same time, loss of a computer service must not be transformed into an unsupported claim of a specific death, treatment failure or number of harmed patients. This study does not assert those outcomes.

Do not add the DOJ subtotal to the FedEx figure: TNT is present in both. More generally, losses reported by a parent, subsidiary, insurer and prosecutor may describe overlapping economic effects. A table with citations is not automatically a sound aggregation method (**Inferred**).

### An accounting discipline for incident histories

For every number, record the entity, currency, period, measure, source date and whether it is forecast, estimate or recorded expense. Record whether insurance is included and whether the figure is a subtotal already contained elsewhere. If any of those fields is unknown, show the uncertainty rather than silently treating all figures as comparable.

This discipline can change the apparent story. A reduction in forecast impact may reflect improved information rather than an earlier false statement. A later expense may be part of recovery rather than a new attack. A large operational disruption may be described as financially immaterial relative to a very large company without being trivial to the people affected. Materiality, severity and public importance are not synonyms (**Proposed analytical framework**).

## Part 6: who and why, without overstating the evidence

The UK's February 2018 statement attributes NotPetya to the Russian military with an almost-certain assessment. It describes an operation aimed principally at disruption in Ukrainian sectors, whose spread reached other countries [6] (**Official assessment**).

The 2020 DOJ announcement identifies six alleged GRU officers and the indictment describes Unit 74455 involvement [7][19] (**Alleged**). This study does not establish a conviction, trial outcome or present procedural status. An indictment is a primary legal record of accusations; treating it as a verdict would misstate its function.

Three questions should remain distinct: who created or operated the capability, what the operation was intended to achieve, and how each individual victim was reached. A government attribution can address the first two without publishing a complete infection chain for every victim. A victim's process logs can address the third without identifying the state behind it (**Inferred**).

Similarly, an actor label is not a universal behavioral guarantee. Relationships among research names, military units and campaign clusters are useful for organizing evidence, but they do not prove that every incident assigned a similar label shares the same people, infrastructure or method. Keep the source and confidence of each attribution attached to the particular operation.

For most defenders, immediate containment does not depend on resolving every attribution question. A dangerous administrative path can be restricted, a compromised credential replaced and a business service recovered while strategic attribution remains under review. That is not indifference to accountability; it is a separation of operational decisions from questions requiring different evidence.

## Part 7: MITRE ATT&CK as an analytical index

The following selected mappings organize the record. They do not prove that a technique occurred on every victim system, that every mapping was made in 2017, or that a mapped control has been tested. MITRE's software entry is S0368; the supply-chain technique page separately includes the M.E.Doc/NotPetya example [15][16].

| Observed behavior | Selected mapping | Evidence and boundary |
|---|---|---|
| Manipulated software/update distribution | T1195.002, Compromise Software Supply Chain | Supplier evidence [8][10]; classification cross-check [16]. |
| Credential extraction from LSASS | T1003.001, OS Credential Dumping: LSASS Memory | Technical analysis [20]; cross-check [15]. |
| Administrative-share propagation | T1021.002, SMB/Windows Admin Shares | Network analysis [2]; cross-check [15]. |
| WMI-based execution | T1047, Windows Management Instrumentation | Incident research [4]; cross-check [15]. |
| SMB exploitation | T1210, Exploitation of Remote Services | Incident research [4]; cross-check [15]. |
| Encryption affecting availability | T1486, Data Encrypted for Impact | Technical analyses [3][20]; cross-check [15]. |

This is an analytical selection, not a complete Navigator layer. The component and host matter: a technique supported for the destructive payload should not automatically be attributed to the earlier supplier backdoor, or vice versa. Likewise, an enterprise technique should not be relabeled an industrial-control-system technique merely because a manufacturer was affected.

Mappings are most useful when linked to an evidence question. For administrative shares: which source, identity and destination were involved? For credential extraction: what access occurred, and what could the resulting identity reach? For encryption: what object became unavailable and what independent recovery evidence exists? The identifier is a navigation aid; the event evidence does the investigative work (**Inferred**).

A detection-coverage percentage would require substantially more than this table. It would need an explicit test population, telemetry prerequisites, expected behavior, outcomes and failure analysis. Six selected mappings do not imply six independent protection layers, and six green checks do not establish that the chain cannot complete. Some detections may share a collector or administrative dependency that fails at the same time.

## Part 8: the defender and vulnerability-management view

The following are original, case-derived proposals, not assertions about configurations this study did not examine. They require environment-specific engineering and authorized validation.

### Inventory the update relationship

For each critical application, identify its owner, distribution channel, execution privilege, expected child processes and operational dependencies. Record whether updates are centrally staged or downloaded independently. Supplier assurance and local containment are separate workstreams: a signed release does not answer how signing authority is protected, while a constrained endpoint does not establish the supplier's integrity.

An exception should explain the business requirement and have an expiry or review trigger. Otherwise a temporary convenience can become a permanent administrative route. The useful output is not another software list but a record connecting a business function, its software authority and the systems it can affect.

### Test privilege and patching independently

Map administrative paths from business workstations into servers and management systems. Review reusable credentials and privileged sessions on endpoints that consume third-party software. The aim is to reduce unnecessary authority available from a compromised starting point, not merely to reduce an account count.

Keep patch installation and scan freshness separate from identity and administrative-access evidence. Report unresolved issues in each. Prioritize systems partly by the relationships they enable: an ordinary workstation with broad administrative reach can be more consequential than an isolated system with a higher vulnerability score.

### Prepare containment authority and its operational cost

Predefine who can pause an update channel, isolate a segment or disable an account. Record dependencies, fallbacks and rollback conditions. Blocking supplier delivery may not stop internal activity; disabling a shared identity may also disable restoration. The plan needs scoped options, not one universal shutdown instruction.

The incident team should know which evidence sources remain accessible when the ordinary network is unavailable. Record collection gaps and preserve the difference between not observing an event and ruling it out. A confidence statement without its sensor coverage is incomplete.

### Restore trust before scaling restoration

Establish a clean administrative path and known-good installation sources before using automation to rebuild widely. Record which identities were replaced or validated. Restore services in dependency order, with tests that reach the business boundary rather than stopping at a successful server login.

A shipping service should demonstrate an accepted and traceable shipment; a financial workflow should reconcile; a clinical workflow needs owner-defined access and integrity checks. Keep temporary workarounds, reduced capacity and unresolved uncertainty visible after reopening. A technically available service may still have substantial recovery work ahead.

## Part 9: an original tabletop and evidence exercise

This fictional exercise uses discussion and benign, authorized validation, not malware execution.

A finance endpoint installs an expected update, then initiates unusual administrative connections. Another business unit has current security updates but shares management infrastructure. A shipping workflow depends on an identity service responders may need to isolate. The supplier reports normal service, while internal alerts continue.

| Inject | Decision participants must justify |
|---|---|
| A legitimate maintenance job resembles suspicious activity | What context distinguishes authorized administration from the investigated chain? |
| A never-encrypted endpoint had an earlier suspect application version | Does it enter the credential-exposure investigation, and what evidence would narrow that scope? |
| A patched server accepted administrative activity | What can the patch dashboard establish, and what remains unresolved? |
| An urgent service depends on an evidence-bearing endpoint | Who weighs preservation against continuity, and which alternative supports both? |
| A recovered file opens but lacks a complete integrity guarantee | Which independent records and owner-led tests justify operational use? |
| No new alerts appear, but temporary workarounds remain | Which containment, restoration and residual-risk conditions support closure? |

Retain a timeline with time zones, a scope register separating delivery/execution/credentials/impact, a decision log, restoration tests and a financial register with overlap flags. Assign an owner to each unresolved item. Measure decision quality as well as speed: rapid isolation that removes recovery access and slow investigation that permits avoidable spread are both failures worth exposing in rehearsal.

## Conclusion

NotPetya is best understood as a chain of abused trust relationships with destructive consequences: trust in a software supplier, trust in an update service, trust granted to credentials, and trust among connected business systems. No single dashboard described that entire chain.

The lasting defensive lesson is to preserve boundaries in both architecture and analysis. Separate delivery from propagation, exploit exposure from administrative reach, technical recovery from service restoration, and official attribution from legal findings. Then require evidence at each transition. That is more demanding than a one-line lesson about patching or backups, but it is also a more faithful account of what this case can teach.

## Sources and reading limits

[1] Microsoft Security, 27 June 2017, [New ransomware, old techniques: Petya adds worm capabilities](https://www.microsoft.com/en-us/security/blog/2017/06/27/new-ransomware-old-techniques-petya-adds-worm-capabilities/). Delivery, propagation and encryption passages checked; updated historical page, not a frozen first-day snapshot.

[2] Microsoft Security, 3 October 2017, [Network technical analysis: NotPetya](https://www.microsoft.com/en-us/security/blog/2017/10/03/advanced-threat-analytics-security-research-network-technical-analysis-notpetya/). Main technical narrative checked; vendor laboratory/telemetry observations, not independent reproduction here.

[3] Kaspersky, 28 June 2017, [ExPetr/Petya/NotPetya is a Wiper, Not Ransomware](https://securelist.com/expetrpetyanotpetya-is-a-wiper-not-ransomware/78902/). Main encryption-identifier analysis checked; user comments are not evidence for this study.

[4] FireEye/Mandiant, 27 June 2017, updated 21 July, [Petya destructive malware variant](https://cloud.google.com/blog/topics/threat-intelligence/petya-ransomware-spreading-via-eternalblue-exploit/). Main incident observations and correction concerning an unrelated document campaign checked; published rule not executed.

[5] A.P. Moller - Maersk, 7 November 2017, [Interim Report Q3 2017](https://investor.maersk.com/static-files/1226cd7b-d1b4-4281-b42c-5f032b0e1595). Relevant printed pages 5 and 7 checked, not a complete financial audit.

[6] UK Foreign Office and NCSC, 15 February 2018, [NotPetya attribution statement](https://www.gov.uk/government/news/foreign-office-minister-condemns-russia-for-notpetya-attacks). Main statement and notes to editors checked; public assessment, not its underlying classified evidence.

[7] U.S. DOJ, 19 October 2020, [Six Russian GRU officers charged](https://www.justice.gov/archives/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and). Relevant allegations and victim-impact passages checked; no current court-status determination.

[8] Anton Cherepanov, ESET, 4 July 2017, [Analysis of TeleBots' cunning backdoor](https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/). Update chronology, data collection and explicit lack of supplier-server forensics checked.

[9] FedEx, [Fiscal 2018 Form 10-K](https://www.sec.gov/Archives/edgar/data/1048911/000156459018016877/fdx-10k_20180531.htm), printed page 53. Relevant restoration and impact passages checked; fiscal-year basis retained.

[10] David Maynor, Matt Olney and Yves Younan, Cisco Talos, 5 July 2017, [The MeDoc Connection](https://blog.talosintelligence.com/the-medoc-connection/). Supplier investigation, log-window and backdoor corroboration passages checked; missing April/May logs and overwritten configuration remain limitations.

[11] Cisco Talos, 27 June 2017, updated 6 July, [New Ransomware Variant Nyetya Compromises Systems Worldwide](https://blog.talosintelligence.com/worldwide-ransomware-variant/). Main propagation and credential sections checked; historical preliminary research, not a current protection assessment.

[12] Merck, filed 27 February 2018, [2017 Form 10-K](https://www.sec.gov/Archives/edgar/data/310158/000031015818000005/mrk1231201710k.htm). Cyberattack discussion, printed pages 37–38, and stockpile discussion checked; no clinical-outcome inference or complete audit.

[13] Merck, filed 27 February 2019, [2018 Form 10-K](https://www.sec.gov/Archives/edgar/data/310158/000031015819000014/mrk1231201810k.htm). Cyberattack and residual sales-impact passages checked; later reported effect distinguished from prior forecast.

[14] Microsoft, 14 March 2017, [MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010). Publication date, executive summary and affected-software table checked; no asset-specific patch verification.

[15] MITRE ATT&CK, [NotPetya, S0368](https://attack.mitre.org/software/S0368/). Selected Enterprise mapping entries checked on 14 November 2026; not a complete mapping audit or validation of every technical sentence.

[16] MITRE ATT&CK, [T1195.002: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/). Definition and Sandworm/NotPetya example checked on 14 November 2026; retrospective classification.

[17] Sebastian Eschweiler, CrowdStrike, 23 August 2017, [Decrypting NotPetya/Petya: Tools for Recovering Your MFT](https://www.crowdstrike.com/en-us/blog/decrypting-notpetya-tools-for-recovering-your-mft-after-an-attack/). Method, evaluation and limitations checked; no tool downloaded or run.

[18] Sebastian Eschweiler, CrowdStrike, 17 October 2017, [Full Decryption of Systems Encrypted by Petya/NotPetya](https://www.crowdstrike.com/en-us/blog/full-decryption-systems-encrypted-petya-notpetya/). Test-disk, real-world and conclusion sections checked; title is not adopted as a universal recovery guarantee.

[19] U.S. District Court, Western District of Pennsylvania, October 2020, [Unsealed indictment](https://www.justice.gov/d9/press-releases/attachments/2020/10/19/2020_10_19_unsealed_indictment_0.pdf). Opening and NotPetya paragraphs 31–38 checked; allegations, not findings after trial. Entire 50-page document not reviewed.

[20] Karan Sood and Shaun Hurley, CrowdStrike, 29 June 2017, [NotPetya Technical Analysis: File Encryption, MFT Encryption, Credential Theft](https://www.crowdstrike.com/en-us/blog/petrwrap-ransomware-technical-analysis-triple-threat-file-encryption-mft-encryption-credential-theft/). Main technical sections checked, including separate encryption paths, reboot behavior and anti-forensics; no independent sample analysis.

[21] A.P. Moller - Maersk, 28 June 2017, [Cyber attack update](https://investor.maersk.com/news-releases/news-release-details/cyber-attack-update). Full announcement body checked; current page chrome has a later date that is not the incident publication date.

[22] A.P. Moller - Maersk, 16 August 2017, [Interim Report Q2 2017](https://investor.maersk.com/static-files/7eee21c8-e825-46d2-bc62-dcd155d00e88). Cyber-attack section on printed page 6 checked, not the complete report.

[23] FedEx/TNT, 30 June and 6 July 2017, [TNT Operations Updates](https://newsroom.fedex.com/newsroom/global/tnt-operations-update). Both short updates checked; contemporaneous service status and uncertainty, not a complete forensic account.

[24] FedEx, 17 July 2017, [Additional disclosure on cyberattack affecting TNT Express](https://investors.fedex.com/news-and-events/investor-news/investor-news-details/2017/FedEx-Files-10-K-with-Additional-Disclosure-on-Cyber-Attack-Affecting-TNT-Express-Systems/default.aspx). Cyberattack disclosure section checked; risks and knowledge as of that date.

[25] Merck, 28 July 2017, [Second-quarter 2017 results](https://www.merck.com/news/merck-announces-second-quarter-2017-financial-results/). Financial Outlook paragraphs on operational restoration checked; unrelated product, clinical and financial claims not incorporated.
