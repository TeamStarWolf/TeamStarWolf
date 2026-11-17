# SMBGhost: Compression Arithmetic, Client Exposure and the 2020 Emergency Patch

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Windows platform and vulnerability-management owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,666 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2020-0796, you need to separate an affected SMB implementation from the whole protocol family or client exposure from server exposure, or you are distinguishing SMBGhost from SMBleed

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [6. Client exposure changed the mitigation problem](#_6-client-exposure-changed-the-mitigation-problem), [8. Crash, privilege escalation and remote execution](#_8-crash-privilege-escalation-and-remote-execution)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Network Attacks Reference](/NETWORK_ATTACKS_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- SMBGhost (CVE-2020-0796) was a Windows SMB 3.1.1 implementation vulnerability disclosed in March 2020. ([Executive assessment](#executive-assessment))
- The flaw crossed a trust boundary processing compressed network data before authentication, affecting both servers and connecting clients. ([Executive assessment](#executive-assessment))
- CERT/CC describes possible arbitrary code execution with SYSTEM privileges. ([Executive assessment](#executive-assessment))
- The lesson is distinctions summaries erase: a server workaround versus client protection, a crash versus code execution. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

SMBGhost, CVE-2020-0796, was a Windows SMB 3.1.1 implementation vulnerability disclosed in March 2020. Its significance was not simply that a file-sharing service could be attacked. The flaw crossed a trust boundary while processing compressed network data, before authentication, and affected both receiving servers and connecting clients. CERT/CC describes possible arbitrary code execution with SYSTEM privileges. That is a considerably different exposure model from a stolen password used to access an otherwise correctly implemented share. [1]

Microsoft released KB4551762 on March 12, 2020. The historical update identifies builds 18362.720 and 18363.720. Today the retained page marks that package expired and directs readers toward later security quality updates, so the original KB is evidence of the response milestone rather than a present-day deployment prescription. [2]

The strongest retrospective conclusion is about distinctions that incident summaries often erase: compressed size versus allocated size; a server workaround versus client protection; a crash versus code execution; an exploit demonstration versus an observed campaign; and a protocol version versus a particular implementation. The sources establish a serious vulnerability and evolving research, but they do not support inventing a single named victim, financial loss or global outbreak count.

## 1. Research boundaries

This study uses Microsoft research and servicing records, CERT/CC and CERT-EU advisories, original technical analysis retained by Trellix and Jamf, NHS Digital guidance, current Microsoft protocol documentation, and the official CISA catalog repository. Citations identify the particular records used. Technical research is discussed at the level of failure conditions and demonstrated outcomes, without reproducing packet construction, memory manipulation, exploit code or a procedure for attacking a system.

The interactive MSRC vulnerability record returned only a JavaScript requirement. The CISA June 5 alert could not be retrieved directly because it returned 403. Accordingly, this draft does not claim to have verified that alert's precise wording or infer a June attack count from secondary headlines. The official CISA catalog was readable through its cisagov repository. Current protocol documentation is labeled by its revision date rather than passed off as an untouched March 2020 specification.

An additional limitation is bibliographic: technical research now retained on successor-company websites may carry current branding around older work. This draft cites the retained pages and their displayed dates, not an unsupported claim that today's organization names were used in every original publication. Likewise, a page's initial date and its last-edited date may describe different bodies of content.

## 2. Disclosure and response chronology

CERT-EU records a March 10 Microsoft advisory, its own March 11 initial publication, and a March 13 revision incorporating the patch. Its affected-products list covers Windows 10 versions 1903 and 1909 across the listed architectures, plus Windows Server versions 1903 and 1909 in Server Core installations. This is narrower than every Windows system or every implementation of SMB. [3]

Synacktiv's March 12 page contains two chronological layers. Its original narrative gives March 9 for the advance-warning disclosure and initially says no fix exists. An appended Patch update explicitly records March 12 KB4551762 and analyzes the corrected code. Reading only the introduction would misrepresent the complete retained source. The source's March 9 statement still differs from the CERT-supported March 10 public date; this review does not independently resolve that discrepancy. [1,2,3,4]

Subsequent milestones changed what could responsibly be said about exploitation. A March 31 research publication demonstrated local privilege escalation. An April 6 Microsoft detection announcement addressed attempts against unpatched domain controllers. Microsoft's May 4 engineering account explained its discovery and technical root cause. June research described chaining a separate information-disclosure issue with SMBGhost. Each milestone answers a different question and should retain its own date. [5,6,7,8]

## 3. Affected implementation, not the whole protocol family

The name SMBGhost and references to SMBv3 can invite an excessively broad interpretation. A protocol is a shared language; a vulnerability exists in code implementing some portion of that language. An assessment based only on the presence of file sharing would miss the product and release boundaries. Conversely, a workstation is not automatically outside scope merely because it is not called a server.

The CERT-EU product list distinguishes Windows 10 from the relevant Windows Server Core releases. The retained Azure ATP article uses broader Windows Server 2019 wording. This study uses the explicit product list for historical scope instead of treating the detection article's shorthand as a substitute for a product advisory. Present-day applicability still requires the actual operating-system release and servicing state, not only a familiar marketing name. [3,6]

Original analysis retained by Trellix identifies separate server and client driver paths, srv2.sys and mrxsmb.sys, reaching related decompression processing. The researchers reported crashes in both directions. That evidence explains why a control applied to the server role could fail to address the client role on the same machine. [9]

The case-specific lesson is to model an endpoint by the network roles it performs during a transaction. A machine can accept file-sharing requests in one connection and initiate them in another. Asset labels such as desktop, file server or management host do not alone identify which parser will consume external data.

## 4. Compression introduced a size-consistency obligation

The archived March 12 technical analysis describes an allocation based on size and offset information from a compressed message, followed by decompression whose effective bounds could disagree with that allocation. In its patch comparison, the author identified checked addition and subtraction routines, including RtlULongAdd and RtlULongSub. These are concrete clues that arithmetic validation, not merely disabling a feature, was central to the repair. [9]

The engineering principle is precise: the amount of memory reserved must agree with the range of memory that subsequent parsing, copying and decompression can touch. A compressed representation has at least two sizes of interest, the encoded bytes received and the expanded data expected. An offset adds another relationship: where data begins relative to the received object. Validating one number independently cannot prove that all combinations remain within bounds.

Microsoft's May 4 account attributes the dangerous behavior to network-derived length and offset parsing. It describes both an out-of-bounds write associated with an overflowing size calculation and an out-of-bounds read associated with source-length handling. The error therefore should not be reduced to a vague statement that the compression algorithm itself was broken. [7]

These facts support a conceptual reconstruction, not a reproduction of exploitation. The receiver trusted arithmetic derived from external metadata at a boundary where the resulting sizes governed privileged memory operations. The repair needed those relationships to remain valid even when the input was inconsistent. No malicious numeric values, packet layouts or ordering instructions are necessary to understand that failure.

### 4.1 What the patch comparison does and does not establish

Synacktiv's appended comparison shows checked addition before allocation, an error branch when arithmetic fails, an additional size comparison, and checked subtraction before subsequent processing. Its guessed label for one comparison operand is not a verified symbol name. Its suggestion that added event tracing might detect real attacks is explicitly speculation, not evidence of a campaign or a published telemetry count. [4]

Microsoft's current RtlULongAdd documentation explains the helper's contract: it accepts ULONG operands and returns a status; an out-of-range result produces STATUS_INTEGER_OVERFLOW and the output is invalid. The page was revised in February 2024, so it explains the documented API, not a newly examined 2020 binary. The patch comparison supplies the historical connection. [15]

The original analytical conclusion is that inserting a checked helper is only one part of a safe repair. The caller must honor its failure status before using the result. An arithmetic result that fits the integer type must also fit the particular message and destination allocation. These are different proofs: representability, consistency with received data, and consistency with later memory access. A helper name alone establishes none of the surrounding control flow; the reported error branch is what makes this patch evidence materially stronger than a list of imported functions.

### 4.2 An independent contemporary test, with a narrower result

FortiGuard's March 12 analysis names Windows 10 x64 version 1903 as its test platform. It traces the server's metadata-derived allocation into subsequent decompression and documents memory corruption ending in a kernel crash. That is concrete evidence of the size mismatch on the tested platform. It is not, by itself, evidence of a working remote takeover, a spreading worm, or testing of every architecture in the affected-product list. [14]

The same source illustrates why close reading matters. Its broad introductory wording about Windows users is narrowed by an explicit affected-version list. A register explanation also contains an apparent width typo: EAX and ECX are 32-bit register views, not eight-byte views. This study retains the allocation mechanism without copying that typo, and it does not reproduce the malformed values or the test procedure. [14]

Comparing independent reports supports the root-cause interpretation more strongly than comparing their headlines. One record supplies an observed crash, another a repair comparison, and the vendor supplies a discovery account. These observations answer different questions. Agreement about the vulnerable arithmetic does not turn every research author's timing statement, variable label or prediction into independently established fact.

## 5. Discovery methods and their limits

Microsoft says its internal TKO full-system emulation and feedback-driven fuzzing work helped uncover the vulnerability. Its May account emphasizes repeatable state restoration, code-coverage feedback and the fact that implementation code can evolve while a protocol version remains unchanged. Those details explain why revisiting an apparently familiar stack could reveal a new flaw. [7]

The analytical significance is that a stable version label is not a proof of stable risk. New implementation paths can inherit a mature protocol's public identity without inheriting the same history of testing. Regression assessment must therefore follow changes in code and reachable behavior rather than rely on the age or reputation of the protocol name.

This case also separates finding a crash from explaining it. A fault reported in a decompression routine does not automatically mean the decompression primitive is the origin of the bug. A caller can supply an inconsistent pointer or size. The relevant root-cause question is which component established the invalid assumptions. This is why the Microsoft explanation and external patch comparison are more useful together than a screenshot of a crash alone. [7,9]

Neither vendor research nor a case-study synthesis is an exhaustive proof that every related bug was eliminated. The subsequent SMBleed research makes that limit unusually concrete: a repaired arithmetic condition did not mean the surrounding functionality could never contain another vulnerability.

## 6. Client exposure changed the mitigation problem

CERT/CC's retained guidance distinguishes two network situations: a remote party reaching a vulnerable SMB service and a vulnerable machine initiating a connection to an SMB server. It also states that the compression workaround required no reboot but did not protect SMB clients. Its network advice addresses both inbound and outbound SMB at the perimeter. [1]

That distinction is the central operational trap in this case. A successful change to a server configuration is evidence about the server path, not a certificate that the whole host is safe. If a workstation's relevant risk is the response it receives after making a connection, blocking unsolicited inbound connections does not describe that exposure.

NHS Digital's retained alert repeats the server-only limitation and recommends considering inbound and outbound TCP 445 restrictions at the perimeter, alongside host-level restrictions. Its page was originally published March 11 and last edited June 16. The current text mentions later public exploits, so those statements must not be backdated to the initial March publication. [10]

This is not a recommendation to indiscriminately disable all internal file-sharing traffic. The historical evidence explains which connection directions mattered. Decisions about legitimate dependencies and service availability require the actual environment. The durable corrective action was installation of appropriate fixed software; a network restriction or server-side workaround addressed only specified paths while that correction was pending.

## 7. Patch availability and patch completion were separate events

The March 12 update's build numbers provide concrete historical markers. Microsoft's retained KB also explains that versions 1903 and 1909 shared a common core and system files. The same page now carries an August 5, 2021 expiration notice stating that the old package is no longer offered through its former channels and recommending later security quality updates. [2]

An original inference from this servicing history is that a research article should not present an old emergency update as an eternal standalone installation target. The fact that the historical KB later expired does not reverse the fact that it delivered the 2020 correction. It changes how the record should be used: as evidence of when the fix became available and which builds were identified at that time.

Similarly, a vendor release date is not an organization's remediation date. The sources reviewed do not supply deployment logs for a named victim or prove that every exposed machine received the update. A chronology that says the vulnerability was fixed on March 12 should make clear that this describes product availability, not universal installation.

This distinction is especially useful in explaining persistent vulnerability exposure after an emergency patch. The remaining problem need not be a failed cryptographic primitive or a new zero-day. It can be the gap between availability, asset identification and actual servicing. That is an analytical possibility, not a claim about a particular unexamined organization.

## 8. Crash, privilege escalation and remote execution

The March 31 research retained by Jamf demonstrated local privilege escalation but explicitly distinguished that result from an achieved remote code-execution proof of concept. Its stated demonstration depended on a medium-integrity starting context. This is an important boundary: an attacker already executing locally has information and capabilities that an unauthenticated remote party may not possess. [5]

A crash demonstrates that malformed input can violate a safety condition and disrupt availability. Local privilege escalation demonstrates a way to cross a local authority boundary under specified starting conditions. Remote code execution requires a different completion claim. Using these phrases interchangeably overstates the evidence and conceals the additional work that research had to establish.

This distinction does not make the original emergency patch excessive. A remotely reachable memory-safety flaw can justify urgent response before every exploitation obstacle is publicly solved. Defensive prioritization concerns plausible severe outcomes as well as already observed harm. The correct retrospective account can acknowledge uncertainty at disclosure without describing the vulnerability as harmless.

Nor does a later working demonstration justify rewriting earlier publications as if they already contained it. Preserving the sequence makes the research process visible: initial identification, root-cause analysis, constrained demonstrations and later expanded capability. It also keeps the reader from mistaking a laboratory result for a documented attack against a real organization.

## 9. SMBleed was related, not another name for SMBGhost

A June 9 publication retained by Jamf describes SMBleed as CVE-2020-1206, a separate issue discovered while examining the SMBGhost-related processing. It concerned disclosure of uninitialized kernel memory. The authors reported that combining it with unpatched SMBGhost enabled pre-authentication remote code execution. They also distinguished an authenticated information-leak demonstration from the broader chaining result. [8]

That record should not be summarized as the March patch failing to fix CVE-2020-0796. A neighboring bug and a combined chain are different claims. A system's exposure to a chain depends on the conditions needed by each part, and a later disclosure can create a new remediation obligation without invalidating an earlier correction.

The conceptual distinction is between corruption and information disclosure. One capability changes memory state; another reveals information that can make an otherwise unreliable attack more feasible. The significance for this study is their interaction, not the steps needed to combine them. No implementation of the chain is reproduced here.

A clean history therefore retains two identifiers and two disclosure contexts. The nickname SMBleedingGhost describes combined research; it should not replace the individual vulnerability identities in an inventory, source register or patch history. Otherwise readers cannot tell which correction addresses which underlying failure.

## 10. Detection claims had a defined product and observation scope

Microsoft's April 6 Azure ATP post announced detection of crafted packets attempting to exploit SMBv3 on unpatched domain controllers. The retained page also shows a May 2021 update date. Its announcement is evidence of a detection capability and its intended coverage, not a claim that all Windows hosts everywhere received that capability or that each alert proved successful code execution. [6]

An attempted exploit, a matching packet and a compromised host are different evidentiary states. A sensor can observe an attempted transition without proving its outcome. The absence of an alert likewise does not establish absence of the vulnerable code, especially when the original announcement specifies a product and monitored role.

For this case, the most useful reporting discipline is to preserve what was observed. If the evidence is a crafted-packet alert, call it an attempt or detection. If the evidence is a crash, report disruption rather than assumed control of the host. A completed compromise requires additional supporting observations. This is case-specific because the public record evolved through exactly those differing kinds of demonstrations and detections.

## 11. Later exploitation classification

The official CISA catalog entry reviewed for this draft records CVE-2020-0796 as added on February 10, 2022. The retrieved catalog version is November 13, 2026, and marks ransomware campaign use as known. It does not name a campaign, provide a victim count or identify the first date of exploitation in that entry. [11]

This later classification prevents an inaccurate timeless statement that SMBGhost was never exploited. It does not justify assigning the catalog addition date to the first attack. Addition dates document catalog administration; campaign chronology requires separate evidence. The same restraint applies to the ransomware field: it supports the classification stated by CISA, not a named attribution invented by the author.

The direct June 2020 CISA alert was inaccessible when retrieved. Rather than use secondary headlines to fill its wording, this study relies on the verified later official entry and clearly leaves the earlier alert's precise observation scope unresolved. That gap is preferable to merging public proof-of-concept availability with confirmed attacks without examining the original statement.

## 12. Standards context without historical overreach

Microsoft's current SMB specification describes compression transform headers as objects used by both clients and servers. The retained header page was updated October 4, 2021. The decompression requirements page, updated July 28, 2025, specifies rejection conditions involving message size, algorithm selection, output size and failed decompression. These are current specification observations, not evidence that every requirement appeared identically in the vulnerable 2020 code. [12,13]

The standards context clarifies the categories that an implementation must keep consistent. It cannot substitute for patch analysis. A specification says what conforming behavior should be; a vulnerable binary establishes what a particular implementation actually did. Comparing those categories helps explain the flaw without claiming to have reconstructed a complete historical standards diff.

It also prevents a simplistic recommendation to regard compressed messages as inherently hostile. Compression is a defined protocol function. The danger arose when externally supplied metadata could drive unsafe memory behavior, not from the mere presence of a compression feature in a legitimate session.

## 13. Final assessment

SMBGhost is a useful case study because its response crossed several boundaries simultaneously: server and client, encoded and expanded representations, discovery and exploitation, temporary configuration and fixed code. The evidence supports a serious pre-authentication vulnerability, a rapid March patch, later research milestones and an official known-exploitation classification. It does not support a fabricated outbreak narrative.

The strongest engineering conclusion is that every arithmetic relationship governing privileged network parsing must remain safe for inconsistent inputs. The strongest response conclusion is that a mitigation's scope must be stated in terms of the actual role and connection direction it covers. The strongest historical conclusion is that the date of publication, date of product correction, date of a demonstration and date of a catalog entry cannot be collapsed into one event.

This draft is an unpublished evidence-based interpretation. It is not a live exposure assessment, a deployment instruction for obsolete Windows releases, or a claim to have independently reproduced exploitation.

## Sources and reading scope

[1] CERT/CC, VU#872016, first published 11 March 2020; revised 4 June 2020. Public date, SYSTEM impact and directional mitigation limitations. https://www.kb.cert.org/vuls/id/872016/

[2] Microsoft Support, KB4551762, 12 March 2020, retained expiration notice 5 August 2021. Build numbers, release scope and later servicing status. https://support.microsoft.com/en-us/servicing/os/windows-10/2020/03/march-12-2020-kb4551762-os-builds-18362-720-and-18363-720-expired

[3] CERT-EU, Security Advisory 2020-014, 11 March 2020 with 13 March revision. Product list and response chronology. https://cert.europa.eu/publications/security-advisories/2020-014/

[4] Synacktiv, Lucas Georges, I'm SMBGhost, daba dee daba da, 12 March 2020. Introductory disclosure account only; conflicting March 9 date attributed, not silently adopted. https://www.synacktiv.com/en/publications/im-smbghost-daba-dee-daba-da.html

[5] Jamf retained research, Exploiting SMBGhost for a Local Privilege Escalation, 31 March 2020. Introduction and result limitations; exploit steps omitted. https://www.jamf.com/blog/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-poc-jamf-threat-labs/

[6] Microsoft, Azure ATP now detects SMBGhost, 6 April 2020; retained update 11 May 2021. Detection target and observation scope, not incident counts. https://techcommunity.microsoft.com/blog/microsoft-security-blog/azure-atp-now-detects-smbghost/1281568

[7] Microsoft Security Team, Mitigating vulnerabilities in endpoint network stacks, 4 May 2020. Discovery approach and selected root-cause explanation; no operational reproduction. https://www.microsoft.com/en-us/security/blog/2020/05/04/mitigating-vulnerabilities-endpoint-network-stacks/

[8] Jamf retained research, SMBleedingGhost Writeup, 9 June 2020. Distinct CVE-2020-1206 and stated combined outcome; chain construction omitted. https://www.jamf.com/blog/smbleedingghost-writeup-chaining-smbleed-cve-2020-1206-with-smbghost/

[9] Trellix archived research, Eoin Carrol, SMBGhost Analysis of CVE-2020-0796, 12 March 2020. Server/client paths, arithmetic and patch comparison. https://www.trellix.com/blogs/research/smbghost-analysis-of-cve-2020-0796/

[10] NHS Digital, alert 3390, 11 March 2020; last edited 16 June 2020. Role-specific workaround scope and retained-page chronology. https://digital.nhs.uk/cyber-alerts/2020/3390

[11] Official CISA cisagov catalog repository, catalog version 2026.11.13, CVE-2020-0796 entry. Addition date and classification only; no named campaign inferred. https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json

[12] Microsoft Open Specifications, MS-SMB2 section 2.2.42, updated 4 October 2021. Header role, not historical code proof. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0

[13] Microsoft Open Specifications, MS-SMB2 section 3.3.5.2.1.2, updated 28 July 2025. Current decompression checks, not a claimed 2020 specification snapshot. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eacbd2d4-4383-4ea3-b9d9-c8ba9f5c9ff4

[14] FortiGuard Labs, Yijie Wang, March 12, 2020. Contemporary Windows 10 x64 1903 analysis; allocation mismatch and kernel crash, not a demonstrated worm or victim count. https://www.fortinet.com/blog/threat-research/cve-2020-0796-memory-corruption-vulnerability-in-windows-10-smb-server

[15] Microsoft Learn, RtlULongAdd, revised February 22, 2024. Current helper contract, not a historical binary audit. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntintsafe/nf-ntintsafe-rtlulongadd
