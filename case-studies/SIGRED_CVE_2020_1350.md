# SIGRed: Windows DNS Parsing, Emergency Mitigation and the Evidence Behind Wormability

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Windows and DNS platform owners, vulnerability-management leads, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,232 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of CVE-2020-1350, you need to separate the DNS Server role from DNS clients or a wormability classification from a completed worm, or you are applying the interim registry workaround and Emergency Directive 20-03

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. DNS Server and DNS Client are different surfaces](#_3-dns-server-and-dns-client-are-different-surfaces), [7. Wormability was a risk classification, not a completed worm](#_7-wormability-was-a-risk-classification-not-a-completed-worm)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- SIGRed (CVE-2020-1350) was a critical flaw in Microsoft's Windows DNS Server implementation, disclosed in July 2020. ([Executive assessment](#executive-assessment))
- It was not a failure of DNS as a universal protocol, nor a flaw in every device that performed a DNS lookup. ([Executive assessment](#executive-assessment))
- Microsoft classified it as wormable, but the discoverer had not completed a full exploit chain and Microsoft knew of no active attacks at publication. ([Executive assessment](#executive-assessment))
- The record changed: CISA later added CVE-2020-1350 to its Known Exploited Vulnerabilities on 3 November 2021. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

SIGRed, CVE-2020-1350, was a critical flaw in Microsoft's Windows DNS Server implementation disclosed in July 2020. Its significance came from the combination of remotely supplied DNS data, privileged server execution and a service often colocated with important domain infrastructure. The vulnerability was not a failure of DNS as a universal protocol, nor a vulnerability in every device that performed a DNS lookup. Microsoft identified the DNS Server role as the affected implementation and excluded non-Microsoft DNS servers from this particular issue. [1]

Three different propositions must remain separate throughout the case. Microsoft classified the vulnerability as wormable. The discoverer demonstrated a memory-corruption path and described exploitation primitives, but explicitly said the team had not completed their chaining into a full exploit. At initial publication, Microsoft said it knew of no active attacks. None of these statements means that exploitation was impossible, and none proves that a self-propagating epidemic occurred. [1,2]

The historical record also changed. CISA's official Known Exploited Vulnerabilities data now includes CVE-2020-1350 with a November 3, 2021 addition date. That later classification must not be erased by repeating the July 2020 disclosure statement as if it were timeless. It likewise does not disclose a complete campaign chronology, a named victim population or the first actual exploitation date. [3]

The response offers an unusually useful operational case: a temporary reduction in permitted DNS-over-TCP response size, activation through a DNS-service restart, a permanent software correction and a federal directive with separate short-term and final deadlines. This study explains those distinct states and their tradeoffs without reproducing exploit construction, heap manipulation or an attack sequence.

## 1. Research scope and source limitations

This draft uses the original Check Point research, Microsoft's announcement and support guidance, NSA and CISA documents, CERT-EU and Australian advisories, the DNS-over-TCP standard, Elastic's detection discussion and the official CISA catalog repository. The MSRC interactive vulnerability page returned only a JavaScript requirement. NVD returned no readable content. The CISA-hosted catalog feed returned 403, but its official cisagov repository was accessible. These retrieval outcomes limit claims about directly inspected product-matrix revisions; they do not justify inventing missing content.

The article is a vulnerability and response study, not a reconstruction of one victim's intrusion. The source set does not provide a complete public incident report tying a named organization, actor and loss amount to the flaw. Where it discusses potential consequences or proposes an engineering interpretation, it says so. The study does not execute public proofs of concept or test production DNS servers.

This boundary matters because the public name sounds like a single event. In reality, the record includes private disclosure, technical publication, emergency action, detection engineering and later exploitation classification. Each has a separate date and evidentiary meaning. A coherent case history should connect them without turning a severity assessment into a victim report or turning a demonstration crash into a documented intrusion.

## 2. Discovery chronology and what the seventeen-year label means

Check Point credits Sagi Tzadik and gives a disclosure timeline: initial report to Microsoft on May 19, CVE issuance on June 18, acknowledgement of critical wormability on July 9, and a Microsoft fix on July 14, 2020. Its historical analysis places the affected implementation lineage as far back as Windows Server 2003. The seventeen-year description refers to vulnerability age, not seventeen years of documented hostile exploitation. [2]

The original historical interpretation is that long-lived server code can receive intense attention only after a researcher chooses a particular parsing boundary. Age alone does not identify why earlier testing missed the defect. This draft therefore does not attribute it to a specific development team, claim that Microsoft knowingly ignored it, or treat the absence of earlier public reports as evidence of absence.

The dates also distinguish discovery from public risk awareness. Private coordination allowed a correction to accompany public disclosure, but publication exposed the technical issue to a much wider audience. For an enterprise response chronology, July 14 is the public correction milestone; May 19 is a research disclosure milestone. Combining them into one patch-delay measure would require additional facts about access to the report, investigation and engineering work that these dates alone do not supply.

## 3. DNS Server and DNS Client are different surfaces

Microsoft's July 14 announcement locates the flaw in the DNS Server role. The Check Point research distinguishes the server executable, dns.exe, from the separate Windows DNS-client implementation. A Windows workstation resolving names is therefore not automatically an instance of the vulnerable server role. A Windows Server inventory also needs role information before it becomes an exposure inventory for this specific flaw. [1,2]

The original architectural analysis is that service identity matters more than a broad operating-system label. A machine can depend on DNS without hosting the vulnerable parser. Conversely, a server not ordinarily described as a public website can still process externally influenced network data. The relevant question is which process interprets the data and with what authority.

This distinction prevents both overcounting and undercounting. Counting every Windows endpoint as a SIGRed victim exaggerates the population. Counting only internet-advertised authoritative name servers can miss internal DNS services that participate in resolution. The study does not supply an enterprise census, but it establishes the fields needed to interpret one: the installed role, active service, software state and actual resolution topology. These fields answer a more precise question than whether an organization uses Windows.

## 4. The technical fault was a size-calculation failure

The original research identifies an integer overflow in the SIG-record parsing path, SigWireRead, leading to heap-buffer overflow. Its analysis describes allocation-size narrowing to sixteen bits and the difference between an encoded DNS name and its expanded representation. It also reports that SIG and RRSIG records share the relevant parsing function. These facts explain the affected trust boundary without requiring an exploit packet or memory-layout recipe. [2]

The conceptual failure is a disagreement between the amount of storage reserved and the amount of data the operation can produce. A bounded network message does not guarantee that every derived representation fits the same bound. Parsing can expand compressed names, add internal metadata or convert representations. If the allocator's arithmetic loses information before the copy, the later operation can exceed the reserved region even though the original message obeyed a transport limit.

This is the original engineering conclusion of the case: validate the size of the representation actually stored, with arithmetic that preserves the required range. A transport-level ceiling is useful but cannot substitute for correct internal allocation. The relevant defensive invariant is that every write fits the destination derived for that write. This discussion stops at that invariant; it does not describe how to arrange memory, select overwritten objects or redirect execution.

## 4.1 A useful negative result: similar parsing was not uniformly vulnerable

Check Point's variant analysis identified NsecWireRead as another consumer combining decoded-name size with variable record data. Its reconstructed logic checked input bounds, arithmetic overflow and the final sixteen-bit allocation limit. The authors reported that the final range check prevented the corresponding flaw in that routine. Separately, their DNS-client comparison found a size check in Sig_RecordRead before its allocator call. These were bounded comparisons within the analyzed implementations, not a certification of every DNS parsing path. [2]

This negative result makes the technical case more precise than "DNS compression is dangerous." Compression changes representation size, but the failure depends on what the caller does with that size. Two routines can use comparable data transformations and reach different safety outcomes because one preserves and validates the allocator's range contract. The defensible lesson is to identify the boundary at which a correctly computed larger size can become a smaller allocation request, then ensure that rejection occurs before narrowing. This is original engineering interpretation, not a claim that this study inspected Microsoft's private correction.

The researcher wondered whether the stronger neighboring checks reflected an earlier isolated fix. That question was speculation in the publication. It does not establish Microsoft's development history, prior knowledge of this flaw, a particular internal patch-sharing practice or an earlier concealed incident. Likewise, the observed client/server differences do not reveal the company's organizational ownership of those code bases. [2]

A source-backed review should retain both kinds of finding: the positive result describing the vulnerable path, and the negative result explaining why a superficially similar path did not exhibit the same defect. Removing the negative result can exaggerate scope; converting it into a universal safety guarantee can understate scope. The appropriate conclusion stays at the inspected routine and the property being compared. Independent confirmation of the final vendor patch would require a separately documented build-to-build analysis, which this package does not claim.

## 5. TCP was a legitimate DNS transport, not an anomaly

RFC 7766, published in March 2016, makes TCP support a required part of a full DNS implementation and discusses the growth of responses beyond the original UDP size limit. Its TCP framing includes a two-octet message-length field. The standard treats TCP as a normal transport choice with connection-management requirements, not as evidence that a DNS exchange is malicious. [4]

The original case interpretation is that a blanket instruction to regard DNS-over-TCP as suspicious would miss the point. The vulnerability arose in handling data, not from the mere existence of a TCP connection. Ordinary protocol features can make complex or larger input reachable, and the implementation must remain safe when that happens.

This also explains why transport size and in-memory size deserve separate labels. A two-byte framing field bounds the encoded message. It does not necessarily bound the size of every decoded object or the arithmetic used to allocate it. A retrospective that says only large packet caused overflow leaves out the essential representation issue. Conversely, a retrospective that calls all large DNS responses attacks would create an inaccurate detection premise and could disrupt legitimate resolution behavior.

## 6. The server can be a consumer of untrusted answers

The NSA advisory describes the issue as targeting handling of DNS Signature resource records. The research examines response processing rather than limiting attention to a client's initial query. The important trust relationship is that a DNS service may consume an answer while resolving a request for someone else. Data received as part of a requested transaction remains untrusted input to the parser. [2,5]

The original architectural implication is that inbound protection cannot be described only by who can initiate a connection to the service. Resolution creates interactions with other participants. An internal server can be reachable indirectly through the work it performs for permitted clients, depending on configuration and path. This does not establish that every internal deployment had an identical exploit route; it explains why the actual topology matters.

A trusted forwarder's address is also not a complete description of the ultimate data provenance. DNS is distributed, and an organization's resolution policy determines what information can be obtained and passed onward. This study deliberately omits the discoverer's query sequence and attacker-controlled setup. For defense, the key distinction is enough: a legitimate resolution operation can cause the server to interpret externally influenced record content, so parser correctness remains necessary inside a nominally trusted network.

## 7. Wormability was a risk classification, not a completed worm

Microsoft assigned a CVSS base score of 10.0 and described the flaw as wormable, meaning it could enable propagation without user interaction between vulnerable systems. Its July 14 announcement simultaneously said active attacks were not then known. Check Point's conclusion stated that the team had identified necessary primitives but had not completed the full exploitation chain because of time constraints. [1,2]

Original analysis should hold these statements together rather than choose the most dramatic one. A plausible route to automation can justify exceptional urgency before a public weaponized implementation appears. A researcher can establish a serious memory-safety failure without publishing a turnkey attack. A vendor can report no known exploitation while still assessing a high likelihood of future abuse.

None of those judgments is a guarantee about the future or a census of all adversaries. The correct retrospective describes what was known at the time and then separately records later evidence. It should not call SIGRed a July 2020 ransomware outbreak, nor dismiss it as harmless because the discovery paper stopped short of a complete chain. The evidence supports an emergency response to a dangerous capability, with explicit limits on observed exploitation at disclosure.

## 8. Local System impact and domain context

CERT-EU's July advisory describes successful code execution in the Local System account context. Australia's advisory notes that DNS is commonly installed on domain controllers and that this placement can magnify consequences for organizational services. These are related but not identical claims: privileged execution on a machine and administrative authority over an entire domain should not be treated as interchangeable in every deployment. [6,7]

The original impact analysis begins with the host's actual role. If the affected DNS service runs on a domain controller, the significance differs from a separately deployed member server. The public research's domain-compromise framing is therefore best understood in its domain-controller context, not as a universal assertion that every Windows DNS instance automatically yields the same administrative outcome.

This distinction gives the case more explanatory power. It shows why a seemingly narrow network-service bug can become a strategic concern when critical roles are combined. It also avoids inventing a post-exploitation chain for an unspecified environment. The source set establishes dangerous privilege and common architectural proximity; a particular organization's final impact still depends on its deployment and the actions actually taken by an attacker.

## 9. The temporary size limit was narrowly defined

Microsoft's KB4569509 describes a temporary cap of 65,280 bytes, hexadecimal FF00, on accepted inbound TCP DNS responses. The default maximum described there is 65,535 bytes. The support article warns that oversized responses are silently dropped and that uncommon legitimate queries may consequently fail. It also says the setting does not affect DNS zone transfers. [8]

The original operational interpretation is that this workaround trades a narrow compatibility range for protection while the permanent update is arranged. It is not equivalent to turning off DNS, blocking all TCP or disabling every large response. A change review should preserve that exact scope so operators can reason about likely side effects rather than react to a vague packet-size restriction.

The difference between the two numeric bounds is 255 bytes. That arithmetic is useful for describing the configuration change, but it should not be converted into a universal exploit threshold or a recommendation for arbitrary smaller values. The vendor selected a particular workaround for a particular implementation. This study records it historically and directs current action to maintained guidance rather than treating a six-year-old registry setting as a stand-alone modern security plan.

## 10. No server reboot did not mean no restart

The same Microsoft guidance requires a DNS-service restart for the registry change to take effect. That is consistent with saying the workaround does not require a full server restart, but easy to misread in a shortened summary. NSA's advisory separately states that applying the patch requires a server reboot and that the temporary measure needs the DNS service restarted. [5,8]

The original case-specific lesson is an activation boundary. Writing a configuration value and having the running service enforce it are different events. A deployment record that captures only successful registry distribution can leave the protected state unproven. Likewise, an installed security update may require completion of its activation sequence before it establishes the intended protection.

The distinction also has a service-continuity consequence. Restarting DNS is narrower than restarting the whole host, but still affects a live dependency. The case does not require a generic change-management essay; it requires precise wording about which component restarts and why. A useful historical audit would retain the change timestamp, activation evidence and legitimate resolution checks. It would not test success by attempting an exploit against a production domain controller.

## 11. Representation errors also affected mitigation deployment

KB4569509 warns that pasting a value with the hexadecimal prefix into certain registry-entry contexts can produce a different decimal value, 4,325,120, rather than the intended 65,280. The article's warning is a concrete example of a security configuration being accepted while its meaning differs from the operator's intention. [8]

The original analytical parallel is striking but bounded. The vulnerability involved a size-representation failure inside a parser; the workaround could be misapplied through a representation misunderstanding at the administration layer. These are not the same software defect. They demonstrate why verification must inspect semantic state rather than merely whether an operation returned success.

For this case, the decisive check is the value the service will actually use after activation. A ticket containing the string FF00 is not enough if the deployment method interpreted it differently. The historical record supports this specific warning, not a broad claim that all registry-based mitigations are unreliable. It also explains why exact units and number bases belong in technical documentation when they can change whether a mitigation works.

## 12. Emergency Directive 20-03 separated interim and final states

CISA issued Emergency Directive 20-03 on July 16. It required covered federal agencies to apply the update or workaround to DNS-role servers by 2 p.m. EDT July 17, then apply the July update to all Windows Servers by 2 p.m. EDT July 24. It also addressed newly provisioned or previously disconnected servers before network connection. The directive's scope excluded the specified defense and intelligence systems; it was not a legal order applying to every private organization. [9]

The original response analysis is that the deadline structure encoded different objectives. The earlier milestone reduced immediate exposure on the most directly relevant role. The later milestone completed a broader software baseline and avoided leaving the temporary configuration as the permanent answer. The future-connection requirement addressed machines that could otherwise escape a one-time inventory snapshot.

The directive does not prove that every agency met those deadlines. A requirement and a completion finding are different kinds of evidence. This study reviewed the order, not a complete set of agency attestations or an independent compliance audit. Its value here is the documented decision structure: urgent interim protection, permanent correction and a rule for systems that return later. Those distinctions are more informative than simply describing the response as patch immediately.

## 13. Removing the workaround was part of completion

Microsoft says the security update resolves the vulnerability and that the registry workaround should be removed afterward, though the two are compatible. NSA also recommends removal after patching. The purpose is to avoid retaining an unnecessary nonstandard limit and its possible future operational effects. [5,8]

Original analysis should therefore distinguish three states: uncorrected and unrestricted, temporarily restricted, and permanently corrected with the temporary restriction retired. These states are not an exploit sequence; they describe response outcomes. A system can remain protected while carrying avoidable configuration debt, and a clean patch ticket should not conceal that debt if it affects future troubleshooting.

The case is useful because the temporary measure had a clear, measurable side effect. A later application issue involving an unusually large answer could be misdiagnosed if the old response cap remained undocumented. Removing it after correction is therefore more than tidiness. It restores the intended service behavior while preserving the security result through the software fix. No additional protection should be inferred from leaving an obsolete restriction in place without a current reason.

## 14. Detection engineering supplied hypotheses, not proof

Elastic's retained detection article is dated November 22, 2022 but records a July 17, 2020 detection-release milestone. It discusses unusual child processes of dns.exe, unexpected file modifications by that process and abnormally large DNS traffic. Those are different observation points: network input, service behavior and host changes. The article does not make every matching event a confirmed SIGRed incident. [10]

The original investigative interpretation is that combining those observations can improve a hypothesis while each remains non-exclusive. A large response may be legitimate. A process anomaly may arise from another cause. A rule also depends on collecting the relevant telemetry with the fields its logic expects. The absence of an alert is weak evidence when the sensor never had visibility into the event class.

The publication-date distinction matters too. The retained 2022 page is evidence of the authors' detection discussion and their stated historical timeline, not proof that every sentence was present in July 2020. A rigorous retrospective should preserve that qualifier. This study neither executes the rules nor claims to have validated their false-positive rate in a production environment.

## 15. Later known-exploitation classification changes the retrospective

The official cisagov catalog data reviewed here lists CVE-2020-1350 with dateAdded November 3, 2021. Its record points back to Emergency Directive 20-03. This is stronger later evidence than a timeless claim that the vulnerability was never exploited, but it does not supply a victim roster, named campaign or first exploitation timestamp. [3]

The original historical synthesis is that knowledge changes without making an earlier statement dishonest. Microsoft's July 14 announcement described what was known then. The later catalog describes a subsequent classification. A useful case study can preserve both rather than forcing one to erase the other. This is particularly important when an old vendor blog remains the most easily found source.

The catalog's addition date should not be substituted for attack onset. It is a record-management milestone. Likewise, a due date in a later catalog should not overwrite the separate July 2020 directive deadlines. These dates answer different questions. The study deliberately avoids claiming a named ransomware operation from catalog inclusion alone or using the catalog to manufacture a continuous exploitation timeline that the public record does not provide.

## 16. Unsupported systems and the boundary of a patch claim

NSA's historical list explicitly includes Windows Server 2003 and 2003 R2 with no patch and an upgrade recommendation. Its broader advice covers the supported server updates and prioritizes DNS-role systems. This prevents a misleading summary in which every affected historical version is assumed to have received the same supported correction path. [5]

The original operational consequence is that applicability and remediability are separate fields. A system can be affected even when a normal update is unavailable. A version's appearance in a historical scope list does not establish that it remained supported in 2020, much less that it should be deployed now. For present-day use, lifecycle status and current vendor guidance matter alongside the old CVE.

This also qualifies the headline age claim. The survival of old code across many releases is technically relevant, but it does not mean all installations have equal operational options. A mature case study should preserve differences in support and response rather than summarize the whole population with one version span. The reviewed material supports an upgrade boundary for old systems; it does not establish the number of such systems still operating or their owners' reasons for retaining them.

## 17. Evidence gaps and final assessment

The source set explains the vulnerable implementation, the memory-allocation failure, the response chronology and later known-exploitation classification. It does not establish a worldwide outbreak, a financial loss total or a uniform domain takeover consequence for every DNS server. It also does not provide a complete current product-update matrix, because the interactive MSRC record was not readable in this retrieval path.

The strongest technical conclusion is that encoded-message limits cannot substitute for safe handling of expanded data and internal arithmetic. The strongest response conclusion is that configured protection, active protection and permanent correction are different states. The strongest historical conclusion is that wormability, research demonstrations and observed exploitation belong in separate evidence categories, each dated to its source.

SIGRed is therefore valuable as more than a frightening nickname. It shows how a privileged infrastructure parser can become a high-consequence attack surface and how an emergency response can include precise compatibility tradeoffs rather than a single generic patch instruction. The remaining incident questions require actual forensic records. This draft leaves them open instead of filling them with a fictional company, an invented campaign or a larger word count unsupported by new evidence.

## Sources and reading scope

[1] Microsoft MSRC, July 2020 Security Update: CVE-2020-1350, 14 July 2020. Role scope, wormability and disclosure-time exploitation statement. https://www.microsoft.com/en-us/msrc/blog/2020/07/july-2020-security-update-cve-2020-1350-vulnerability-in-windows-domain-name-system-dns-server

[2] Check Point Research, Sagi Tzadik, SIGRed, 14 July 2020. Selected root-cause, role distinction, timeline and explicit exploit-completion limitation; operational construction omitted. https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/

[3] CISA official cisagov KEV data, catalog version 2026.11.13, CVE-2020-1350 entry. Addition date and record scope, not victim attribution. CISA-hosted feed returned 403. https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json

[4] IETF RFC 7766, DNS Transport over TCP, March 2016. Transport requirements and message framing selected passages. https://www.rfc-editor.org/rfc/rfc7766.html

[5] NSA, Patch Critical Vulnerability in Windows Servers using DNS Server Role, July 2020 revision 1.0. Role and legacy scope, activation distinctions and temporary-workaround retirement. https://media.defense.gov/2020/Jul/16/2002458198/-1/-1/0/CSA_CVE20201350-V_1_0%20-%20COPY.PDF

[6] CERT-EU, Security Advisory 2020-035. Local System impact, affected-role scope and correction guidance. https://cert.europa.eu/publications/security-advisories/2020-035/

[7] ASD ACSC, Advisory 2020-012, 15 July 2020; retained page reviewed June 2026. Domain-controller context and product scope. https://www.cyber.gov.au/advisory/asds-acsc-advisory-2020-012-critical-remote-code-execution-vulnerability-in-windows-dns-server-cve-2020-1350

[8] Microsoft Support, KB4569509. Workaround size, numeric-entry warning, service activation, compatibility, zone-transfer statement and removal guidance. Historical settings, not commands to execute. https://support.microsoft.com/en-us/servicing/os/windows-server/2020/08/kb4569509-guidance-for-dns-server-vulnerability-cve-2020-1350

[9] CISA, Emergency Directive 20-03, 16 July 2020. Original PDF scope, deadlines and reconnection requirement; no claim that agency compliance was independently audited. https://www.cisa.gov/sites/default/files/ed-20-03.pdf

[10] Elastic Security Labs, Detection rules for SIGRed vulnerability, retained page dated 22 November 2022. Detection categories and authors' historical release timeline, not observed-victim evidence. https://www.elastic.co/security-labs/blog/detection-rules-for-sigred-vulnerability
