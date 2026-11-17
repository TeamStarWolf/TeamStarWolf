# FREAK 2015: When Export-Grade RSA Returned Through a Client State Machine

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [POODLE 2014](/case-studies/POODLE_2014.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

TLS and cryptography engineers, platform security teams, incident responders and vulnerability-management owners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,226 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of FREAK, you need to separate a client state-machine defect from server exposure or scan populations from victim counts, or you are reviewing export-cryptography downgrade risk across platforms

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [The state-machine error behind the downgrade](#the-state-machine-error-behind-the-downgrade), [Exposure statistics: three populations and a mixed historical page](#exposure-statistics-three-populations-and-a-mixed-historical-page)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [POODLE 2014](/case-studies/POODLE_2014.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

Key takeaways (reviewed 2026-11-17):

- FREAK let a client appear to request strong encryption while accepting a weak key from a different negotiation path. ([Executive assessment](#executive-assessment))
- It was neither a universal break of RSA nor simply a website with an expired certificate. ([Executive assessment](#executive-assessment))
- The lesson is the gap between installing an update and removing a vulnerable capability. ([Executive assessment](#executive-assessment))
- No reviewed source establishes an aggregate loss total or one attacker behind all possible exploitation. ([Executive assessment](#executive-assessment))

<!-- meta:end -->

## Executive assessment

FREAK demonstrated that a client could appear to request strong encryption while accepting a weak key that belonged to a different negotiation path. Its significance came from the combination of legacy export cryptography, incorrectly enforced handshake rules, and the continued deployment of compatible servers. It was neither a universal break of RSA nor simply a website with an expired certificate.

This study follows the October 2014 private report to OpenSSL, the January 2015 fix, the March public disclosure and subsequent platform responses. It examines the difference between a library defect and server exposure, the limits of Internet scanning statistics, and the operational gap between installing an update and removing a vulnerable capability.

The record supports a technical and response history, not a worldwide breach census. No reviewed source establishes an aggregate loss total or identifies one attacker behind all possible exploitation. Research demonstrations are kept separate from malicious intrusions. Historical release numbers and configuration choices are presented as historical facts, not instructions to install obsolete software today.

## October 2014 to January 2015: the fix preceded the name

OpenSSL's January 8, 2015 advisory describes CVE-2015-0204 as a client accepting a temporary RSA key during a non-export RSA exchange. It records Karthikeyan Bhargavan's report on October 22, 2014 and credits Stephen Henson with the fix. The listed corrected branches were 1.0.1k, 1.0.0p and 0.9.8zd. The advisory labeled the issue Low severity and included several other, distinct vulnerabilities. [1]

These dates explain an otherwise confusing feature of FREAK's chronology. The widely recognized name and public impact discussion arrived after an upstream correction was already available. A March news event does not imply a March first report or a March first fix. Conversely, a January patch does not prove that every dependent product had incorporated it before March.

The initial severity label is evidence of the vendor's classification at that point. It is not proof that later researchers exaggerated the risk. A narrowly described client behavior and a demonstrated ecosystem attack answer different questions. Historical analysis should retain the original classification while explaining what later work established, rather than rewriting the January document as if it contained all subsequent knowledge.

The other items in the advisory also require separation. A DTLS crash, a memory leak and a certificate-verification issue are not automatically parts of FREAK because they shipped in the same release. Release bundles are administrative groupings. The mechanism and affected role determine whether a particular issue belongs in this case.

## March 3: discovery, coordination and measurement were different roles

The University of Michigan's FREAK tracking site dates the announcement to March 3, 2015. It credits discovery to Bhargavan and the miTLS team, further disclosure coordination to Matthew Green, and ongoing measurement to the Michigan researchers. Its exposure model requires a vulnerable client and a server accepting RSA_EXPORT. The page later expanded its browser assessment and warns that TLS-intercepting software can change the result seen by an otherwise unaffected browser. [2]

This division of roles matters. The discovery team, disclosure coordinator and scanning team contributed different evidence. Treating every citation as an independent replication of the same experiment would overstate corroboration. The tracking site and the technical paper also draw on related research activity, so agreement between them should be read with that shared provenance in mind.

The client-server conjunction is equally important. A weak server configuration and a vulnerable browser are individually meaningful findings, but the attack depends on a usable interaction between them. A vulnerability inventory cannot become a victim list merely by counting entries on both sides. It must establish that relevant sessions occurred and that an attacker had the required network opportunity.

A browser's brand name is not a complete security boundary. Its platform library, version and surrounding interception software can affect the connection that actually reaches the network. The historical finding therefore cannot safely be reduced to "browser X was always safe" or "every product with browser Y was compromised."

## The state-machine error behind the downgrade

The research paper, *A Messy State of the Union*, frames FREAK within a broader study of TLS state-machine composition. Different key exchanges require different message sequences; combining their handlers can accidentally allow a sequence that belongs to none of the intended modes. In the FREAK case, affected clients accepted a ServerKeyExchange carrying a weak temporary RSA key where the selected ordinary RSA exchange should reject that message. The paper's example retains a strong certificate key while the session uses the weak temporary key. [3]

The critical property is consistency across the handshake. Checking that a message is well formed is insufficient if the message should not appear in the current state. Likewise, verifying a signature is insufficient if the signed object is being used in a context that the negotiated mode does not authorize.

This distinction is useful beyond terminology. A certificate inspection could show a strong public key and a valid chain while missing the actual weakness in the session setup. The certificate's identity and strength are not a complete description of every subsequent cryptographic decision. FREAK exposed that gap without requiring a forged certificate authority or the factoring of an ordinary modern certificate key.

The conceptual failure is a mismatch between the security state the client believes it negotiated and the input it later accepts. That is why changing a visible preference or removing an advertised option may not fix the vulnerable parser path. Enforcement has to reach the receiving logic, not only the proposal displayed at the start of the exchange.

This article does not reproduce the paper's message-by-message exploitation sequence. The relevant defensive conclusion is that tests must cover prohibited transitions as well as valid ones. A successful connection under a normal sequence proves interoperability. It does not demonstrate rejection of a message that belongs to a different mode.

## Factoring cost and temporary-key reuse

Green's contemporaneous account describes research factoring of 512-bit RSA keys at approximately 7.5 hours and US$104 in EC2 time per key, with manual assistance and crashes in the process. He explains that reuse of temporary export keys could amortize the computation across more than one session. The demonstration involved changing what a vulnerable client saw from an NSA public website served through Akamai; it was not evidence of intrusion into NSA internal systems. [4]

The economic significance is the relationship between key lifetime and computation time. If a supposedly temporary key remains useful across many connections, an expensive preparation step can become cheaper per affected session. "Temporary" describes a role in a protocol; it does not automatically mean a fresh, one-use object in every implementation.

The quoted dollar amount is a reported 2015 research cost, not a current price estimate, a guaranteed attack budget or a complete accounting of labor. It excludes the value of expertise and does not establish an identical runtime for every key or environment. Repeating it without those boundaries would make the attack sound both more deterministic and more broadly measured than the evidence supports.

Nor does the demonstration justify the phrase "the NSA was breached." A client-side interception demonstration against a public web presence has a different scope from unauthorized access to the organization's servers, classified systems or internal network. Naming a prominent domain can explain the research's visibility while still preserving the actual trust boundary.

## Exposure statistics: three populations and a mixed historical page

The Michigan page's table preserves March 3 baselines of 9.6% for HTTPS servers at Alexa top-million names, 36.7% for servers with browser-trusted certificates, and 26.3% for all HTTPS servers. The displayed later values are 8.5%, 6.5% and 11.8%, respectively. The popular-domain list separately states March 10 at 8:00 AM EST. The page also retains prose describing more than one third of trusted-certificate servers as exposed, which aligns with the earlier baseline rather than its later table value. [2]

This is a living historical page, not a perfectly synchronized dataset. The timestamp attached to one list should not silently date every table and sentence. Its "currently vulnerable" labels are historical website language, not a scan performed for this study or a statement about present-day systems.

The different denominators should remain separate. Ranked domain names, endpoints with trusted certificates and all HTTPS endpoints are not interchangeable populations. Hosting concentration, duplicate endpoints and certificate selection can affect their relationship. Averaging the three percentages would not create a meaningful worldwide risk estimate.

A useful calculation can still be made with explicit limits. The trusted-certificate series falls from 36.7% to 6.5%, a reduction of 30.2 percentage points. Relative to the baseline percentage, that is about 82.3%. This is arithmetic on published percentages, not evidence that 82.3% of victims recovered, that the same exact endpoints remained in the sample, or that malicious activity fell by that amount.

The narrower claim is evidence of a substantial reported change in server susceptibility within that measurement series. A robust causal explanation for the change would require the raw longitudinal data and scan methodology. This study has not retrieved those datasets, so it does not assign every change to patch deployment rather than configuration, availability or sample differences.

## March 5 and March 10: Microsoft's client-role correction

Microsoft's advisory 3046015 was published March 5 and updated March 10 to point to the released bulletin. Its revision history also records a same-day clarification concerning the absence of a Windows Server 2003 workaround. The current page is a revised artifact; its later platform metadata should not be treated as a new FREAK disclosure. [5]

MS15-031 identifies the Schannel issue as CVE-2015-1637 and describes a client accepting a shorter RSA key than the negotiated exchange required. The March 10 update corrected cipher-suite enforcement. Microsoft stated that, at original bulletin release, it had received no information indicating public use of this issue to attack customers. The bulletin also notes that an exploitable connection requires server-side RSA export support, disabled by default in Vista/Server 2008 and later configurations. [6]

Those statements distinguish software capability from observed compromise. Microsoft's lack of received reports at one date is not proof that no attack occurred anywhere. It is still valuable evidence and should not be omitted merely because the vulnerability was dramatic. The source supports a bounded statement about vendor awareness, not a universal negative.

The word "server" in an operating-system product name can also mislead. A Windows Server machine can initiate outbound TLS connections and therefore act as a client in the vulnerable exchange. Inventory categories based only on whether a host serves web pages can miss that role. Conversely, the existence of a vulnerable client stack does not mean that every inbound service exposes export ciphers.

## Workaround persistence and the Server 2003 distinction

Microsoft's bulletin warns that its cipher-restriction workaround can break connections to peers without a mutually supported remaining suite. Installing the update does not automatically restore the disabled choices. The bulletin's FAQ separately states that export ciphers can remain enabled on Windows Server 2003 after the update and directs administrators to additional guidance. [6]

This is a concrete reason to separate three closure tests: the client implementation rejects the inappropriate key, the service no longer offers the weak capability, and temporary operational restrictions have been reviewed. Passing one test does not logically prove the other two.

A workaround also has a lifecycle. During an emergency, a deliberately restrictive policy can be the correct risk tradeoff. After a patch, leaving it in place may be desirable, or it may cause avoidable failures. That decision requires an explicit policy review rather than an assumption that the installer returned every setting to its previous state.

The Server 2003 note does not mean that the update failed to address the stated client vulnerability. It means that the broader capability-removal objective was separate. This distinction prevents an inaccurate all-or-nothing assessment of the patch and gives a more useful explanation of why additional hardening could still be necessary.

## Apple's Secure Transport response

Apple's iOS 8.2 security content identifies CVE-2015-1067 in Secure Transport. It describes acceptance of short ephemeral RSA keys during full-strength RSA exchanges and says the correction removed ephemeral RSA-key support. The entry explicitly limits the vulnerable connection to servers supporting export-strength RSA suites. The page now displays a November 2023 publication date, so that header is not used here as the 2015 release date. [7]

The separate identifier matters. CVE-2015-0204 is not a universal identifier for every affected implementation. A cross-platform incident can involve related defects in different codebases, with different fixes and product packaging. Collapsing them into one CVE can create misleading inventories and incomplete remediation claims.

Apple's description also illustrates a different repair boundary from a server-side cipher configuration. Removing a client's acceptance path and removing a server's ability to offer the weak exchange can both obstruct the attack, but they operate at opposite ends of the connection. A case study should preserve that distinction rather than describe all actions simply as "disabling FREAK."

This study does not infer full device adoption from the availability of the update. It has not examined installation telemetry, individual device records or every OS X and Apple TV release associated with the same issue. The selected Apple source establishes the iOS correction and its mechanism.

## Red Hat: defaults, application overrides and running processes

Red Hat's historical bulletin notes that export ciphers were disabled by default in the then-latest RHEL releases but could be enabled by applications. It covers affected unpatched OpenSSL packages in RHEL 5, 6 and 7 and separately describes an affected openssl097a compatibility package with no planned fix under the stated lifecycle policy. It recommends ensuring running services load the updated libraries, with rebooting as the simplest safe approach, and disabling server export suites to protect unpatched clients. [8]

This adds two operational details that a release-only chronology would miss. A library default is not always the application's effective configuration. And replacing a file on disk is not always the same as replacing the code already loaded by a long-running process.

The compatibility-package exception also makes a blanket "all packages patched" claim unsafe. Product support policies can leave different components on different paths even within the same operating-system family. A historical account should report the limitation as the vendor stated it at that time, rather than assume that every affected package received an equivalent update.

These observations suggest a specific evidence chain for remediation: identify the dependency actually used by the application, determine the effective negotiation policy, and confirm that the running process uses the corrected implementation. The case does not justify claiming that any single package-manager success message proves the entire chain.

## OpenStack: the TLS boundary could sit outside the application

OpenStack's March 11 security note lists not only OpenStack clients and services but also web servers, TLS terminators, proxies and other components depending on their TLS backend. It recommends server-side removal of weak export choices because operators cannot assume all connecting clients have been updated. The note's broad title uses "protocol downgrade"; the mechanism examined here is specifically the RSA export key-exchange downgrade, not necessarily a fallback to an older TLS version. [9]

The architectural consequence is ownership ambiguity. The application team may see a TLS-protected endpoint while a proxy or separate termination layer makes the actual cryptographic decisions. A remediation task assigned only to the application repository can therefore stop short of the component responsible for the exposed behavior.

The reverse situation matters too: updating a public-facing terminator does not necessarily update clients that make outbound requests elsewhere. The dependency graph has direction. The same service can be protected in one role and still vulnerable in another. FREAK's paired client-and-server requirements make that direction unusually important.

This is why the study avoids a simplistic infrastructure-wide label. A cloud installation can contain multiple TLS libraries, independently managed endpoints and different negotiated policies. An accurate account identifies which connection and which role a finding describes.

## Typed chronology

- October 22, 2014: private report to OpenSSL, as recorded in its advisory. [1]
- January 8, 2015: OpenSSL publishes CVE-2015-0204 correction and branch release guidance. [1]
- March 3, 2015: public FREAK announcement and research explanation. [2][4]
- March 5, 2015: Microsoft advisory and revision; Michigan client assessment expands. [2][5]
- March 10, 2015: Microsoft update bulletin; Michigan popular-domain list has its own timestamp. [2][6]
- March 11, 2015: OpenStack publishes its security note. [9]
- 2015 IEEE Symposium on Security and Privacy: research paper documents FREAK within a broader state-machine investigation. [3]

The Apple page confirms the iOS 8.2 correction but its current header does not establish the release day. The chronology deliberately does not substitute a modern page-maintenance date for a historical product event.

## Evidence limits and conclusions

The strongest evidence concerns the defect, public response and measured susceptibility. The original research demonstrates feasibility, while vendor advisories establish their own fixes and known limitations. The Michigan site reports exposure rather than successful intrusion. The sources are related in places and should not be counted as wholly independent replications.

This draft reads the original paper's introduction, relevant state-machine discussion, complete FREAK subsection and disclosure summary. It does not claim a full audit of the entire paper, formal proofs, appendices or unrelated attacks. Nor does it reproduce the factoring experiment, inspect all historic browser builds or verify every affected vendor matrix. No public targets were scanned and no attack tooling was run.

The supported conclusion is specific: export cryptography remained dangerous because an implementation could activate it outside the mode the client intended. Strong certificates and strong advertised preferences did not guarantee strong session setup. Effective remediation required both correct client enforcement and removal of weak server choices, with attention to loaded libraries and temporary workarounds.

A deeper follow-up should add dated deployment data, archived per-platform releases and reproducible scan methodology. It should not fill the missing victim record with hypothetical losses. The useful history is the chain from a narrowly described state-machine bug to ecosystem exposure, followed by several distinct kinds of corrective action.

## Source register

[1] OpenSSL, security advisory, January 8, 2015. FREAK section and surrounding distinct vulnerabilities read. https://openssl-library.org/news/secadv/20150108.txt

[2] University of Michigan researchers, *Tracking the FREAK Attack*. Full core narrative, comparison table and timestamp inspected; long domain roster sampled. Historical page, not current scanning. https://freakattack.com/

[3] Beurdouche et al., *A Messy State of the Union: Taming the Composite State Machines of TLS*, IEEE S&P 2015. Introduction, relevant state-machine discussion, FREAK subsection V-D and disclosure summary V-E read; remaining proofs and appendices not fully reviewed. https://www.microsoft.com/en-us/research/wp-content/uploads/2015/05/A-Messy-State-of-the-Union-Taming-the-Composite-State-Machines-of-TLS.pdf

[4] Matthew Green, disclosure coordinator, *Attack of the week: FREAK*, March 3, 2015. Complete substantive article read; comments excluded. Reported demonstration and cost, not independently reproduced. https://blog.cryptographyengineering.com/2015/03/03/attack-of-week-freak-or-factoring-nsa/

[5] Microsoft, security advisory 3046015, March 5, revised March 10, 2015. Current revised advisory and full revision history read. https://learn.microsoft.com/en-us/security-updates/securityadvisories/2015/3046015

[6] Microsoft, MS15-031, March 10, revised March 24, 2015. Executive summary, affected products, vulnerability description, workaround and FAQ read. Historical settings not applied. https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-031

[7] Apple, *About the security content of iOS 8.2*. Full Secure Transport entry and surrounding release content read; current November 2023 metadata is not the historical release date. https://support.apple.com/en-ca/103585

[8] Red Hat, *FREAK: OpenSSL vulnerability (CVE-2015-0204)*, updated May 8, 2015. Complete substantive bulletin including restart and mitigation sections read; linked package advisories not independently audited. https://access.redhat.com/articles/1369543

[9] OpenStack, OSSN-0045, March 11, 2015. Full substantive note read; current site build date is not incident timing. https://docs.openstack.org/security-notes/OSSN-0045.html
