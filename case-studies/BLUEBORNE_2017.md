# BlueBorne: Bluetooth Exposure Beyond the Pairing Prompt

*A TeamStarWolf case study. Published 15 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Mobile, endpoint and firmware security engineers, vulnerability-management owners and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 17 min (3,959 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of BlueBorne, you need to separate radio proximity from internet reachability or userspace from kernel fixes, or you are reviewing Bluetooth-stack exposure and multi-vendor remediation

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [3. Radio proximity and remote access](#_3-radio-proximity-and-remote-access), [4. Discovery, pairing and input processing](#_4-discovery-pairing-and-input-processing)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Mobile Security Reference](/MOBILE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Endpoint Security Reference](/ENDPOINT_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

BlueBorne challenged a familiar mental model: a device that has not accepted a pairing request is not necessarily insulated from hostile Bluetooth input. Armis's research described eight implementation vulnerabilities across major operating-system families. The researchers explained that the relevant attacks did not require the target to be discoverable or previously paired to the attacker, nor did they depend on the user approving a new connection. That finding concerned processing below the user interaction many people regarded as the security boundary. [1]

The practical lesson is not that every device carrying a Bluetooth logo has the same flaw. The affected software, architecture, configuration and consequence varied. Some issues involved information disclosure; others involved code execution or interception. Supplier assessments narrowed the risk for particular products, and the path from an upstream fix to a corrected deployed device differed across ecosystems. [2][3][4]

This case study concentrates on that variation. It examines the September 2017 disclosure, the distinction between radio proximity and internet reachability, the difference between discovery and authorization, and the evidence needed to close a remediation task. It does not invent a victim count, identify an attacker, or describe BlueBorne as a confirmed self-propagating global outbreak.

An effective response would have needed both technical and organizational precision. The technical work was to identify the actual vulnerable component and supported remedy. The organizational work was to find devices whose radios and update ownership were missing from ordinary asset management. The study develops an original defensive model for doing that without conducting exploit tests on production equipment.

## 1. Scope and evidence method

Primary material includes Armis's technical white paper, Android's September 2017 bulletin, CERT/CC and JPCERT/CC coordination records, and supplier assessments from Red Hat, Ubuntu and Microchip. These sources answer different questions. A researcher demonstrates or characterizes a weakness; a supplier determines its impact on supported configurations; a coordination center helps organize cross-vendor information.

The review used selected relevant passages rather than a complete line-by-line audit of all implementations or every page of the research paper. No exploit was downloaded or executed. No device was scanned, paired, modified or tested. The defensive recommendations and fictional training scenario are original analysis, separated from historical findings through explicit wording and citations.

The publicly hosted Armis PDF has a 2017-oriented filename but carries a later copyright footer. It is therefore cited as the available research text rather than asserted to be a byte-identical copy of the original disclosure-day document. The original research landing page also redirected during retrieval. These limitations matter when reconstructing exact publication history. [1]

Historical package versions and patch-level strings in this study explain the 2017 response. They are not a current installation baseline. A present administrator should use current supplier-supported guidance and confirm that the device still has a maintained update path.

## 2. What the BlueBorne name represented

CERT/CC released vulnerability note VU#240311 on 12 September 2017 and later revised it. It described a collection of Bluetooth implementation issues affecting Windows, iOS and Linux-derived systems, including Android and Tizen. Its catalog separated memory-safety problems from flaws in the security requirements of networking profiles. [2]

That grouping is useful for communication but dangerous if interpreted as one universal defect. A common name does not imply a shared patch, identical prerequisites, or the same degree of control after exploitation. It also does not establish that all hardware from a listed platform family is affected regardless of software build and configuration.

Original analysis should therefore retain the individual vulnerability identifiers alongside the campaign-style name. A response register can use "BlueBorne" as a parent topic while giving each applicable component its own evidence and closure record. This makes it possible to finish one correction without accidentally declaring unrelated components resolved.

The distinction also helps readers interpret severity. A group containing a critical code-execution flaw and a lower-severity disclosure issue should not assign the worst effect to every member. Conversely, a lower-severity issue should not disappear simply because another issue receives more attention. Its relevance depends on the system's data, permissions and surrounding defenses.

## 3. Radio proximity and remote access

Red Hat's analysis states that the affected system needed Bluetooth hardware and service enabled, with the attacking device within operating range. This is a remote interface in the sense that hostile input can arrive without physical access to the target's keyboard, but it is not automatically an internet-reachable service. [5]

Original risk analysis should keep those meanings distinct. A nearby radio channel can cross an organizational boundary even when no routed network connection exists between the devices. Conversely, the existence of a software vulnerability does not mean an attacker anywhere in the world can reach it directly. Range, enabled functionality and implementation behavior remain part of the exposure question.

Distance should not be reduced to an invented universal radius. A practical assessment should use the actual environment and approved supplier information rather than assume that every wall or room boundary isolates the signal. This study does not provide methods for extending attack range or locating targets.

The defensive implication is that network diagrams need an accurate account of relevant wireless interfaces. An asset described as "not connected to the office network" may still process input from a radio interface. A different interface creates a different control problem; it does not make all existing network controls irrelevant.

## 4. Discovery, pairing and input processing

Armis's central finding was that the described attacks could reach vulnerable processing without the familiar pairing approval. The research also explicitly rejected the assumption that turning off discoverability alone was sufficient. [1]

The original architectural lesson concerns the order of operations. A device may need to parse some protocol input before it can decide whether to accept, reject or authenticate a peer. Security review must include that early processing. A user-facing trust decision cannot protect code that already consumed hostile data before the decision occurred.

This does not mean pairing is pointless. It means pairing and safe input handling answer different questions. A sound implementation must both enforce the intended authorization rules and safely process messages received outside an authorized session. Treating either function as a substitute for the other leaves part of the system unexamined.

For organizations, the user interface is therefore incomplete evidence. A screenshot showing no paired attacker device does not prove that the vulnerable code was unreachable. Similarly, an employee saying that they never clicked an acceptance prompt does not by itself exclude this class of exposure. Investigation should be driven by platform-specific facts rather than a security model borrowed from ordinary accessory setup.

## 5. Android's evidence and the patch-date discrepancy

Android's September 2017 bulletin lists CVE-2017-0781 and -0782 as critical remote-code-execution issues, -0783 as high-severity information disclosure, and -0785 as moderate-severity information disclosure. Its revision history says the four records were added on 12 September as part of coordinated disclosure. The bulletin identifies 2017-09-01 and 2017-09-05 patch-level strings, with the latter covering all applicable issues in that bulletin. [3]

The historical CERT/CC and JPCERT/CC pages instead refer to a September 9 Android security patch level. This study preserves that inconsistency and uses the Android supplier bulletin for its patch-level description. It does not create a new recommended threshold by averaging or silently normalizing the dates. [2][3][7]

The analytical lesson is that a coordination advisory may be useful for discovering scope while the platform supplier remains essential for the exact remedy. A research record should include the document revision and the claim it supports, so that a later reviewer can understand why the response used one source for classification and another for maintenance details.

Android's bulletin also said it had received no reports of active customer exploitation of the newly reported issues. That is a bounded statement in a dated bulletin, not proof that no exploitation ever occurred anywhere. [3]

## 6. Linux user space and the kernel

Ubuntu's assessment separates CVE-2017-1000250 in the BlueZ userspace daemon from CVE-2017-1000251 in the kernel's Bluetooth L2CAP processing. The former involved disclosure of daemon memory. For its kernels, Ubuntu described stack protection as changing the expected impact of the latter from code execution to a system crash. Its timeline records BlueZ updates on 12 September and kernel updates on 18 September 2017. [4]

The distinction makes a concrete difference to remediation tracking. Updating a userspace Bluetooth package is not evidence that the running kernel has received a separate correction. A management system that stores only the broad product name can overlook that difference even when the administrator believes the Bluetooth subsystem has been updated.

Original response records should therefore identify the component that changed and the component whose state was verified. Where a correction requires activation through a restart or another supplier-defined procedure, the evidence should show that the active instance changed. Package delivery and effective runtime correction are related but different events.

A mitigation that changes a likely consequence also deserves careful language. A crash can still matter greatly to an essential service. Describing a mitigation as protection against one outcome should not erase the remaining availability risk or become a reason to leave the underlying flaw uncorrected.

### 6.1 Source-level repair: cached response boundaries

The BlueZ correction linked by Ubuntu is commit 9e009647b14e810e06626dde7f1bb9ea3c375d09. In service_search_attr_req, the former condition checked whether a cached response existed. The revised condition also checks that the continuation position remains below that cached response's data size before proceeding. The commit describes an out-of-bounds heap read, not a kernel write or universal code-execution flaw. [9]

The original analytical point is that possession of a valid cache object is insufficient evidence that a continuation position is valid inside it. Object existence and range validity are separate invariants. A resumed transaction still requires bounds checking; earlier successful processing cannot confer unlimited authority on later metadata. That is a more precise explanation of this repair than simply saying Bluetooth needed stronger authentication.

This study inspected the published change but did not build BlueZ, reproduce the defect, or evaluate every downstream backport. Ubuntu's advisory supplies the connection to CVE-2017-1000250. The upstream change alone does not identify which package a particular distribution installed.

### 6.2 Source-level repair: output construction is also a boundary

Ubuntu links kernel commit e860d2c904d1a9f38a24eb44c9f34b8f915a6ea3 for the separate L2CAP issue. Its patch propagates output-capacity arguments through configuration-building and parsing helpers. The option-append helper checks that remaining capacity can hold the option header and content before writing. Call sites pass the remaining space rather than assuming the destination is large enough. The stated purpose is preventing overflow of the stack buffer used to build configuration options. [10]

This distinguishes incoming-message validation from safe construction of the response. A parser can read input without immediately overrunning the input buffer yet still produce too much output for its local destination. The review question must therefore follow the transformation across both sides of the operation. Those are conceptual defensive implications, not a packet sequence or exploit recipe.

The inspected change is stronger evidence than a generic assertion that a patch added checks. It identifies which size information had to cross function boundaries and where the final write was bounded. It is not proof that all related logic is correct, that every vendor incorporated the change unchanged, or that every affected architecture has the same exploitation outcome.

### 6.3 Concrete release and activation evidence

Ubuntu USN-3413-1, published September 12, lists historical BlueZ corrections for 14.04, 16.04 and 17.04. For example, its 16.04 entry identifies bluez and libbluetooth3 version 5.37-0ubuntu5.1. This is a userspace package record for CVE-2017-1000250, not evidence that a kernel fix was active. [11]

The separate September 18 USN-3420-1 covers the 16.04 kernel issue. It lists the generic 4.4.0-96 kernel package at version 4.4.0-96.119, alongside different kernel flavors. Its instructions require a reboot after updating and discuss an ABI change requiring third-party kernel modules to be rebuilt and reinstalled. The notice also fixes unrelated vulnerabilities, which must not be counted as additional BlueBorne members. [12]

The original conclusion is that the six-day gap between these two notices is a difference between supplier release milestones, not a measured six-day exposure interval for every device. Installations could precede or follow an organization's own discovery and maintenance window. A correct historical account preserves package, flavor, activation and date without turning the old versions into today's recommended baseline.

Direct kernel.org pages failed during this QA pass; matching upstream commits were readable in the Linux and BlueZ GitHub repositories. The reviewed content was the source change itself, not comments or unverified claims from an unrelated fork. This retrieval fallback is recorded so readers can distinguish a missing source from an alternative primary-source route.

## 7. Red Hat's architecture-specific assessment

Red Hat rated CVE-2017-1000251 Important and described pre-authentication processing in the affected kernel subsystem. Its advisory distinguished configurations with stack protection from certain PPC64 configurations without it. It also identified products or architectures not affected for different reasons, such as absence of the vulnerable modules or the relevant service. The advisory cautioned that code execution could not be fully ruled out even where stack protection reduced the risk. [6]

This is more nuanced than a statement that "Linux is vulnerable" or "stack protection solves BlueBorne." A supplier's classification reflects a defined product context. The presence of a mitigation can change the practical assessment without removing the need for the supplier's correction.

Original review should preserve these conditions rather than reduce them to a single inherited label. Architecture, installed services, loaded components and operational configuration can all affect applicability. The person recording the decision should identify which condition was actually established and which remains inferred.

A non-affected determination also needs an owner. If it depends on a service remaining absent, enabling that service later should trigger reassessment. Configuration-based non-exposure is not an immutable property of the asset name. The supporting evidence should survive long enough for a future change reviewer to recognize that dependency.

## 8. Apple and Windows within the collection

JPCERT's contemporary alert lists the Apple issue as CVE-2017-14315, identifies older iOS and Apple TV releases, and reports the researcher's statement that iOS 10 addressed the iOS vulnerability. Its Windows entry identifies CVE-2017-8628 as a Bluetooth driver spoofing vulnerability and points readers to September 2017 Microsoft security updates. [7]

CERT/CC's description associates the Windows and Android networking-profile issues with interception rather than treating them as the same code-execution flaw found elsewhere. [2] That distinction is important when explaining what a particular affected device could expose and which boundary a correction restores.

The Microsoft Security Update Guide page required JavaScript and did not expose substantive detail through the retrieval used here. This study therefore does not invent a complete Windows package matrix or claim that all Microsoft records were inspected. It relies on the cited coordination record for this limited historical classification and directs current maintenance decisions to the supplier.

Original analysis should also avoid reading a historical statement about iOS 10 as present-day advice to install that release. A release can contain a relevant historical correction while being unsuitable as a current supported operating system. The case is about the change in the security condition, not about preserving a 2017 platform baseline indefinitely.

## 9. Host software versus radio hardware

Microchip's assessment locates the relevant issues in the host Bluetooth stack rather than its device firmware or driver implementation, and it directs attention to host-layer correction. Its ATWILC3000 discussion also includes a planned firmware measure with an estimated future date. A plan in a retained historical advisory is not verification that the promised release shipped. [8]

This source illustrates why component boundaries matter. A procurement record might identify the radio vendor while the vulnerable processing belongs to the operating-system stack on the host. Asking only the hardware supplier whether its firmware is affected can leave the actual software exposure unanswered.

The original response model should map responsibility without transferring accountability away from the device owner. The radio supplier, operating-system vendor, equipment manufacturer and local administrator may each control a different part of the remedy. The organization using the device still needs one person responsible for obtaining a complete applicability decision.

A useful supplier question names the product, build and relevant component, then asks for the supported correction and verification method. A generic statement that one component is not affected should be recorded at that scope. It should not silently become an assurance about the entire assembled device.

## 10. Capability, demonstration and incident claims

The reviewed research and advisories establish a vulnerability disclosure and describe potential effects. They do not provide this study with a verified global victim census or a documented self-propagating epidemic. Armis's demonstration of exploitation capability is evidence about capability; it is not itself evidence of malicious use against a named organization. [1]

Original historical writing should keep three categories separate: what researchers demonstrated, what defenders observed, and what an attacker is known to have accomplished. A statement that a technique could support malware propagation belongs in the first or analytical category unless incident evidence supports more.

Likewise, a large estimate of potentially exposed devices would not equal a count of compromised devices. Estimation methodology, platform exclusions and patch adoption affect the former. For the latter, an investigator needs evidence of actual activity and outcome. This case deliberately avoids a headline-scale number that would obscure those differences.

Attribution is another independent question. A vulnerability may be available to many actors. Naming a researcher, vendor or disclosure coordinator does not identify an adversary. The absence of a documented attacker in this study is an evidence limit, not an invitation to fill the gap with a plausible story.

## 11. A bounded defensive evidence model

The following is original analysis, not a claim about a named organization's 2017 response. Record the actual platform, Bluetooth stack, enabled functions and business owner. Map each applicable CVE to the supplier's remedy. Preserve unknowns as verification tasks instead of counting them as either fixed or confirmed compromised.

For the Linux examples above, keep userspace installation evidence separate from the active kernel version and the supplier's activation requirements. For Android, retain the supplier's exact patch-level semantics rather than the inconsistent date in a secondary coordination record. For assembled equipment, distinguish the radio component supplier's statement from the host operating-system assessment.

Safe verification can use supported configuration and package evidence, followed by functional checks of legitimate workflows. It does not require an exploit demonstration on production equipment. A restriction that interrupts an accessibility or operational dependency needs an approved alternative and an accountable exception, not an assumption that the dependency is unimportant.

The evidence limits remain material. No complete Windows package matrix, all-device applicability survey, firmware audit or incident census was performed. Neither a missing pairing record nor an absence of obvious malfunction proves that vulnerable processing was unreachable. Conversely, a connectivity failure by itself does not prove BlueBorne exploitation.

## 12. Fictional exercise: Cedar Field Services

Cedar Field Services is a fictional training organization with a managed laptop fleet, shared Android handhelds and supplier-maintained equipment. Its security coordinator receives a BlueBorne advisory and must produce a response plan. No real company, employee or victim is represented.

The laptop team reports that users have been told not to accept pairing requests. The handheld supplier says a platform fix exists but has not confirmed its product release. A Linux equipment owner reports updating the BlueZ package and assumes the kernel issue is resolved too. A procurement record lists a radio vendor that says its own firmware is not the vulnerable component.

Participants should identify the unsupported conclusions. Pairing advice does not establish absence of the vulnerable processing. An upstream fix does not establish product deployment. A userspace package result does not establish the running kernel state. A component supplier's statement does not settle the assembled product's host-software exposure.

A final inject adds a business dependency: disabling Bluetooth would interrupt an approved accessibility workflow. The group should propose a supported remedy or an approved temporary alternative, with the affected user's needs represented in the decision. The exercise tests coordination and evidence, not exploitation skill.

## 13. Exercise answer framework and closure metrics

A good response assigns a service owner to each unresolved item and uses a status vocabulary that distinguishes verified correction from temporary restriction and uncertainty. The coordinator should request product-specific evidence rather than collect general reassurance from every team.

For the handhelds, the next useful result is a supplier-supported update path and a realistic deployment decision. For the Linux equipment, the team should inspect the separate component requirements. For the radio-vendor statement, it should identify who maintains the host stack. For the accessibility dependency, it should coordinate an alternative rather than impose a change that makes the device unusable.

Original metrics should retain devices that cannot yet be assessed. Report the number with verified correction, the number under an approved temporary restriction and the number still awaiting a supported decision. Keep the age and business consequence of exceptions visible. A percentage that excludes the hardest devices is a weak measure of actual progress.

Finally, review a sample of closed records. Ask whether each contains evidence for the active state and whether its conclusion matches the source's scope. This catches the common failure of closing a task because an update was announced, a package was downloaded or an instruction was sent, rather than because the relevant device was shown to be corrected.

## 14. Conclusion

BlueBorne's lasting lesson concerns trust boundaries that are easy to overlook. User-facing pairing, radio discovery, host software and vendor hardware are related parts of a system, but none should be treated as a universal proxy for the others. Security assurance depends on identifying which component processes the input and what condition actually prevents the harmful behavior.

The historical record supports a careful, platform-specific response. Researcher findings establish the class of problem; supplier records refine applicability and maintenance; local evidence establishes what is deployed. Original governance must connect those layers and preserve uncertainty until an accountable person resolves it.

The result is a more useful case study than a claim of universal takeover. It explains why apparently disconnected devices still need accurate interface inventories, why a mitigation may change consequences without removing the flaw, and why a completed response requires evidence of the active corrected state.

## Sources and reading scope

[1] Armis, BlueBorne Technical White Paper, available hosted edition with later copyright footer. Selected introduction, discovery assumptions and vulnerability catalog reviewed; no exploit implementation performed. https://info.armis.com/rs/645-PDC-047/images/BlueBorne%20Technical%20White%20Paper_20171130.pdf

[2] CERT/CC, VU#240311, released 12 September 2017, revised 8 November 2017. Cross-platform catalog and update guidance; historical Android date wording differs from supplier bulletin. https://kb.cert.org/vuls/id/240311

[3] Android Open Source Project, September 2017 Security Bulletin. Patch-level definitions, four BlueBorne entries, revision history and dated exploitation statement. https://source.android.com/docs/security/bulletin/2017-09-01

[4] Ubuntu, Blueborne vulnerability knowledge base. Separate userspace/kernel issues, configured impact and dated update availability. https://ubuntu.com/security/vulnerabilities/blueborne

[5] Red Hat, BlueBorne - An Analysis, 4 October 2017. Proximity prerequisites, protocol context and supplier correction discussion. https://www.redhat.com/en/blog/blueborne-analysis

[6] Red Hat Product Security, Blueborne CVE-2017-1000251 advisory, September 2017. Product, architecture and stack-protection distinctions; activation and remediation scope. https://access.redhat.com/security/vulnerabilities/blueborne

[7] JPCERT/CC, alert AT170037, September 2017. Platform catalog, historical Apple/Windows scope and supplier references. https://www.jpcert.or.jp/english/at/2017/at170037.html

[8] Microchip, BlueBorne Attack Vector. Host-stack versus component scope and historical planned mitigation; a plan is not verified release evidence. https://www.microchip.com/en-us/products/wireless-connectivity/features/security/software-vulnerability-response/blueborne-attack-vector


[9] BlueZ upstream commit 9e009647b14e810e06626dde7f1bb9ea3c375d09, sdp cached-response bounds correction. Matching commit linked by Ubuntu; source diff reviewed through upstream GitHub after kernel.org retrieval failed. https://github.com/bluez/bluez/commit/9e009647b14e810e06626dde7f1bb9ea3c375d09

[10] Linux upstream commit e860d2c904d1a9f38a24eb44c9f34b8f915a6ea3, L2CAP configuration output-buffer bounds. Matching Ubuntu-linked source change reviewed through upstream GitHub; no compiled reproduction. https://github.com/torvalds/linux/commit/e860d2c904d1a9f38a24eb44c9f34b8f915a6ea3

[11] Ubuntu USN-3413-1, September 12, 2017. BlueZ CVE-2017-1000250, distribution packages and historical versions. https://ubuntu.com/security/notices/USN-3413-1

[12] Ubuntu USN-3420-1, September 18, 2017. Kernel CVE-2017-1000251, Ubuntu 16.04 package flavors, reboot and ABI guidance; also contains unrelated fixes. https://ubuntu.com/security/notices/USN-3420-1
