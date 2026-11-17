# BootHole: A Fatal Error That Returned and the Secure Boot Revocation Problem

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Platform, firmware and vulnerability-management owners, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 14 min (3,253 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of BootHole, you need to separate a signature check from safe execution or a patch from revocation, or you are planning Secure Boot revocation with its ordering and recovery-media consequences

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [4. Authentic code is not necessarily safe code](#_4-authentic-code-is-not-necessarily-safe-code), [6. The rollback problem made revocation essential](#_6-the-rollback-problem-made-revocation-essential)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Hardware Security Reference](/HARDWARE_SECURITY_REFERENCE.md), [Firmware and IoT Security Reference](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CVE Reference](/CVE_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment

BootHole, CVE-2020-10713, was disclosed publicly on July 29, 2020. It was a GRUB2 configuration-parser vulnerability with implications for UEFI Secure Boot. Its central lesson was not that cryptographic signatures had been mathematically broken. A correctly signed program could process attacker-controlled configuration unsafely and execute unintended code after the signature check had succeeded. [1]

The response was unusually difficult because fixing the parser did not make older signed vulnerable programs disappear. A device that still trusted those older programs could accept them again. Complete protection therefore involved both corrected boot components and withdrawal of trust from vulnerable predecessors, with ordering and compatibility consequences for installed systems and recovery media. The July 29 maintainer announcement explicitly warned that replacing binaries alone did not close that path. [2]

This was not an unauthenticated network worm. The reviewed advisories require substantial existing access, such as administrative privilege or physical access. Those prerequisites reduce the set of immediate attackers but do not erase the security boundary: Secure Boot is intended to constrain what executes before the operating system even when an attacker has acquired privileged access within that operating system. [3]

The most instructive evidence is therefore a combination of a small source patch, a large cross-vendor trust transition, and documented boot regressions during deployment. The public record supports those findings. It does not establish a named BootHole victim, a global compromise count or a financial-loss total.

## 1. Scope and source method

This study uses original Eclypsium research, a preserved source patch, maintainer communications, Oracle's first-person coordination account, Ubuntu security notices, Red Hat advisories, an NSA technical advisory and Microsoft's retained DBX guidance. It distinguishes the original CVE from additional flaws discovered during the surrounding review. It also separates a vulnerability in GRUB2 from flaws in firmware itself.

The Eclypsium page now displays a July 2026 update date alongside its original July 2020 publication. Red Hat's overview was updated in September 2021. Ubuntu's knowledge-base page retains historical future-tense deployment plans. Those pages are valuable records, but they should not be treated as frozen publication-day snapshots or current instructions for a 2026 system. Their dated notices and patch artifacts provide firmer anchors for specific milestones.

Retrieval was incomplete in defined places. The GNU mailing-list patch-series page timed out twice; the Debian security overview returned 404; the Debian release announcement returned 403; the UEFI revocation-list page returned 403. The exact parser patch was available through Debian Sources, and the maintainer announcement was readable through the oss-security archive. This study does not claim to have inspected an unavailable full revocation list or a complete distribution-by-distribution deployment history.

No firmware settings, boot databases or live systems were modified for this research. The discussion explains failure conditions and recovery dependencies without providing an exploit payload or instructions to weaken Secure Boot.

## 2. Dated sequence: discovery, coordinated release and repair follow-up

Oracle's September 17, 2020 retrospective says GRUB2 maintainers were approached by Eclypsium in early April. It describes coordination involving roughly one hundred participants from eighteen companies or organizations, and reports that the work extended beyond the bootloader to signing and revocation dependencies. This is the participants' account, not an independently audited attendance count. [4]

The preserved parser patch carries an April 15 author date. That timestamp identifies an authored source change, not the date every distribution shipped it. The public disclosure and Ubuntu's first security notice followed on July 29. NSA issued its advisory on July 30. Red Hat issued a shim bug-fix advisory on August 1, and Ubuntu published its regression notice on August 4. [3,5,6,7,8]

That sequence shows why a single patch date would be misleading. The source correction existed before the coordinated announcement. Products then distributed corrected packages, replacement signatures and follow-up fixes on their own schedules. The broader trust transition could not be measured only by when one code repository changed.

Nor should the later regression notices be described as proof that the original vulnerability remained uncorrected in every updated binary. They document separate failures affecting boot availability. Security correction, distribution integration and successful deployment were related but distinct stages.

## 3. The parser contract failed at error handling

The preserved patch is titled "yylex: Make lexer fatal errors actually be fatal." Its explanation identifies a mismatch between a generated lexer and its host application's error handler. The lexer expected a fatal-error call to stop processing. GRUB2's handler instead printed a message and returned, allowing the surrounding processing to continue. The patch changes the handler from grub_printf to grub_fatal in grub-core/script/yylex.l. [5]

This is a more informative root cause than simply saying that a long configuration string caused an overflow. The implementation already recognized a condition it could not safely handle. The missing property was a reliable transition out of the unsafe path. Detecting an invalid condition is not equivalent to containing it.

Eclypsium describes the affected input as the external grub.cfg configuration and explains that the file typically lacked the executable signature protection applied to the signed shim and GRUB2 binaries. That allowed the malicious input to differ while the trusted executable itself remained intact. [1]

The original analytical conclusion is that a security check can fail through control flow even when its predicate is correct. If code after an error handler assumes that returning is impossible, a handler that merely logs the failure breaks that assumption. The meaningful repair is to make the failure path enforce the contract, not to improve the wording of the error message.

The small diff should not be mistaken for a small operational problem. A few changed source lines can sit in a component whose signature has already been distributed across a large trust ecosystem. Repair complexity then depends on deployment and trust inheritance, not the number of lines edited.

## 4. Authentic code is not necessarily safe code

Secure Boot establishes whether an executable is accepted by the platform's trust policy. It does not prove that the executable contains no exploitable parser or that every configuration file it later reads is harmless. BootHole matters precisely because those statements can diverge: a genuine authorized executable can interpret unauthorized input incorrectly.

The NSA advisory explains the role of shim: distributions embed their own key in this initial component, which then authorizes a distribution-signed bootloader. It states that the BootHole vulnerability was not in shim, even though trust in affected shim paths had to be withdrawn to prevent vulnerable GRUB2 versions from loading. [3]

That distinction keeps the causal account accurate. Revoking or replacing a component does not necessarily mean the original memory-safety bug was inside that component. It may instead be the available point at which a platform can stop trusting a vulnerable downstream artifact.

Likewise, a successful executable signature check is not evidence that subsequent execution remained trustworthy. The signature attests to the accepted file identity and integrity. It cannot retroactively constrain arbitrary behavior caused by a flaw while that file processes data. This case is therefore about the composition of authentication and memory safety, not the defeat of the signature algorithm.

## 5. Existing administrative access still left a boundary to cross

Red Hat's overview identifies prerequisite access such as physical control, influence over a PXE-boot network, or remote access with root privileges. It rates the issue Moderate within its own impact framework, while the maintainer disclosure gives the CVSS 3.1 base score as 8.2 with a local attack vector and high privileges required. Those are differently scoped assessments, not numbers that should be silently substituted for one another. [2,9]

The important question is what an attacker gains beyond the starting position. Operating-system administrator access is extensive, but a platform may still enforce restrictions on pre-operating-system code. A boot-chain bypass can undermine the integrity assumptions on which the next operating-system instance depends. Treating all administrator access as identical to all firmware or pre-OS authority would erase the boundary the feature is designed to preserve.

At the same time, the prerequisite must remain prominent. Calling BootHole a remote takeover flaw without explaining the prior access would mislead readers about exposure. A network route involved in a boot environment is not equivalent to a universally reachable unauthenticated internet service.

The study does not claim that persistence automatically survives every reinstall or every hardware replacement. That would depend on where attacker-controlled artifacts and trust settings remain. The reviewed records establish the potential to subvert boot, not an unconditional persistence property for all recovery procedures.

## 6. The rollback problem made revocation essential

The July 29 oss-security announcement explains why an attacker could reintroduce an older signed exploitable bootloader even after the installed copy had been corrected. It identifies the UEFI revocation list, dbx, as the means to prevent those previously accepted artifacts from loading and explicitly includes old installation media among the consequences. [2]

This distinguishes two completion states. A machine may currently boot a corrected component while still accepting a vulnerable predecessor. The first state demonstrates the active path; the second concerns the set of paths the platform would permit in the future. A successful boot after a package update proves neither that all older copies were removed nor that they would be rejected if supplied again.

Revocation changes the platform's acceptance policy. That is why it cannot be treated as ordinary cleanup of an unused package. It can affect a maintenance USB, a dormant second operating system, a network-provisioning image or a fallback environment that has not been used recently.

An appropriate retrospective therefore asks what remained trusted, not just what was installed. That framing is specific to this incident's signed-component rollback problem and explains why a simple software inventory would have been incomplete evidence of protection.

## 7. Update ordering was a security and availability requirement

NSA's historical guidance calls for updating boot components, testing the withdrawal of trust, then applying revocation broadly. It warns that revoking trust first can prevent startup and emphasizes representative testing across device models and firmware revisions. The same document includes installation media and multi-boot environments in the update scope. [3]

The sequencing problem can be understood without reproducing administrative commands. The system needs an accepted, corrected route to boot before the policy rejects the former route. If the old path is removed from trust before a viable replacement is available, the platform may enforce its policy correctly and still leave the owner unable to start the machine.

There are consequently two different reasons a post-update system might not boot. One is intended rejection of an old vulnerable component. Another is an unintended implementation regression in newly shipped software. Diagnosis must determine which occurred rather than assuming that every failed boot means the revocation mechanism malfunctioned.

This case does not support disabling Secure Boot as a permanent remediation. Removing the enforcement boundary may restore compatibility, but it does not restore the guarantee the response was meant to protect. Historical recovery procedures are not interchangeable with a completed secure configuration.

## 8. Distribution-specific trust choices mattered

Ubuntu's retained knowledge base says its response revoked the 2012 Canonical UEFI signing key used for vulnerable GRUB2 binaries and used a 2017 key for fixed binaries. It warns that the DBX is shared by operating systems on the same motherboard, so an update from one operating system can prevent another from starting. [10]

The inference is that dual-boot systems have a shared security-policy dependency even when their package managers are independent. Updating one distribution does not imply the second distribution's loader, rescue environment or installer has become compatible with the new trust policy. Ownership boundaries in software administration do not necessarily match boundaries in platform firmware.

Oracle's account adds another concrete complication: reuse of signing keys across boot artifacts forced broader re-signing. The maintainers recommended separate certificates for separate artifacts so that one future vulnerable component would not necessarily force unrelated components to be reissued. [4]

That recommendation is about reducing the consequences of revocation, not making signatures intrinsically stronger. The cryptographic algorithm can remain unchanged while the operational cost of withdrawing trust becomes smaller. Certificate architecture is therefore part of incident recovery design, not merely a build-system detail.

## 9. Windows exposure did not mean Windows used GRUB2 by default

Broad descriptions of BootHole affecting Windows require a qualification. NSA says Windows endpoints needed trust revocation when their firmware trusted the relevant certificate authority; it distinguishes that from replacing Linux boot components. Eclypsium similarly points to platforms trusting the Microsoft third-party UEFI authority. [1,3]

The conceptual distinction is between the software an operating system normally uses and the software its platform would permit to execute. A device can be exposed to an accepted vulnerable third-party boot path even if that path is not its normal one. Conversely, the presence of the Windows name alone does not establish every relevant trust setting or revocation state.

This is why the article avoids saying the Windows bootloader itself contained CVE-2020-10713. The identified bug was in GRUB2. Platform trust policy explained how the consequences could extend beyond systems normally booting that loader.

The exact current certificate and DBX state of a device cannot be inferred from this historical case study. It would require device-specific evidence. No such assessment was performed here.

## 10. Regression evidence: Ubuntu and Red Hat

Ubuntu's USN-4432-2, published August 4, explicitly says the initial security update introduced regressions that prevented some BIOS systems from booting, including pre-UEFI machines and UEFI configured in Legacy mode. It directs affected users to verify the bootloader's understanding of the boot-device location and installation. This is narrower than a claim that all Ubuntu systems broke or that only Secure Boot systems were affected. [8]

The distinction is instructive: a fix motivated by a Secure Boot vulnerability could have availability consequences outside Secure Boot mode because the updated software also served other boot configurations. Testing only the security feature's main configuration would not exhaust the deployment surface.

Red Hat's August 1 RHBA-2020:3262 is a shim bug-fix advisory for RHEL 8 and records a correction for crashes during startup on some systems. The broader BootHole overview explicitly advises against the earlier shim packages associated with the original security advisories and points to replacement packages. [7,9]

These vendor records establish real release corrections. They do not provide a fleet-wide failure rate or justify a universal statement about every Linux distribution. They also should not be collapsed into one shared bug merely because both appeared after BootHole updates. Their package identities, affected boot modes and notices remain separate evidence.

## 11. One named flaw prompted a broader review

Ubuntu's July 29 notice distinguishes CVE-2020-10713 from other issues in function handling, memory allocation, filesystem-related arithmetic, kernel-signature validation and initrd size handling. The notice requires both an updated bootloader and the later revocation step for full mitigation. [6]

Oracle's retrospective reports that further review used static analysis and led to twenty-eight patches, with distribution-specific variants. It also describes differences between upstream compiler requirements and the constraints of distribution toolchains. [4]

The analytical point is that the public nickname should not become a substitute for the vulnerability inventory. A single coordinated release can contain several independent defects. If a case history assigns every patch in the response to one configuration-parser CVE, it obscures what each repair actually addressed.

Similarly, later GRUB security disclosures should not automatically be described as the same original BootHole flaw returning. A shared component and a similar security consequence are not enough to establish identical root cause. This study stays focused on the 2020 parser failure and its immediate remediation ecosystem.

## 12. Present-day guidance is not the 2020 procedure

Microsoft's retained KB4575994 now says the article is deprecated: manual DBX updating described by the old article is no longer necessary because updates are delivered through monthly servicing. This is the current statement on that specific support page, not a verification that any particular device has installed them. [11]

A historical article that reproduces the old manual procedure without checking its status would mislead a reader trying to act today. The correct use of the record is to explain how the response evolved and refer current operations to applicable vendor guidance, rather than promote an obsolete procedure as evergreen advice.

This also illustrates why future-tense text in an old advisory needs care. A statement that a distribution planned to deliver revocations later is evidence of a phased plan at the time. It is not proof that the update is still pending years afterward, and it is not proof that every customer eventually installed it.

The inaccessible UEFI list prevents this study from independently validating the exact current entries or completeness of the historical revocation rollout. That limitation is explicit instead of hidden behind the general statement that a patch existed.

## 13. What the evidence does and does not prove

The source patch supports a specific control-flow defect. The advisories support prerequisites, affected components and response dependencies. Vendor notices support actual boot regressions and follow-up corrections. The coordination retrospective supports the participants' description of the cross-company process. None of those records, by itself, establishes a named attacker campaign exploiting this flaw.

Bootkit capability is not the same as an observed BootHole deployment. A vendor's discussion of other boot malware supplies context, not attribution to CVE-2020-10713. This study therefore reports no invented actor, victim count or loss estimate and makes no claim that absence of such evidence proves exploitation never occurred.

The strongest conclusion is about two separate trust failures. In the parser, an error routine failed to enforce the behavior its caller depended upon. In deployment, previously valid signatures could continue to authorize unsafe code until trust was deliberately withdrawn. Correcting the former without completing the latter left an important condition unresolved.

A successful response had to preserve both integrity and recoverability: accept corrected components, reject vulnerable predecessors, and maintain a working supported boot path. That is why BootHole belongs in a case-study collection not only as a memory-safety vulnerability but as an example of the operational consequences of revoking widely distributed signed software.

## Sources and reading scope

[1] Eclypsium, There's a Hole in the Boot, published 29 July 2020; retained page updated 28 July 2026. Discovery, configuration trust boundary and conditional cross-platform scope. https://eclypsium.com/research/theres-a-hole-in-the-boot/

[2] John Haxby, oss-security maintainer announcement, 29 July 2020. Original CVE, prerequisites, rollback and revocation consequences. https://www.openwall.com/lists/oss-security/2020/07/29/3

[3] NSA, Mitigate the GRUB2 BootHole Vulnerability, July 2020 revision 1.0, released 30 July. Ordered remediation, shim distinction, Windows scope and testing cautions. https://media.defense.gov/2020/Jul/30/2002467902/-1/-1/0/CSA_MITIGATE_THE_GRUB2_BOOTHOLE_VULNERABILITY_20200730_NSA_GOV%20-%20COPY.PDF

[4] Oracle Linux engineers, An inside look at CVE-2020-10713, 17 September 2020. First-person coordination account, signing-key reuse and broader patch work. https://blogs.oracle.com/linux/an-inside-look-at-cve-2020-10713-aka-the-grub2-boothole

[5] Peter Jones patch preserved in Debian Sources, grub2 2.04-12, CVE-2020-10713.patch; author date 15 April 2020. Fatal-handler contract and minimal code change; no exploit reproduced. https://sources.debian.org/patches/grub2/2.04-12/CVE-2020-10713.patch/

[6] Ubuntu USN-4432-1, 29 July 2020. Distinct CVEs and paired bootloader/revocation response. https://ubuntu.com/security/notices/USN-4432-1

[7] Red Hat RHBA-2020:3262, 1 August 2020. RHEL 8 shim correction for boot crashes on some systems. https://access.redhat.com/errata/RHBA-2020:3262

[8] Ubuntu USN-4432-2, 4 August 2020. Regression in some BIOS and Legacy-mode systems; not a universal outage count. https://ubuntu.com/security/notices/USN-4432-2

[9] Red Hat Boot Hole overview, public 29 July 2020; updated 3 September 2021. Prerequisites, vendor severity framing and replacement-shim guidance. https://access.redhat.com/security/vulnerabilities/grub2bootloader

[10] Ubuntu BootHole knowledge base, published 29 July 2020; retained text reviewed 16 November 2026. Canonical signing-key transition and multi-boot dependency. Historical future-tense plans not represented as current status. https://ubuntu.com/security/vulnerabilities/boothole

[11] Microsoft KB4575994, retained deprecated support page reviewed 16 November 2026. Current notice superseding manual DBX procedure; not a device-compliance audit. https://support.microsoft.com/en-us/servicing/os/secure-boot/2020/12/microsoft-guidance-for-applying-secure-boot-dbx-update-kb4575994
