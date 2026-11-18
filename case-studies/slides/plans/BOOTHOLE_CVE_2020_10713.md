# Slide plan: BootHole and the revocation problem

- Study: case-studies/BOOTHOLE_CVE_2020_10713.md
- Cover title: BootHole / Secure Boot bypass / The revocation problem
- Subtitle: A GRUB2 config-parser flaw turned a one-line fix into a cross-vendor trust transition carrying real boot-failure risk.
- Published: 18 November 2026
- Notes: The cover frames BootHole as a story about remediation difficulty, not broken cryptography.

## OVERVIEW | A signed program that ran unsafe code
- CVE-2020-10713, disclosed by Eclypsium on 29 July 2020, sat in GRUB2's parsing of its grub.cfg configuration.
- A correctly signed bootloader could execute attacker-controlled code after its signature check passed.
- The grub.cfg file usually lacked the signature protection applied to the signed shim and GRUB2 binaries.
- Secure Boot is meant to constrain pre-OS code even when an attacker already holds privilege inside the OS.
Caption: Evidence grade: Confirmed
Notes: This establishes the defect as a composition failure between a valid signature and unsafe later execution.

## TIMELINE | From April patch to August fixes
The response unfolded across months, not a single patch date.

| Date | Milestone |
| --- | --- |
| Early April 2020 | Eclypsium approached GRUB2 maintainers |
| 15 April 2020 | Parser patch authored |
| 29 July 2020 | Public disclosure; Ubuntu USN-4432-1 |
| 30 July 2020 | NSA advisory issued |
| 1 August 2020 | Red Hat RHBA-2020:3262 shim fix |
| 4 August 2020 | Ubuntu USN-4432-2 regression notice |
Caption: Evidence grade: Confirmed
Notes: The spread of dates shows why one patch date would misrepresent the trust transition.

## ROOT CAUSE | A fatal error that did not stop
- The preserved patch is titled "yylex: Make lexer fatal errors actually be fatal."
- The generated lexer expected a fatal-error call to halt processing.
- GRUB2's handler instead printed a message and returned, letting the surrounding processing continue.
- The fix changed grub_printf to grub_fatal in grub-core/script/yylex.l.
Caption: Evidence grade: Confirmed
Notes: The real defect was a missing transition out of the unsafe path, not a mis-worded error message.

## SCALE | A small diff, a large repair
Stat: 1 line | Core change: grub_printf becomes grub_fatal
Stat: 28 | Patches across the broader review
Stat: ~100 | Participants in the coordinated response
- Oracle reports 18 companies or organizations took part, with distribution-specific patch variants.
- Repair complexity came from deployment and trust inheritance, not the number of lines edited.
Caption: Evidence grade: Reported
Notes: The participant and patch counts are the coordinators' own account, not an audited tally.

## COMPOSITION | Authentic is not the same as safe
Left: What the signature proves
- The file's accepted identity and integrity under the platform's trust policy.
- That the platform agreed to run this exact executable.
Right: What it does not prove
- That the executable contains no exploitable parser.
- That every configuration file it later reads is harmless.
Caption: Evidence grade: Confirmed
Notes: The signature algorithm was never defeated; authentication and memory safety are separate properties.

## PREREQUISITES | Not a remote, unauthenticated worm
- The reviewed advisories require existing access, not remote unauthenticated reach.
- Red Hat lists physical control, PXE-boot network influence, or remote access with root privileges.
- Exploitation needs the privilege to modify grub.cfg or install a vulnerable signed bootloader.
- The prerequisite narrows the attacker set but does not erase the pre-OS boundary.
Caption: Evidence grade: Confirmed
Notes: Calling BootHole a remote takeover without the prior-access condition would mislead on exposure.

## SEVERITY | Two framings, not one number
Stat: 8.2 | CVSS 3.1 base, local vector, high privileges
Stat: Moderate | Red Hat impact rating in its framework
- The maintainer disclosure gives the 8.2 base score; Red Hat rates the issue Moderate.
- The two are differently scoped assessments and should not be silently substituted.
Caption: Evidence grade: Confirmed
Notes: Reporting both values keeps the severity account honest about its differing frameworks.

## ROLLBACK | Why a patch alone left the hole open
- Patching the parser did not remove older signed-but-vulnerable binaries from the field.
- An attacker with access could supply an older signed bootloader and have it accepted again.
- The UEFI revocation list, dbx, is the means to stop those predecessors from loading.
- A successful boot after an update does not prove old copies would be rejected if resupplied.
Caption: Evidence grade: Confirmed
Notes: This separates "patch available" from "safely deployed" and explains why revocation was essential.

## ORDERING | Revoke too early and the machine will not boot
- NSA guidance: update boot components, test the withdrawal of trust, then apply revocation broadly.
- Removing the old path before a corrected route exists can leave a machine unable to start.
- Two causes explain a post-update boot failure: intended rejection, or a shipped implementation regression.
- Revocation scope includes installation media and multi-boot environments.
Caption: Evidence grade: Confirmed
Notes: Sequencing was both a security and an availability requirement, since dbx changes acceptance policy.

## DISTRIBUTIONS | Shared firmware policy, separate owners
Left: Canonical key transition
- Revoked the 2012 Canonical UEFI signing key used for vulnerable GRUB2 binaries.
- Used a 2017 key for the fixed binaries.
Right: The shared DBX problem
- The DBX is shared by operating systems on the same motherboard.
- An update from one operating system can prevent another from starting.
Caption: Evidence grade: Confirmed
Notes: Dual-boot systems share a platform-policy dependency even when their package managers are independent.

## WINDOWS | Exposure did not mean GRUB2 was in use
- The bug was in GRUB2; the Windows bootloader did not contain CVE-2020-10713.
- NSA: Windows endpoints needed revocation when firmware trusted the relevant certificate authority.
- Eclypsium points to platforms trusting the Microsoft third-party UEFI authority.
- A device can permit a vulnerable third-party boot path that is not its normal one.
Caption: Evidence grade: Confirmed
Notes: Platform trust policy, not default bootloader choice, explains the cross-platform scope.

## REGRESSIONS | The fix broke boots it was not aimed at
Left: Ubuntu USN-4432-2
- The initial update introduced regressions on some BIOS systems.
- Pre-UEFI machines and UEFI in Legacy mode were affected, outside Secure Boot.
Right: Red Hat RHBA-2020:3262
- A RHEL 8 shim bug-fix for crashes during startup on some systems.
- The overview advises against the earlier shim packages and points to replacements.
Caption: Evidence grade: Confirmed
Notes: A fix motivated by Secure Boot had availability effects in boot modes the feature does not govern.

## INVENTORY | One nickname, several defects
Stat: 1 | Named CVE: CVE-2020-10713
Stat: 28 | Patches reported in the broader review
- Ubuntu's notice separates the parser CVE from function-handling, memory-allocation and other issues.
- Oracle reports the follow-up review used static analysis, with distribution-specific variants.
- A shared component and similar impact do not make later GRUB flaws the same root cause.
Caption: Evidence grade: Reported
Notes: The public nickname should not stand in for the actual vulnerability inventory.

## LESSON | Integrity and recoverability together
- The parser's error routine failed to enforce the behavior its caller depended on.
- Previously valid signatures kept authorizing unsafe code until trust was deliberately withdrawn.
- A sound response had to accept corrected components, reject predecessors, and keep a supported boot path.
- The public record shows no named victim, compromise count or financial-loss total.
Caption: Evidence grade: Inferred
Notes: BootHole belongs in the collection as much for its revocation economics as for the memory-safety bug.
