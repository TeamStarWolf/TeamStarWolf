# Slide plan: Ragnar Locker 2020: Ransomware Inside a Virtual Machine

- Study: case-studies/RAGNAR_LOCKER_2020.md
- Cover title: Ragnar Locker 2020 / Ransomware in a VM / Isolation reconsidered
- Subtitle: How a legitimate VM with writable host shares put harmful activity behind a trusted process, and why access, not the executable, defines isolation.
- Published: 18 November 2026
- Notes: The cover sets the frame: a configured-sharing case, not a proven hypervisor escape or a named-victim reconstruction.

## EXECUTIVE SUMMARY | A configured-sharing case, not a proven VM escape

- Per Sophos's May 2020 investigation, Ragnar Locker deployed ransomware inside a VirtualBox virtual machine with a small Windows XP guest.
- Running a program inside a virtual machine does not mean every file it can reach belongs only to that machine.
- The record supports deliberate file sharing exposing host data, not a proven hypervisor vulnerability or a universal detection failure.
- The recommendation: examine the authority and data access granted to an execution environment, not just the software's name and reputation.
Caption: Evidence grade: Confirmed observation; no VM escape established.
Notes: Executive framing; sources are [1] Sophos, [2] FBI, [3] Eurojust, [4] Oracle docs. No malware sample or criminal infrastructure was accessed.

## KEY FACTS | One observed deployment, carried inside a small virtual machine

Stat: 49 kB | Ransomware component size
Stat: 122 MB | Installer package
Stat: 282 MB | Virtual disk image
Stat: 3.0.4 | Sun xVM VirtualBox version
- An unsigned installer was delivered through a Group Policy task, per Sophos.
- It deployed Sun xVM VirtualBox 3.0.4 and a stripped-down Windows XP SP3 guest.
- Writable shared folders exposed host local, removable and mapped drives to the guest; preparation included service interruption and shadow-copy deletion.
Caption: Evidence grade: Confirmed; Sophos May 2020 observation.
Notes: Sizes, versions, the Group Policy delivery and shared-folder exposure from [1]; these describe the observed attack, not every family incident.

## PART 1 | Vulnerability, exploit and incident are not one claim

- A vulnerability, an exploit demonstration and an incident are distinct claims and must not be collapsed.
- Keep "affected" distinct from "compromised," and operators' claims distinct from confirmed findings.
- The sources give no complete victim list, no uniform intrusion sequence and no determination of criminal guilt.
- Enforcement records describe several suspects and a suspected developer, not one identified actor behind every incident.
Caption: Evidence grade: Confirmed boundaries; no in-the-wild escape claimed.
Notes: Scope and evidence discipline from [1] and the study's method section; the enforcement caveats from [3].

## PART 1 | Shared access changes the meaning of isolation

- Oracle's VirtualBox documentation describes shared folders exposing host files to a guest through Guest Additions.
- They do not require ordinary guest networking, and access can be read-only or read-write.
- Removing a network adapter does not reverse a separate folder-sharing decision.
- A useful model records each bridge independently: what crosses, in which direction and under whose control.
Caption: Evidence grade: Inferred, conceptual; not proof of 3.0.4 defaults.
Notes: Shared-folder mechanism and access options from [4]; current docs are later-version context, not retrospective proof of every historical setting.

## PART 1 | Process reputation is incomplete evidence

- A signed, familiar application can be trustworthy as software and still operate in an untrustworthy context.
- Host-side writes appeared under the virtualization process rather than as the guest ransomware executable.
- A host process name is a starting point, not a verdict; combine installation, identity and data-access evidence.
- Organizations can retain needed virtualization while making unexpected use visible, with a named owner and scope.
Caption: Evidence grade: Confirmed observation plus original analysis.
Notes: The host-process context from [1]; the investigative framing is the study's original defensive analysis.

## PART 2 | Three sources describe three bounded windows

Each source answers a different question over a different observation window.

| Source | Window | Supports | Does not establish |
|---|---|---|---|
| Sophos [1] | May 2020 | The VM deployment mechanism | That every incident used virtualization |
| FBI FLASH [2] | As of Jan 2022 | At least 52 entities, 10 sectors | A worldwide infection total |
| Eurojust [3] | Oct 2023 | 6 suspects, 9 servers, 168 alleged | A conviction or reconciled count |
| Oracle docs [4] | VirtualBox 7.2 | The shared-folder mechanism | All 3.0.4 options and defaults |
Caption: Evidence grade: Confirmed dated records; non-claims explicit.
Notes: Rows condensed from [1][2][3][4]; each count and date stays attached to its own source scope.

## PART 2 | The counts cannot be combined into one denominator

Stat: 52 | FBI identified entities (at least)
Stat: 168 | Companies in Eurojust allegation
Stat: 10 | Critical-infrastructure sectors
Stat: 9 | Servers taken down, 2023
- The sources use different dates, methods and case definitions and share no reconciled denominator.
- "At least 52" preserves incompleteness; one organization can contain many endpoints.
- The 168-company figure is a 2023 allegation, not the FBI count plus growth, and not a conviction record.
- First awareness in April 2020 is not a malware family's birth date.
Caption: Evidence grade: Reported, bounded to each source's scope.
Notes: FBI identified-entity count and sectors from [2]; the Eurojust allegation, suspects and servers from [3]; the figures are not subtractable.

## DEFENDER VIEW | Deployment authority deserves its own investigation

- A deployment system changes many machines efficiently, which creates a consequential trust relationship.
- The unsigned installer arrived through a Group Policy task; ask which identities could create it and whether approval records exist.
- Inventory should record ownership, approved guest images, data-sharing expectations and permitted install hosts.
- Separation of duties: preparing a package need not grant authority to deploy it everywhere.
Caption: Evidence grade: Original analysis anchored to [1].
Notes: The Group Policy delivery is the observation from [1]; the authority and inventory recommendations are the study's original design analysis, not claims about a named victim.

## DEFENDER VIEW | Detection must span the host and guest boundary

- Host telemetry, guest telemetry and central management records observe different parts of the same event.
- A practical hypothesis is unauthorized virtualization followed by unusual access to business data.
- Do not label all bulk writes malicious; backup jobs, indexing and migration also create substantial activity.
- Record collection gaps honestly; a missing guest view is a visibility limit, not proof the host saw nothing useful.
Caption: Evidence grade: Original defensive analysis.
Notes: Detection framing drawn from the study's detection-engineering section; evidence discipline follows [1].

## DEFENDER VIEW | Containment should follow access, not only the executable

- Removing one suspicious guest may stop one observed activity while leaving the introducing authority intact.
- Host-accessible paths can extend beyond the local disk to removable and mapped drives.
- Establish what the affected identity could actually reach; a drive name alone does not reveal ownership or sensitivity.
- Containment has observable criteria: the deployment path disabled, identities addressed, production access removed.
Caption: Evidence grade: Original analysis; access facts from [1].
Notes: The writable host, removable and mapped drive exposure is from [1]; the containment criteria are original recommendations, checked rather than inferred from a ransom message disappearing.

## DEFENDER VIEW | Backup independence and separate confidentiality conclusions

- The observed preparation included service interruption and shadow-copy deletion, so backups need independent authority.
- A copy continuously writable through the same authority as production can share the relevant failure mode.
- Separate the integrity of the backup from the cleanliness of the environment into which it is restored.
- Restoration answers availability; it does not by itself resolve what data may have been copied earlier.
Caption: Evidence grade: Confirmed prep from [1]; acceptance criteria original.
Notes: Shadow-copy deletion from [1]; the FBI's protective-backup advice is historical context [2]; acceptance and confidentiality-versus-availability tests are original analysis.

## CROSS-CUTTING THEMES | Where the case is overstated versus understated

Left: Easy to overstate
- A proven hypervisor escape, when the evidence shows configured sharing.
- One ransom total or victim count combined from sources with different denominators.
- A single named actor behind every Ragnar Locker incident.
Right: Easy to understate
- Legitimate software plus configuration can relocate harmful activity behind a trusted process.
- Each integration bridge, network and shared folders, is a separate security decision.
- Confirmed observations and operators' claims need separate conclusions.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn from [1][2][3]; keep configured sharing distinct from an exploit, and keep counts attached to their windows.

## CLOSE | A precise account beats an exploit story or a victim total

- Running inside a virtual machine does not isolate host files the guest was deliberately given access to.
- Keep vulnerability, exploit and incident distinct, and keep affected separate from compromised.
- The durable work: document approved execution environments, review the authority that deploys them, test the access across their boundaries.
- Open gaps: no complete victim list, no combinable counts, no proven escape and no proof of eradication from every endpoint.
Caption: Evidence grade: case-specific conclusions, bounded to the sources.
Notes: Conclusion synthesis across the study; rests on [1][2][3][4], with the strongest claim limited to configured sharing behind a host process context.
