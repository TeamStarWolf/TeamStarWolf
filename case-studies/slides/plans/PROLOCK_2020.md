# Slide plan: ProLock 2020: A Ransomware Operation's Unreliable Promise

- Study: case-studies/PROLOCK_2020.md
- Cover title: ProLock 2020 / The Unreliable / Recovery Promise
- Subtitle: A ransomware operation whose decryptor could corrupt large files, where a supplied key was not restored data and shared tooling was not one actor.
- Published: 18 November 2026
- Notes: Evidence-bounded history; no malware, criminal portal or stolen data was accessed, and no exploit code is reproduced.

## EXECUTIVE SUMMARY | The final name does not answer the real questions

- ProLock's hardest questions are not answered by identifying its final executable.
- The record separates a predecessor, a successor, several intrusion paths and operators who changed payloads.
- The criminal promise to reverse encryption could itself add more corruption to the files.
- The disappearance of one ransomware name would not remove the access operations that delivered it.
Caption: Evidence grade: Confirmed framing; no single victim or payment confirmed.
Notes: Executive-assessment framing; sources are [1] through [10], with no malware or criminal portal accessed.

## KEY FACTS | Dated facts, bounded figures, no victim total

Stat: Mar 2020 | ProLock appears after PwndLocker
Stat: 8,192 | Start bytes left unchanged in sample
Stat: 64 MB | Size above which decryptor could corrupt
Stat: 2019-0859 | CVE seen in privilege escalation
- Group-IB dated ProLock to March 2020, after PwndLocker's late-2019 activity. [2]
- Sophos found files under 8,192 bytes skipped and the first 8,192 bytes of larger files unchanged. [3]
- A public advisory warned ProLock's criminal decryptor could corrupt files larger than 64 MB. [4]
- Reported ransom figures were demands, not verified payments. [5]
Caption: Evidence grade: Confirmed and Reported, dated advisories and research.
Notes: Figures from [2][3][4][5]; the decryptor warning is a relayed advisory, not an independent victim experiment.

## PART 1 | Predecessor, successor, access and operators differ

- A predecessor's recoverable weakness is not the successor's recoverability.
- An access component, a ransomware payload and an operator cluster answer different questions.
- Keep affected and compromised, and claimed and confirmed, in separate fields.
- Combining the sources into one smooth attack chain would be dramatic but less accurate.
Caption: Evidence grade: Confirmed distinctions; original analytical framing.
Notes: Scope and evidence rules; the separation of access, payload and operator is the study's model [2][7].

## PART 1 | PwndLocker recovery was conditional, not universal

- Emsisoft announced a customized recovery service for PwndLocker, not a universal downloadable decryptor. [1]
- Recovery required the executable used in the attack, a file that normally deleted itself.
- A family label is a starting point for testing applicability, not a substitute for it.
- "Researchers cracked ProLock" would erase both the predecessor and the method's conditions.
Caption: Evidence grade: Confirmed vendor announcement; conditions stated.
Notes: Recovery conditions and executable requirement from [1]; the label caution is original analysis.

## PART 1 | A successor with several distinct access paths

- Group-IB's May 14 analysis placed ProLock's appearance in March 2020. [2]
- QakBot-assisted intrusion and weakly protected RDP are described as different routes.
- A payload could be concealed in an image file and activated by a separate loading sequence.
- Not every ProLock event involved QakBot, and not every QakBot infection reached ProLock.
Caption: Evidence grade: Reported research; relationship stated as conditional.
Notes: Attack-chain, QakBot and RDP routes from [2]; the conditional relationship is kept bounded.

## PART 1 | The loader mattered more than the executable

- Sophos's July 27 investigation assessed RDP as the most likely route in its mid-March case. [3]
- The recovered set included an image, a task definition and batch files.
- A PowerShell sequence extracted the payload into memory; an isolated executable did not reproduce encryption.
- Collecting the loading components is more informative than hunting one obvious executable.
Caption: Evidence grade: Demonstrated under stated conditions; single-case route.
Notes: Loader mechanism and the RDP assessment from [3]; images are not executable by themselves.

## PART 2 | The first 8,192 bytes were not a recovery service

- In the Sophos sample, files under 8,192 bytes were skipped and the first 8,192 bytes of larger files stayed unchanged. [3]
- An unchanged beginning cannot certify the integrity of the rest of the object.
- A file can still look like its expected type while the usable content is altered.
- Partial preservation under observed behavior is not free recovery of the file.
Caption: Evidence grade: Demonstrated, sample-bound; not every build.
Notes: Byte-threshold behavior from [3]; the integrity consequence is original analysis.

## PART 2 | A supplied decryptor is not restored data

- The August 3 advisory warned ProLock's criminal decryptor could corrupt files larger than 64 MB. [4]
- It relayed other reporting rather than publishing an independent victim experiment.
- Emsisoft's Fabian Wosar described fixing a decryptor defect that still required the attackers' keys. [10]
- Possessing key material and correctly restoring data are separate requirements.
Caption: Evidence grade: Reported advisory and attributed expert statement.
Notes: The 64 MB warning from [4]; the decryptor-defect assistance from [10], distinct from the PwndLocker announcement [1].

## PART 2 | Disruption reported without an ATM claim

- KrebsOnSecurity's May 11 report reproduced Diebold Nixdorf's account of activity found on April 25. [10]
- The company said it disconnected corporate systems and contained the spread.
- It reported disruption to a field-service request system, said ATMs and customer networks were not affected, and denied paying a ransom.
- These are preserved company statements, not an independent forensic audit.
Caption: Evidence grade: Reported company statements via one interview report.
Notes: All Diebold points attributed to the company as reproduced in [10]; containment and impact kept as separate entries.

## PART 2 | September tooling and the exfiltration question

- Group-IB's September 10 update added hijacked email threads and privilege escalation involving CVE-2019-0859. [5]
- BloodHound followed later by AdFind; separate teams was offered as one possible explanation, not proof.
- Group-IB observed exfiltration; Sophos saw no direct evidence of theft; Intrinsec saw no Rclone. [2][3][6]
- Keep a separate exfiltration status per engagement: observed, assessed, not observed or unresolved.
Caption: Evidence grade: Reported per engagement; negatives bounded.
Notes: Toolkit and CVE from [5]; the three exfiltration findings have different subjects [2][3][6].

## PART 2 | Operational continuity is not code identity

- Group-IB's November assessment argued QakBot-associated operators likely shifted from ProLock to Egregor. [7]
- It rested on operational similarities such as tooling and naming, not proof of a renamed executable.
- Egregor's code relationships were placed nearer other ransomware families.
- Egregor victim counts and demands are not transferred into ProLock's total; ANSSI's 2021 Lockean report adds comparison, not a new victim list. [8]
Caption: Evidence grade: Reported assessment; continuity, not code identity.
Notes: Migration assessment from [7]; Lockean cluster context from [8], with distinctions preserved.

## DEFENDER VIEW | What a credible recovery result would show

A credible recovery demonstration separates four states; each answers a different question.

| State | What it establishes | What it does not establish |
|---|---|---|
| Key obtained | Access to key material | A working restoration |
| Tool modified | A corrected decryptor | A decrypted sample |
| Sample decrypted | Output on a working copy | Validated production data |
| Data validated | Content matches a trusted reference | A family-wide recovery rate |
Caption: Evidence grade: Original defensive guidance from the integrity problem.
Notes: Four-state model and the untouched-copy discipline from the study's recovery analysis [3][4][10].

## CROSS-CUTTING THEMES | Where the record is overstated and understated

Left: Easy to overstate
- "Researchers cracked ProLock" as universal free recovery.
- A paid ransom or a supplied decryptor as restored data.
- Shared QakBot access as one named actor across cases.
Right: Easy to understate
- A decryptor defect that could corrupt large files after payment.
- A multi-stage intrusion with preparatory access, not an instant attachment.
- Demands recorded as demands, never as confirmed payments.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn across [1][2][3][4][5][7]; denominators and recovery stages kept separate.

## CLOSE | Can the organization trust its data again?

- A predecessor's recoverability did not guarantee the successor's.
- A supplied decryptor did not guarantee intact data.
- A common access component did not establish a single actor, and a migration did not prove a rebrand.
- The strongest account names what was recovered, what was missing, and whether the data can be trusted again.
Caption: Evidence grade: case-specific conclusions, outcome claims bounded.
Notes: Conclusion synthesis across [1] through [10]; precision over an unsupported victim or payment total.
