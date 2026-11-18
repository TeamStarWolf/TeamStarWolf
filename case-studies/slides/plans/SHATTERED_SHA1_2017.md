# Slide plan: SHAttered: The SHA-1 Collision That Made Migration Tangible

- Study: case-studies/SHATTERED_SHA1_2017.md
- Cover title: SHAttered / The SHA-1 collision that / made migration tangible
- Subtitle: A 2017 research collision showed matching SHA-1 digests could no longer carry adversarial trust; it was not a stolen key or a global compromise.
- Published: 16 November 2026
- Notes: Cover only; evidence-bounded account separating the demonstration from what systems would need before it became an attack.

## EXECUTIVE SUMMARY | A research demonstration, not a key theft or ransomware

On February 23, 2017 Google and CWI announced a practical SHA-1 collision and made a failed assumption inspectable.

- Two PDFs showed different visible content but computed the same SHA-1 digest.
- It was a research demonstration, not a reported key theft or ransomware incident.
- The artifacts did not show any previously chosen file could be rewritten at its hash.
- The lesson: matching digests could no longer bear the same adversarial trust.
Caption: Evidence grade: a Confirmed announcement; no attributed abuse.
Notes: Announcement and scope limits from Google's post [1].

## KEY FACTS | The numbers describe effort, not a stolen secret

Stat: 2^63.1 | Compression-function calls, reported
Stat: ~9e18 | SHA-1 computations, Google figure
Stat: 100,000x | Faster than generic brute force
Stat: 6,500 | CPU-years, first phase
- Google cited about 6,500 CPU-years and 110 GPU-years; CWI used about 100 GPU-years.
- CPU-years and GPU-years are not interchangeable units to sum into one runtime.
- Figures are reported equivalent effort, not elapsed time or a current price.
Caption: Evidence grade: Reported; not independently benchmarked.
Notes: Google computation figures [1]; the 2^63.1 and 100 GPU-year variant [2][4].

## PART 1 | A collision is not a second preimage or a decrypt

A collision and a second-preimage problem are different tasks, and neither recovers a key.

- A collision gives two different inputs with one digest, chosen together.
- A second preimage starts from an existing input and finds another that matches it.
- GitHub said SHAttered did not generate a collision against an existing object.
- A collision reveals no private key; it is failed collision resistance, not a decrypt.
Caption: Evidence grade: a Confirmed distinction from the sources.
Notes: The existing-object point from GitHub's explanation [6].

## PART 1 | Deprecation preceded the demo by years

The 2017 collision confirmed a known weakness; it did not start the clock on SHA-1.

- NIST traced collision techniques to Wang, Yin and Yu's 2005 work.
- NIST deprecated SHA-1 in 2011 and disallowed it for digital signatures by end of 2013.
- NIST urged migration to SHA-2 or SHA-3 for collision-resistance uses.
- February 2017 exposed an existing migration gap; it did not start the clock.
Caption: Evidence grade: Confirmed via the NIST chronology.
Notes: Deprecation dates and the migration position from NIST [3].

## PART 1 | The result was identical-prefix, not chosen-prefix

The paper's result is narrower than colliding two arbitrary, independently meaningful prefixes.

- The paper demonstrates an identical-prefix collision for full SHA-1.
- A shared prefix precedes different collision material and a compatible common suffix.
- Reported effort was about 2^63.1 compression-function calls.
- The study gives no document-forgery recipe and does not reproduce the collision blocks.
Caption: Evidence grade: Demonstrated for full SHA-1.
Notes: Identical-prefix scope and the 2^63.1 effort from the paper [2].

## PART 1 | The PDF demonstration was legible but bounded

The PDF framing made the risk legible without providing a general forgery capability.

- The preserved project page shows two PDFs with different content and one SHA-1 digest.
- It uses alternative rental agreements to show why a digest-only signature can mislead.
- At disclosure the team knew of no malicious use; that is not a permanent assurance.
- The study names no victim count, financial loss or attributed campaign for SHAttered.
Caption: Evidence grade: Demonstrated; no attributed abuse.
Notes: Demonstration, the Q&A and known-abuse limits from the project page [5].

## PART 2 | Subversion treated equal hashes as equal content

SHAttered became an application failure where content addressing assumed equal hashes meant equal data.

- Apache listed servers through 1.9.5 as affected in FSFS or FSX repositories.
- Representation sharing could deduplicate colliding files, storing only one content.
- A commit could succeed, then later operations failed because MD5 checksums differed.
- Fixes were 1.9.6 and 1.8.18; disabling sharing alone was not a complete solution.
Caption: Evidence grade: Confirmed historical version boundaries.
Notes: Affected versions, storage mechanism and fixes from the Apache advisory [7].

## PART 2 | Git's object boundary changed the consequence

The same weakness had different immediate effects depending on how the hash input was encoded.

- GitHub announced detection and rejection of content showing collision-attack evidence.
- The published PDFs did not collide as Git object names: Git also hashes header info.
- A separate computation would be needed to collide the object representation.
- Hardened SHA-1 became Git's default from 2.13.0, while still advocating migration.
Caption: Evidence grade: Confirmed per GitHub and Git docs.
Notes: The object-header distinction [6]; the hardened default and transition objective [8].

## PART 2 | Detection bought time; it did not complete migration

A collision detector narrows the live claim rather than restoring collision resistance.

- A detector can reject inputs with covered attack structure, even one half of a pair.
- That differs from comparing two objects already present; it helps at ingestion.
- Coverage is limited to the attack families the detector recognizes.
- Git's rationale targets migration, not an indefinite promise that hardening suffices.
Caption: Evidence grade: Confirmed scope; detector completeness not audited.
Notes: Detector behavior and the migration objective from the Git transition doc [8].

## DEFENDER VIEW | Defenders had three distinct responses, not one fix

Migration, collision detection and application rejection answered different parts of the loss.

- Migration to a stronger hash removed new dependence on SHA-1 collision resistance.
- Collision detection rejected inputs showing covered attack structure at ingestion.
- Application rejection handled formats that treated equal hashes as equal content.
- Do not store a pair of dangerous test artifacts in production just to observe behavior.
Caption: Evidence grade: Confirmed responses; completeness not audited.
Notes: Detection and the archive caution [5]; the migration goal [8].

## CROSS-CUTTING THEMES | Overstated claims versus the understated migration gap

The strongest labels overstate 2017 while the real gap is understated.

Left: Overstated
- "SHA-1 was decrypted" or "broken" conflates collisions with preimage and key recovery.
- Backdating 2019 chosen-prefix work (Shambles) onto the 2017 demo overstates its reach.
- "The PDFs compromised all Git history" ignores the object-header distinction.
Right: Understated
- Deprecation and migration failure predated 2017 and were the central gap.
- Content-addressed storage can turn a collision into missing data, beyond signatures.
- A workaround's claim (known attempts rejected) is narrower than infeasible.
Caption: Evidence grade: an Inferred synthesis of the study's framing.
Notes: The backdating caution and property distinctions [9]; the Git boundary [6][8].

## CLOSE | The records support migration, not global compromise

The evidence makes a migration case and leaves stated limits open.

- SHAttered gave a concrete collision and legible document ambiguity, not a global break.
- Maintainers had to assess their own encodings, trust decisions and storage assumptions.
- This pass did not benchmark the computation, verify example hashes or audit detectors.
- Eliminating new dependence and preserving old objects are related but distinct goals.
Caption: Evidence grade: Confirmed scope; open limits stated.
Notes: Findings and open limits drawn from the Subversion, Git and detector sections [6][7][8].
