# SHAttered: The SHA-1 Collision That Made Migration Tangible

*A TeamStarWolf case study. Published 16 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Cryptography and application engineers, secure-development and supply-chain teams, and security architects

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 9 min (2,161 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want an evidence-bounded account of the 2017 SHA-1 collision, you need to tell a collision from a second preimage or a detector from a stronger hash, or you are planning a hash migration

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive assessment](#executive-assessment), [2. What a collision establishes](#_2-what-a-collision-establishes), [7. Subversion exposed an application-level failure](#_7-subversion-exposed-an-application-level-failure)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md), [DevSecOps Reference](/DEVSECOPS_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive assessment
On February 23, 2017, Google and CWI announced a practical SHA-1 collision: two PDF files with different visible contents but the same digest. It was a research demonstration, not a reported theft of signing keys or a ransomware incident. The public artifacts made a failed cryptographic assumption inspectable. They did not show that an attacker could replace any previously chosen file while preserving its hash. [1]

This focused draft examines the demonstration, its computational scale, application-specific consequences and the response by software maintainers. It is shorter than a full cryptanalytic monograph. It separates what the researchers demonstrated from what particular systems would have to do before the result could become an attack.

The most useful lesson is not that every SHA-1 operation failed at once. It is that matching digests could no longer bear the same adversarial trust. Migration, collision detection and application rejection were different responses to that loss.

## 1. Evidence and reading scope
The account uses the original announcement, the research paper hosted by CWI, the researcher's preserved project page, NIST's contemporary response, Apache's Subversion advisory, GitHub's response and Git's transition document. A later chosen-prefix result is included only to explain how the attack model changed.

The current shattered.io domain presented unrelated contemporary news material in search results. This draft therefore uses the preserved project page on Marc Stevens's research site and CWI's paper repository rather than treating everything presently on the historical domain as the original team's work.

The ePrint PDF endpoint returned a forbidden response; the CWI copy was retrieved. Selected introduction, contribution and scope passages were reviewed. The differential-path search, computational execution and example PDF hashes were not independently reproduced. No files were submitted to any public collision checker. Current Git documentation is identified as later documentation, not proof of what every deployment supported in 2017.

## 2. What a collision establishes
A collision supplies two different inputs whose computed digest is the same. A second-preimage problem instead starts with a particular existing input and asks for another input matching it. Those are not interchangeable tasks.

GitHub's contemporary explanation explicitly said SHAttered did not generate a collision against an existing object. The attack produced a prepared pair. The distinction limits claims about already published repositories: a demonstration of colliding documents is not evidence that arbitrary old commits can be rewritten invisibly. [6]

Nor does a collision reveal a signature's private key. In an affected signing workflow, the problem is that the digest may fail to distinguish the intended data from different data. The cryptographic signature operation can behave as designed while the binding between digest and document becomes inadequate.

This is why “SHA-1 was decrypted” is the wrong description. Hashing and encryption solve different problems. The incident concerns a failed collision-resistance assumption, not a recovered encryption key.

## 3. The warning period preceded the demonstration
NIST's February 24, 2017 response traced the research trajectory to Wang, Yin and Yu's 2005 work, which showed collision techniques requiring less work than generic search. NIST said it deprecated SHA-1 in 2011 and disallowed its use for digital signatures at the end of 2013. It urged migration to SHA-2 or SHA-3 for applications relying on collision resistance. [3]

These dates matter because the public collision was not the first warning or the first policy action. Treating February 2017 as the day an otherwise unchallenged algorithm suddenly became suspect erases the central migration failure: theoretical weakness had already become sufficient reason to change.

There is also a difference between a standards body's restriction and universal removal from software. An organization can publish a transition policy while applications retain old formats, compatibility paths or internal identifiers. The research demonstration exposed the consequence of that gap; it did not measure the worldwide completion rate of migration.

## 4. Full SHA-1 and the chosen-prefix distinction
The paper describes an identical-prefix collision for full SHA-1. A common prefix is followed by different collision material, with a common suffix compatible with the equality. It reports an executed effort equivalent to about 2^63.1 compression-function calls. [2]

That technical description is narrower than a general ability to begin with two arbitrary, independently meaningful prefixes and make them collide. It is also different from earlier work on reduced versions or freestart compression-function settings. The contribution was a concrete collision for the full hash function under its actual operation.

The distinction explains why the PDF format mattered. Demonstrating that two byte strings collide is one result. Arranging for the strings to remain valid documents with substantially different visible meaning makes the risk legible to people who use signatures and content identifiers. The study does not provide a document-forgery recipe or reproduce the collision blocks.

The mathematical result and the document demonstration should be recorded separately: a collision is the primitive-level failure; the surrounding file format determines how much useful meaning the two files can carry.

## 5. Computation was expensive, but generic search was much worse
Google's announcement described roughly nine quintillion SHA-1 computations, about 6,500 CPU-years for the first phase and 110 GPU-years for the second. It said the technique was more than 100,000 times faster than brute force. These are reported equivalent processing efforts, not elapsed calendar duration. [1]

The publication and CWI announcement use approximately 100 GPU-years rather than Google's 110. This draft retains that source difference instead of silently presenting one rounded estimate as an exact universal total. CWI also described the joint project as more than two years of work combining cryptanalysis and Google's computing infrastructure. [2, 4]

A CPU-year and a GPU-year are not interchangeable units that should be casually added into a single elapsed runtime. Hardware, implementation and parallelism affect interpretation. Likewise, a historical estimate is not a current purchase price for reproducing the work.

The engineering significance is the achieved computation, not a claim that collisions became free. Practical cryptanalysis can remain resource-intensive while becoming feasible for organizations with substantial infrastructure.

## 6. The PDF demonstration and its limits
The researcher's preserved project page describes two PDFs displaying different content while sharing a SHA-1 digest. It uses alternative rental agreements as an example of why a signature tied only to that digest could be misleading. The page also distinguishes potential application classes from observed abuse: its answer about malicious use was that none was known to the researchers at that time. [5]

That historical statement is not a permanent assurance that no one later used SHA-1 weaknesses. It is the team's stated knowledge at disclosure. This study identifies no victim count, financial loss or attributable criminal campaign for SHAttered itself.

The team also presented collision detection, including protection for certain Google services. Such detection was a response to recognizable cryptanalytic structure, not a proof that the original SHA-1 collision-resistance property had been restored. A detector and a replacement hash have different assurance stories.

For an archive, the distinction is practical: preserve the research result, but do not store a pair of dangerous test artifacts in production systems simply to see what happens.

## 7. Subversion exposed an application-level failure
Apache's advisory identified servers through version 1.9.5 as affected. In FSFS or FSX repositories, representation sharing could deduplicate the colliding files on their SHA-1 checksum so only one file's content was stored. The initial commit could succeed while later operations failed because the files' MD5 checksums differed. [7]

The historical fixes were 1.9.6 and 1.8.18 with representation sharing enabled. Apache stressed that disabling sharing was not a complete solution: clients also relied on SHA-1 and could encounter problems. BDB repositories were outside the affected storage case. These are historical version boundaries, not recommendations to deploy those now-old releases. [7]

The failure was not a stolen secret. It was an application treating equal hashes as sufficient evidence of equal content. That makes SHAttered relevant beyond signatures. Content-addressed storage and deduplication can turn a cryptographic collision into missing data or inconsistent state.

The advisory's configuration condition matters as much as the version number. A list saying merely “upgrade Subversion” loses the reason the patch worked and the circumstances in which it did not.

## 8. Git's object boundary changed the demonstration
GitHub's March 20, 2017 response announced detection and rejection of Git content showing collision-attack evidence. It also explained why the published PDFs did not themselves have colliding Git object names: Git hashes object-specific header information as well as file bytes. A separate computation would be necessary to produce a collision in that representation. [6]

This is an unusually useful qualification. The same mathematical weakness can have different immediate consequences in different encodings. A raw file digest and a structured object's digest are not necessarily the same input to the hash function.

Git's later transition document records hardened SHA-1 as the default from version 2.13.0, while still advocating migration beyond SHA-1. It explains that object names connect file contents, trees and revisions, making a hash transition a data-model and compatibility problem rather than a one-line replacement of a checksum call. [8]

The defensible conclusion is neither “Git was unaffected” nor “the PDFs compromised all Git history.” The primitive was weak; the demonstrated artifacts and each application's representation had to be assessed separately.

## 9. Detection bought time; it did not complete migration
A collision detector can reject inputs displaying the structure of covered attacks, including when only one half of a pair is available. That differs from comparing two objects already present. The response can therefore help at ingestion, before both conflicting objects are seen.

But coverage is a property of the detector and attack families it recognizes. Git's transition rationale explicitly avoids assuming that future SHA-1 attacks will always have viable mitigations. Its objective is migration to a stronger hash, not an indefinite promise that hardening makes SHA-1 equivalent to an unbroken design. [8]

This case suggests a useful review question: what exact security claim remains after a workaround? “Known collision attempts are rejected” is narrower than “adversarial collisions are infeasible.” The former can be valuable without justifying the latter.

For long-lived repositories, signatures and archives, migration must also preserve the ability to interpret old objects. Eliminating new dependence and preserving historical evidence are related but distinct engineering goals.

## 10. Later chosen-prefix work should not be backdated
The later SHA-1 is a Shambles project reported a practical chosen-prefix collision and a PGP identity-certification demonstration. Its authors explained the stronger capability: the two prefixes can be independently selected before collision material is constructed. They described discussions with GnuPG beginning in May 2019 and a countermeasure in version 2.2.18, released November 25, 2019. [9]

Those developments should not be attributed to the February 2017 SHAttered demonstration. They show why an attack taxonomy belongs in an incident chronology. A label such as “SHA-1 broken” can conceal improvements in attacker freedom and application feasibility.

The later researchers also distinguished collision weaknesses from preimage resistance and from HMAC usage. That is not an endorsement of continued SHA-1 deployment. It is a reminder that different constructions depend on different properties, and a security finding should name the property it actually defeats. [9]

This draft does not extend the later result into a complete history of every SHA-1 protocol retirement.

## 11. Findings and open limits
SHAttered established a concrete collision and illustrated meaningful document ambiguity. Software maintainers then had to evaluate their own encodings, trust decisions and storage assumptions. Subversion and Git supplied different, documented examples of that evaluation.

The records support a migration case, not a global compromise claim. This research pass did not independently benchmark the computation, verify the example-file hashes or audit detector completeness. It also did not inspect a live repository for exposure.

A deeper follow-up could compare the paper's experimental sections with released implementation revisions and reproduce harmless digest checks in an isolated environment. Those steps are not implied by reading the publication. Until performed, the package should remain a focused, source-based historical draft.

## Sources and reading scope

[1] Google Security Blog, Announcing the first SHA1 collision, 23 February 2017. Announcement and computation figures. https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html

[2] Stevens et al., The First Collision for Full SHA-1, CRYPTO 2017, CWI-hosted paper. Selected introduction and contribution passages; experiments not reproduced. https://ir.cwi.nl/pub/26763/CRPT1111.pdf

[3] NIST, Research Results on SHA-1 Collisions, 24 February 2017. Deprecation chronology and migration position. https://csrc.nist.gov/News/2017/Research-Results-on-SHA-1-Collisions

[4] CWI, CWI and Google announce first collision for Industry Security Standard SHA-1. Body dates announcement 23 February; page publication label 27 February 2017. https://www.cwi.nl/en/news/cwi-and-google-announce-first-collision-for-industry-security-standard-sha-1/

[5] Marc Stevens, preserved SHAttered project page. Historical demonstration, Q&A and known-abuse limits. https://marc-stevens.nl/research/shattered.io/

[6] GitHub, SHA-1 collision detection on GitHub.com, 20 March 2017, updated 4 January 2019. Object-header distinction and response. https://github.blog/news-insights/company-news/sha-1-collision-detection-on-github-com/

[7] Apache Subversion, SHA-1 collision advisory. Historical versions, storage mechanism and representation-sharing conditions. https://subversion.apache.org/security/sha1-advisory.txt

[8] Git project, hash-function-transition documentation, accessed 16 November 2026. Later documentation; background and objective reviewed, not a 2017 deployment inventory. https://git-scm.com/docs/hash-function-transition

[9] Leurent and Peyrin, SHA-1 is a Shambles project page. Chosen-prefix scope, GnuPG chronology and security-property distinctions; later context. https://sha-mbles.github.io/
