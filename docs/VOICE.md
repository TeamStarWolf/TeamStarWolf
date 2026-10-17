# Voice and Credibility Guide

How TeamStarWolf writes and looks. The reader is a practitioner who will check our claims against the source; these rules exist so that check passes.

## Sentences

- Write plain declarative sentences. Say what a thing does and under what conditions.
- Use English (US) spelling and the serial (Oxford) comma.
- No exclamation marks outside quotations.
- No em-dashes (U+2014); use a colon, comma, parentheses, or a new sentence.
- No emoji. A check mark in a table is fine.

## Terms

- Use ATT&CK's own terms exactly: tactic, technique, sub-technique, procedure, group, software, campaign, mitigation, data component, detection strategy, analytic.
- A mitigation (ATT&CK), a countermeasure (D3FEND), and a control (NIST SP 800-53) are different objects. Name the one you mean.
- Put identifiers, file paths, commands, and literal values in code font: `T1059.001`, `CAPEC-66`, `AML.T0051`, `data/attack/technique_profiles.jsonl`.
- Write the framework version when a fact depends on it: "in ATT&CK v19.2".

## Claims and numbers

- Every count comes from a script; never type a headline count by hand. `scripts/build_stats.py` computes the reference-document count and the ATT&CK, Engage, and Navigator object counts. Its `--check` mode fails CI when a front-door page misstates a technique, group, software, campaign, detection strategy, analytic, Engage, or layer count.
- Do not write a count no script computes yet (guides, learning paths, pages). Script-written counts between `<!-- name:start -->` and `<!-- name:end -->` markers arrive in site phase P1.
- Cite the primary source for every claim about an external framework, standard, product, or incident.
- State the limits: "The ICS and Mobile atlases carry no NIST SP 800-53 control mappings." "The CTID control mapping targets ATT&CK v16.1; techniques added later have no CTID mapping of their own."
- Separate what was measured from what was reported, and say when a fact was not checked.

## Words we do not use

Each says how the writer feels, not what the thing does; name the measurable property instead. The lint also catches unhyphenated spellings.

`comprehensive`, `powerful`, `cutting-edge`, `state-of-the-art`, `world-class`, `best-in-class`, `industry-leading`, `enterprise-grade`, `military-grade`, `next-level`, `game-changing`, `game-changer`, `revolutionary`, `revolutionize`, `groundbreaking`, `unparalleled`, `seamless`, `effortless`, `supercharge`, `blazing-fast`, `lightning-fast`, `unbreakable`, `hack-proof`, `unhackable`, `one-stop`, `must-have`, `battle-tested`, `leverage`, `leveraging`, `empower`.

Instead of `a powerful disassembler`, write "a disassembler with a decompiler and a scripting API". Proper names are allowed (the ATT&CK campaign Cutting Edge, Seamless SSO). Use `robust`, `unlock`, and `ultimate` only in a technical sense (adversarial robustness, unlocking a volume or an account).

## Provenance and credit

- Where generation matters, add one plain provenance line: "Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17." Do not apologize for the page.
- Credit upstream work by name and link: [MITRE ATT&CK](https://attack.mitre.org/), the [Center for Threat-Informed Defense (CTID)](https://ctid.mitre.org/), [SigmaHQ](https://github.com/SigmaHQ/sigma), and every project whose data we reuse. [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) records their terms.
- Wherever ATT&CK content is reproduced, carry the trademark line: "ATT&CK is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE."

## Persona and look

- The Star Fox naming and STARWOLF 64 art behind the TeamStarWolf persona are naming and art only, never a claim about people, affiliations, or capability. No personal names appear anywhere.
- The site defaults to the dark theme, with identifiers and paths in monospace.

## How the lint works

`scripts/check_voice.py` records the hits that predate it in `scripts/baselines/voice.json`; a new hit fails CI. After cleaning a page, run `--update-baseline`; it only lowers counts (`--allow-growth` is for adding a word to the list). CI also fails a pull request that raises any rule's baselined total.
