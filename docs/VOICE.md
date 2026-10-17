# Voice and Credibility Guide

How TeamStarWolf writes and looks, for readers who check every claim against its source.

## Sentences

- Write plain declarative sentences: what a thing does, under what conditions.
- Use English (US) spelling and the serial (Oxford) comma.
- No exclamation marks outside quotations, em-dashes (U+2014), or emoji. A plain check mark (U+2713) is fine; U+2705 and U+2714 are not.

## Terms

- Use ATT&CK's terms exactly: tactic, technique, sub-technique, procedure, group, software, campaign, mitigation, data component, detection strategy, analytic.
- A mitigation (ATT&CK), countermeasure (D3FEND), and control (NIST SP 800-53) are different objects; say which.
- Put identifiers, paths, and literal values in code font: `T1059.001`, `CAPEC-66`, `data/attack/technique_profiles.jsonl`.
- Give the framework version a fact depends on: "in ATT&CK v19.2".

## Claims and numbers

- Take counts from scripts. In CI, `scripts/build_stats.py --check` checks front-door counts of Enterprise techniques, groups, software, campaigns, detection strategies, and analytics, Engage activities and mappings, and Navigator layers; the lint flags hand-typed counts of references, guides, paths, and pages.
- Other counts are unchecked: leave them out, or have a script write them between `<!-- name:start -->` and `<!-- name:end -->` markers, which the lint skips.
- Cite the primary source for every claim about an external framework, standard, product, or incident.
- State the limits: "The ICS and Mobile atlases carry no NIST SP 800-53 control mappings."
- Separate measured from reported facts, and say which were not checked.

## Words we do not use

They describe feelings, not behavior; name the measurable property. Inflections (`leveraged`) and spaced forms (`battle tested`) count too, except `one stop`, `must have`, and `next level`.

`comprehensive`, `powerful`, `cutting-edge`, `state-of-the-art`, `world-class`, `best-in-class`, `industry-leading`, `enterprise-grade`, `military-grade`, `next-level`, `game-changing`, `game-changer`, `revolutionary`, `revolutionize`, `groundbreaking`, `unparalleled`, `seamless`, `effortless`, `supercharge`, `blazing-fast`, `lightning-fast`, `unbreakable`, `hack-proof`, `unhackable`, `one-stop`, `must-have`, `battle-tested`, `leverage`, `empower`.

Write "a disassembler with a decompiler", not `a powerful disassembler`. Proper names pass (Seamless SSO). Use `robust`, `unlock`, and `ultimate` only in their technical sense.

## Provenance and credit

- A page drafted or substantially revised with an AI assistant carries this line under its title, dated when last checked against its sources: `Drafted with an AI assistant from the sources cited; checked against them on <YYYY-MM-DD>.` No apology.
- Upstream names and quoted descriptions stay verbatim, never edited for voice; the lint skips text matching the MITRE datasets under `data/`.
- Credit upstream work by name and link: [MITRE ATT&CK](https://attack.mitre.org/), the [Center for Threat-Informed Defense](https://ctid.mitre.org/), [SigmaHQ](https://github.com/SigmaHQ/sigma), and every project whose data we reuse. [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) records their terms.
- Reproduced ATT&CK content carries this notice word for word: "© The MITRE Corporation. This library includes material from MITRE ATT&CK®, used under the MITRE ATT&CK Terms of Use. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE." Every other MITRE framework (CAPEC, CWE, D3FEND, ATLAS, Engage, CAR) carries its notice from THIRD_PARTY_NOTICES.md.

## Persona and look

- The TeamStarWolf name and STARWOLF 64 art are naming and art only, never a claim about people, affiliations, or capability. Star Fox is a Nintendo trademark; this project is not affiliated with or endorsed by Nintendo.
- No maintainer's or owner's personal name appears; credit researchers and authors by their published names.
- The site defaults to the dark theme; code font is monospace, without ligatures.

## How the lint works

`scripts/check_voice.py` fails CI on hits missing from `scripts/baselines/voice.json`, which holds the existing hits until they are fixed, and on a pull request raising a baselined total. `--update-baseline` only lowers counts unless `--allow-growth` records a new rule's existing hits.
