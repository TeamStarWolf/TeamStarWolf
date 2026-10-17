# Voice and Credibility Guide

How TeamStarWolf writes and looks, for a reader who checks every claim against its source.

## Sentences

- Write plain declarative sentences: what a thing does, under what conditions.
- Use English (US) spelling and the serial (Oxford) comma.
- No exclamation marks outside quotations, no em-dashes (U+2014), and no emoji. A plain check mark (U+2713) in a table is fine; the emoji forms U+2705 and U+2714 are not.

## Terms

- Use ATT&CK's terms exactly: tactic, technique, sub-technique, procedure, group, software, campaign, mitigation, data component, detection strategy, analytic.
- A mitigation (ATT&CK), countermeasure (D3FEND), and control (NIST SP 800-53) are different objects; say which.
- Put identifiers, paths, and literal values in code font: `T1059.001`, `CAPEC-66`, `data/attack/technique_profiles.jsonl`.
- Give the framework version when a fact depends on it: "in ATT&CK v19.2".

## Claims and numbers

- Every count comes from a script. `scripts/build_stats.py --check` fails CI when a front-door page misstates a technique, group, software, campaign, detection strategy, analytic, Engage, or layer count.
- Do not write a count no script computes (guides, learning paths, pages). Script-written counts sit between `<!-- name:start -->` and `<!-- name:end -->` markers; the lint skips them.
- Cite the primary source for every claim about an external framework, standard, product, or incident.
- State the limits: "The ICS and Mobile atlases carry no NIST SP 800-53 control mappings."
- Separate measured from reported facts; say when a fact was not checked.

## Words we do not use

Each says how the writer feels, not what the thing does; name the measurable property. The lint also catches inflections (`leveraged`) and spaced spellings (`battle tested`), except `one stop`, `must have`, and `next level`.

`comprehensive`, `powerful`, `cutting-edge`, `state-of-the-art`, `world-class`, `best-in-class`, `industry-leading`, `enterprise-grade`, `military-grade`, `next-level`, `game-changing`, `game-changer`, `revolutionary`, `revolutionize`, `groundbreaking`, `unparalleled`, `seamless`, `effortless`, `supercharge`, `blazing-fast`, `lightning-fast`, `unbreakable`, `hack-proof`, `unhackable`, `one-stop`, `must-have`, `battle-tested`, `leverage`, `empower`.

Write "a disassembler with a decompiler and a scripting API", not `a powerful disassembler`. Proper names pass (Seamless SSO). Use `robust`, `unlock`, and `ultimate` only in their technical sense.

## Provenance and credit

- A page drafted or substantially revised with an AI assistant carries this line under its title: "Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17." Do not apologize for the page.
- Upstream object names and quoted descriptions are reproduced verbatim, never edited for voice; the lint skips text matching the MITRE datasets under `data/`.
- Credit upstream work by name and link: [MITRE ATT&CK](https://attack.mitre.org/), the [Center for Threat-Informed Defense](https://ctid.mitre.org/), [SigmaHQ](https://github.com/SigmaHQ/sigma), and every project whose data we reuse. [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) records their terms.
- Where ATT&CK content is reproduced, carry this notice word for word: "© The MITRE Corporation. This library includes material from MITRE ATT&CK®, used under the MITRE ATT&CK Terms of Use. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE." CAPEC, D3FEND, and ATLAS content carries that framework's notice from THIRD_PARTY_NOTICES.md.

## Persona and look

- The TeamStarWolf name and STARWOLF 64 art are naming and art only, never a claim about people, affiliations, or capability. Star Fox is a Nintendo trademark; this project is not affiliated with or endorsed by Nintendo.
- No maintainer's or owner's personal name appears; researchers and authors are credited by the names they publish under.
- The site defaults to the dark theme; identifiers and paths are monospace.

## How the lint works

`scripts/check_voice.py` fails CI on hits not recorded in `scripts/baselines/voice.json` and on a pull request that raises a baselined total. `--update-baseline` only lowers counts.
