# Voice and Credibility Guide

How TeamStarWolf writes and looks. The reader is a practitioner who will check our claims against the source; every rule here exists so that check passes. `scripts/check_voice.py` enforces the mechanical rules in CI.

## Sentences

- Write plain declarative sentences. Say what a thing does and under what conditions.
- Use English (US) spelling. Use the serial (Oxford) comma, as the front-door pages do.
- No exclamation marks in our own sentences. Quotations keep their own punctuation.
- No em-dashes (U+2014). Use a colon, a comma, parentheses, or a new sentence.
- No emoji. Typographic symbols such as a check mark in a table are fine.

## Terms

Use each framework's own terms exactly:

- ATT&CK: tactic, technique, sub-technique, procedure, group, software, campaign, mitigation, data component, detection strategy, analytic.
- Controls: a mitigation (ATT&CK), a countermeasure (D3FEND), and a control (NIST SP 800-53) are different objects. Name the one you mean.
- Put identifiers, file paths, commands, and literal values in code font: `T1059.001`, `G0016`, `CAPEC-66`, `AML.T0051`, `data/attack/technique_profiles.jsonl`, `Password1!`.
- Write the framework version when a fact depends on it: "in ATT&CK v19.2".

## Claims and numbers

- Every number comes from a script. Headline counts (references, guides, learning paths, pages, techniques) are computed by `scripts/build_stats.py` and checked in CI. Do not type them by hand; text a script writes between `<!-- name:start -->` and `<!-- name:end -->` markers is exempt from the lint.
- Every claim about an external framework, standard, product, or incident cites its primary source.
- State the limits. Examples: "The ICS and Mobile atlases carry no NIST SP 800-53 control mappings." "The CTID control mapping targets ATT&CK v16.1; techniques added later have none."
- Separate what was measured from what was reported, and say when a fact was not checked.

## Words we do not use

These say how the writer feels, not what the thing does. Replace each with the measurable property behind it.

`comprehensive`, `powerful`, `cutting-edge`, `state-of-the-art`, `world-class`, `best-in-class`, `industry-leading`, `enterprise-grade`, `military-grade`, `next-level`, `game-changing`, `game-changer`, `revolutionary`, `revolutionize`, `groundbreaking`, `unparalleled`, `seamless`, `effortless`, `supercharge`, `blazing-fast`, `lightning-fast`, `unbreakable`, `hack-proof`, `unhackable`, `one-stop`, `must-have`, `battle-tested`.

Instead of `a powerful disassembler`, write "a disassembler with a decompiler and a scripting API". Proper names that contain one of these words (the ATT&CK campaign Cutting Edge, Seamless SSO) are allowed.

## Provenance and credit

- Where generation matters, add one plain provenance line, for example: "Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17." Do not add disclaimers that apologize for the page.
- Credit upstream work by name and link: MITRE, the Center for Threat-Informed Defense (CTID), SigmaHQ, and every other project whose data or text we reuse. `THIRD_PARTY_NOTICES.md` records the terms of reused data.
- Wherever ATT&CK content is reproduced, carry the trademark line: "ATT&CK is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE."

## Persona and look

- TeamStarWolf is the public persona. The Star Fox naming and the STARWOLF 64 art are naming and art only. They are never a claim about people, affiliations, or capability. No personal names appear anywhere.
- The site defaults to the dark theme. Identifiers and paths are set in monospace.

## How the lint works

`python scripts/check_voice.py` scans the root Markdown and `guides/`, `disciplines/`, `case-studies/`, `tools-research/`, and `docs/`. It reports em-dashes, emoji, sentence-ending exclamation marks, the words above, and hand-typed headline counts. Hits that predate the lint are recorded in `scripts/baselines/voice.json`; a new hit fails CI. After cleaning a page, run `python scripts/check_voice.py --update-baseline` so the baseline only shrinks.
