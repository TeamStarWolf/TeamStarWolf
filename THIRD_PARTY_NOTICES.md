# Third-Party Notices

The TeamStarWolf reference library is released under the [MIT License](LICENSE).
It aggregates and reformats data from several third-party sources, each governed
by its own terms. This file records those sources and their licenses. A
machine-readable, per-file provenance record — with row counts, byte sizes and
SHA-256 checksums — is generated at [`data/MANIFEST.json`](data/MANIFEST.json)
by [`scripts/build_manifest.py`](scripts/build_manifest.py).

Nothing here modifies the license of the upstream material; it remains under the
terms of its respective owner. Where this library derives new records (for
example the technique/group/software/campaign profiles, or the vendor->technique
crosswalk), the derivation is MIT-licensed but the underlying facts remain under
the upstream terms noted below.

---

## MITRE ATT&CK®, ATT&CK for ICS, ATT&CK for Mobile

Datasets under `data/attack/` (including `ics/` and `mobile/`), the detection
strategies, analytics, data components, mitigations, groups, software and
campaigns.

> © The MITRE Corporation. This library includes material from MITRE ATT&CK®,
> used under the MITRE ATT&CK Terms of Use. ATT&CK® and MITRE ATT&CK® are
> registered trademarks of The MITRE Corporation.
> https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

## MITRE D3FEND™

`data/attack/technique_to_d3fend.jsonl`, `data/attack/d3fend_countermeasures.jsonl`.

> © The MITRE Corporation. Includes material from MITRE D3FEND™, used under the
> D3FEND Terms of Use. https://d3fend.mitre.org/

## MITRE Cyber Analytics Repository (CAR)

`data/attack/technique_to_car.jsonl`.

> © The MITRE Corporation. Includes material from the MITRE Cyber Analytics
> Repository. https://car.mitre.org/

## MITRE Engage™

Datasets under `data/engage/`.

> © The MITRE Corporation. Includes material from MITRE Engage™, used under the
> MITRE Engage Terms of Use. https://engage.mitre.org/

## MITRE CWE™

`data/weaknesses/cwe.jsonl`.

> © The MITRE Corporation. Includes material from the Common Weakness Enumeration
> (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/

## MITRE CAPEC™

`data/weaknesses/capec.jsonl`.

> © The MITRE Corporation. Includes material from the Common Attack Pattern
> Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use.
> https://capec.mitre.org/

## MITRE ATLAS™

Datasets under `data/ai/`.

> © The MITRE Corporation. Includes material from MITRE ATLAS™ (Adversarial
> Threat Landscape for Artificial-Intelligence Systems). https://atlas.mitre.org/

## Center for Threat-Informed Defense (CTID)

`data/control_to_technique.jsonl` (Mappings Explorer, ATT&CK <-> NIST SP 800-53
Rev 5) and the fraud framework datasets under `data/fraud/`. The
`data/vendor_to_technique.jsonl` crosswalk is derived in part from the CTID
control->technique mappings.

> Licensed under the Apache License, Version 2.0.
> Copyright © The MITRE Corporation. The Center for Threat-Informed Defense is a
> non-profit, privately funded research and development organization operated by
> MITRE Engenuity. https://ctid.mitre.org/ ·
> https://github.com/center-for-threat-informed-defense
>
> A copy of the Apache License, Version 2.0 is available at
> https://www.apache.org/licenses/LICENSE-2.0

## NIST Special Publication 800-53 Rev 5

Control identifiers and titles referenced in `data/control_to_technique.jsonl`
and `data/vendor_to_control.jsonl`.

> Produced by the U.S. National Institute of Standards and Technology. As a work
> of the U.S. Government, it is in the public domain (17 U.S.C. § 105).
> https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

---

*Corrections to attribution or licensing are welcome — open an issue. When adding
a dataset, record its source and license in `scripts/build_manifest.py`'s
`PROVENANCE` table and add an entry here.*
