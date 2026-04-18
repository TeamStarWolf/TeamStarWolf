# ATT&CK Navigator — TeamStarWolf Vendor Coverage

Live ATT&CK Enterprise heatmap showing NIST 800-53 Rev 5 control coverage depth across 313 techniques. Scores represent the number of NIST 800-53 Rev 5 controls that mitigate each technique, sourced from the [CTID attack-control-framework-mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings) project.

**Score interpretation:**
- **High score (20–33)** — Many controls address this technique; broad vendor coverage across the enterprise stack
- **Medium score (10–19)** — Moderate control coverage; most mature security programs address this
- **Low score (1–9)** — Fewer controls map to this technique; may represent capability gaps worth prioritizing

**References:**
- [Layer JSON file](https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json)
- [Controls Mapping](../CONTROLS_MAPPING.md) — Vendor → NIST 800-53 cross-reference
- [Coverage Schema](../COVERAGE_SCHEMA.md) — Data model and gap scoring functions
- [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/)

---

<div style="position:relative; width:100%; padding-bottom:65%; min-height:500px;">
  <iframe
    src="https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FTeamStarWolf%2FTeamStarWolf%2Fmain%2Fnavigator%2Fteamstarwolf_vendor_coverage.json"
    style="position:absolute; top:0; left:0; width:100%; height:100%; border:1px solid #334155; border-radius:6px;"
    title="MITRE ATT&CK Navigator — TeamStarWolf Vendor Coverage"
    loading="lazy"
    allowfullscreen>
  </iframe>
</div>

> **Tip:** Use the layer controls in the Navigator toolbar to filter by tactic, score, or platform. Export a custom layer to compare against your own stack.
