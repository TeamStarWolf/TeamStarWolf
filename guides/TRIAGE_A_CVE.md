# Triage a New CVE in 30 Minutes

> **In half an hour you will turn "is this bad for us?" into a defensible Track/Attend/Act decision with an SLA, an owner, and an exported audit artifact.** This guide is for anyone who gets handed a CVE ID — a vuln-management analyst, a SOC lead, a sysadmin, or the one security person at a small shop — and needs to decide what to do about it without guessing.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| ~30 minutes | Intermediate | A CVE ID, asset-inventory access, a terminal with `curl` (or just a browser) | A decision (Track / Track\* / Attend / Act), an SLA tier with owner and due date, and the recorded input vector that justifies both |

The method comes straight from this library's precedence rule: **verified exploitation (KEV) > predicted exploitation (EPSS) > your environment > abstract severity (CVSS)**. Each step below collects one layer of that stack; the CISA SSVC decision tree then turns the collected inputs into an action. The worked example threaded through the checkpoints is CVE-2023-4966 (CitrixBleed).

## Before you start

- [ ] Have the CVE ID in hand, and know roughly why it landed on your desk (scanner finding, vendor email, news). Rusty on how CVE records work? Skim [CVE Reference](/CVE_REFERENCE.md) first.
- [ ] Confirm you can query your asset inventory / CMDB for a product name — the environmental steps die without it. See [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for what a usable inventory looks like.
- [ ] Skim the signal-precedence model this guide operationalizes: [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md).
- [ ] Have `curl` available ([official docs](https://curl.se/docs/)) — every data source here is a free, no-auth HTTP endpoint. A browser works for all of them too.
- [ ] Bookmark the [CISA SSVC calculator](https://www.cisa.gov/ssvc-calculator) — you will finish the triage inside it.
- [ ] Know where your written SLA policy lives, if you have one. If you don't, the editorial example table in [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) is a starting point to adapt.

## Step 1 — Pin down what you are actually triaging (3 min)

Get the authoritative CVE record, not a news article's paraphrase of it.

1. Open `https://www.cve.org/CVERecord?id=CVE-2023-4966` (substitute your CVE ID), or pull the same record as JSON:

   ```bash
   curl https://cveawg.mitre.org/api/cve/CVE-2023-4966
   ```

2. From the record's CNA container, write down: **vendor, product, affected versions, and the one-line vulnerability description.**
3. Query your inventory for that product. Count the assets; note which ones face the internet (you will need this again in Step 6).

If you don't run the product anywhere, record that and stop — "not deployed, verified against inventory on 2026-09-25" **is** a completed triage, and it's the fastest defensible outcome this guide produces.

**Checkpoint:** One sentence of scope, e.g. "CVE-2023-4966 — Citrix NetScaler ADC/Gateway buffer overflow, session-token disclosure; we run NetScaler Gateway on 2 appliances, both internet-facing."

**Watch out:** A record in RESERVED state has no details yet, and a REJECTED one is dead — check the state before spending your 30 minutes. Also expect the CNA and CISA (Step 3) to occasionally disagree on severity; record which container a datum came from rather than averaging them.

## Step 2 — Check KEV and read all of its flags (3 min)

The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the highest-confidence public exploitation signal: every entry is CISA-verified exploitation in the wild. Search the catalog page for your CVE ID, or pull the live feed:

```bash
curl -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

```python
import json
kev = json.load(open("kev.json"))
hit = next((v for v in kev["vulnerabilities"] if v["cveID"] == "CVE-2023-4966"), None)
print(json.dumps(hit, indent=2) if hit else "Not in KEV")
```

If it's listed, four fields carry the meaning:

| Field | What it tells you |
|---|---|
| `dateAdded` / `dueDate` | When CISA verified exploitation, and the federal remediation deadline computed from it — a free, well-calibrated benchmark SLA even outside government |
| `knownRansomwareCampaignUse` | `Known` here + internet-facing is the strongest patch-now signal public data offers |
| `forensicTriage` | `Yes` means CISA put it in the fastest BOD 26-04 tier, where "were we already compromised?" is part of the job (Step 9) |
| `requiredAction` | The actual remediation instruction — read it word for word |

**Checkpoint:** A recorded KEV verdict with flags. For the example: listed 2023-10-18, `knownRansomwareCampaignUse: Known`, and a `requiredAction` that demands killing all active and persistent sessions *in addition to* patching — patching alone leaves stolen sessions alive.

**Watch out:** "Not in KEV" never means "not exploited." KEV requires a clear remediation to exist before a CVE can enter, so actively exploited vulnerabilities without a fix are absent by design. And treat the flags as live fields: they get flipped on existing entries without announcement, so diff the whole feed on every pull, not just new IDs.

## Step 3 — Pull CISA's pre-computed SSVC inputs from Vulnrichment (4 min)

Three of the five decision-tree inputs you'll need in Step 7 are published per CVE by CISA through [Vulnrichment](https://github.com/cisagov/vulnrichment), delivered as an ADP container inside the same CVE record you fetched in Step 1:

```bash
curl https://cveawg.mitre.org/api/cve/CVE-2023-4966
```

In the JSON, find `containers.adp[]` where `providerMetadata.shortName` is `CISA-ADP`, then the `metrics[].other` entry with `"type": "ssvc"`. Its `options` array holds:

| Decision point | Values |
|---|---|
| **Exploitation** | `none` / `poc` / `active` |
| **Automatable** | `yes` / `no` |
| **Technical Impact** | `partial` / `total` |

You can also browse the raw file in the Vulnrichment repo — records live at `<year>/<number-range>/CVE-YYYY-NNNN.json`, e.g. `2024/3xxx/CVE-2024-3477.json`. The data is CC0-licensed, so it drops into any pipeline without attribution friction.

**Checkpoint:** Three values on paper with their source noted. For the example: Exploitation `active`, Automatable `yes`, Technical Impact `total` — from the CISA-ADP container.

**Watch out:** Not every CVE is enriched, and enrichment lags disclosure (CISA commits to roughly three business days under BOD 26-04 guidance). If the ADP container is missing, set Exploitation yourself from Step 2 plus the vendor advisory, and mark the value as self-assessed. Conversely, `Exploitation: active` here often appears *before* formal KEV addition — treat it as an early warning, not a contradiction.

## Step 4 — Read EPSS as a probability, not a rank (3 min)

[EPSS](https://www.first.org/epss/) estimates the probability that your CVE will be exploited in the wild in the next 30 days, refreshed daily. Pull it — no API key needed:

```bash
curl "https://api.first.org/data/v1/epss?cve=CVE-2023-4966"
```

The response carries three values per CVE: `epss` (the 0–1 probability — this is the risk signal), `percentile` (queue position among all scored CVEs — context only), and `date` (score date). Two reading rules from FIRST's own guidance:

- The distribution is brutally skewed: a probability of roughly **0.10 already sits near the 88th percentile**. A "92nd percentile" CVE can still be a modest absolute risk, so write policies against the probability, never the percentile.
- If the CVE is KEV-listed, FIRST's guidance is two words: **"Follow KEV."** EPSS earns its keep ranking the enormous population KEV can't cover — for a KEV hit, this step is a 20-second confirmation, not a decision input.

**Checkpoint:** Probability recorded with its date, e.g. "EPSS 0.99999 (2026-09-25)" for the example — which changes nothing, because KEV already outranks it.

**Watch out:** Never multiply EPSS by CVSS to make a "risk score" — FIRST states plainly that the product doesn't compute probability × severity and calls the practice never a good idea. Never trend scores across EPSS model versions (v5 went live 2026-06-15; a jump at a version boundary is methodology, not threat). And expect brand-new CVEs to be underestimated — the model hasn't seen them yet.

## Step 5 — Read the vendor advisory and any VEX statement (4 min)

Now the fix side. Follow the reference links in the CVE record and the KEV `notes` field to the vendor's advisory and confirm three things:

1. **The fixed version or official mitigation** — the concrete thing your ticket will ask for.
2. **Whether patching alone is sufficient** — CitrixBleed's advisory requires killing active sessions post-patch; credential-exposure bugs demand rotation; some fixes need a config change to take effect.
3. **Whether the supplier has issued a machine-readable CSAF/VEX statement** for your product combination. A `known_not_affected` / `not_affected` status with a justification label (e.g. `vulnerable_code_not_in_execute_path`) closes the finding defensibly — record the label and you're done with this CVE.

**Checkpoint:** A fix target ("upgrade to version X" or "apply mitigation Y"), any mandatory post-patch actions, and a VEX status if one exists.

**Watch out:** A VEX `not_affected` applies to the exact product and version the statement names — don't stretch it across your whole fleet. And VEX statements get superseded; note the document date so a re-check is possible.

## Step 6 — Establish the two inputs only you can supply (4 min)

Everything so far was derivable from public feeds. The next two inputs are environmental — no feed can answer them, and defaulting them turns the whole exercise back into a severity score:

1. **Exposure.** For the affected assets from Step 1: are they reachable by unauthenticated entities via public networks? Answer from evidence — your external attack-surface scan or perimeter inventory — not from what the firewall is *supposed* to do.
2. **Mission Prevalence and Public Well-Being Impact** (CISA's SSVC values). Mission Prevalence: `Minimal` / `Support` / `Essential` — does the vulnerable component directly provide, or support, a mission-essential function? Public Well-Being: `Minimal` / `Material` / `Irreversible` — could exploitation cause physical, environmental, financial, or psychological harm beyond the system itself? The calculator combines the two into a single Mission & Well-Being value of Low, Medium, or High.

**Checkpoint:** An exposure verdict per asset group and a Mission & Well-Being value, each with the evidence source written next to it ("internet-facing per EASM scan 2026-09-24"; "Essential — sole remote-access gateway for claims processing").

**Watch out:** This is where triage quality is actually decided. If your analysts hand-research exploitation status (Steps 2–4 automate that) but shrug at "is it internet-facing?", the effort is pointed backwards — fix the inventory before you tune anything else.

## Step 7 — Walk the CISA SSVC tree and export the decision (4 min)

Open the [CISA SSVC calculator](https://www.cisa.gov/ssvc-calculator) and answer its decision points with the values you just collected — Exploitation and Technical Impact (Step 3, cross-checked against Step 2), Automatable (Step 3), Mission Prevalence and Public Well-Being (Step 6). The tree lands on one of four outcomes:

| Outcome | Meaning (per CISA's SSVC guide) |
|---|---|
| **Track** | No action required now; reassess when new information arrives; remediate on standard timelines |
| **Track\*** | Specific characteristics warrant closer monitoring for changes; standard timelines |
| **Attend** | Requires supervisory-level attention; remediate sooner than standard timelines |
| **Act** | Requires supervisory *and* leadership attention; remediate as soon as possible |

Use the calculator's **Export** to save the decision as PDF or JSON, and attach it to your ticket. That export — the full input vector plus the outcome — is the audit artifact; it is what makes the decision defensible six months from now.

For the example, `active` / `yes` / `total` plus an internet-facing, mission-essential gateway (Mission & Well-Being High) lands on **Act**.

**Checkpoint:** An exported decision file showing every input value and the resulting Track/Track\*/Attend/Act outcome.

**Watch out:** The outcome names encode *escalation altitude* — who must be in the room — not patch speed. Day counts come next, from your SLA policy. Don't skip the export to save a minute; an outcome without its recorded inputs can't answer "why didn't you patch the 9.8 first?"

## Step 8 — Pull ATT&CK context for the gap before the fix lands (2 min)

If remediation will take days, detection has to cover the interim — and for that you need to know what adversaries *do* with the vulnerability. The only authoritative per-CVE source is the [CTID KEV-to-ATT&CK mappings](https://ctid.mitre.org/mappings/external/kev/) in MITRE's Mappings Explorer: browse to your CVE's page and record its mapped technique IDs, which are decomposed into exploitation technique, primary impact, and secondary impacts. Hand those IDs to your detection team — that's the answer to "what do we watch for while this is open?" Layer downloads (JSON, CSV, Excel, STIX, Navigator) exist for doing this in bulk.

**Checkpoint:** A short list of technique IDs attached to the ticket — or the explicit note "no authoritative ATT&CK mapping exists for this CVE."

**Watch out:** Never fake the bridge by walking CVE → CWE → CAPEC → ATT&CK; that chain describes the weakness *class* and is frequently wrong about the actual vulnerability. If CTID hasn't mapped your CVE, say so — weakness-class context from [CWE Reference](/CWE_REFERENCE.md) is honest as context, not as a mapping.

## Step 9 — Land the SLA and set its tripwires (3 min)

Convert the outcome into work:

1. **Assign the SLA tier** from your written policy — the editorial example ladder in [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) runs P0 (3 days, KEV + exposed + automatable + total control) through P4 (scheduled maintenance). No policy yet? Use the KEV `dueDate` span and BOD 26-04's tier structure (3 / 6 / 14 / 30 / 60 days / fix-on-upgrade) as the public benchmark and write yours down afterward.
2. **If you landed in the fastest tier** (or KEV said `forensicTriage: Yes`), open a second work item: determine whether the vulnerability was already exploited on those assets *before* your patch lands. "Patch" and "were we already hit?" are separate deliverables on the same clock — route the second through [IR Playbooks](/IR_PLAYBOOKS.md).
3. **Set re-evaluation triggers.** A priority is a cached decision; write down what invalidates it: KEV addition, a large EPSS jump, a new or superseded VEX statement, an exposure change. Wire these to alerts if you can, a weekly diff if you can't.
4. **File the ticket**: decision + SLA + owner + due date + the exported input vector + technique IDs.

**Checkpoint:** A ticket a stranger could audit: what was decided, by when it must be done, who owns it, exactly which inputs produced it, and what would reopen it.

**Watch out:** Don't run one clock for two jobs — closing the patch task while the forensic-triage question is still open is how "remediated" and "compromised" end up both being true.

## What good looks like

- **Reproducible:** a colleague re-running Steps 2–7 with your recorded inputs reaches the same outcome.
- **Defensible in both directions:** you can answer "why so urgent?" *and* "why did you defer that 9.8?" from the input vector alone, without reconstructing anything from memory.
- **Correctly ordered:** verified exploitation outranked prediction, prediction outranked severity, and your environment promoted or demoted both — no EPSS×CVSS arithmetic anywhere.
- **Time spent where it counts:** the public-feed steps felt mechanical (they should — automate them next; see the pipeline sketch in [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md)), and most of your 30 minutes went to exposure, mission impact, and the advisory's fine print.
- **Alive, not archived:** the decision has named tripwires, so a KEV addition or EPSS jump reopens it automatically instead of waiting for next quarter's scan.

## Go deeper

**In this library:**

- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md) — the full decision layer this guide walks: SSVC models, KEV semantics, BOD 26-04, EPSS interpretation, signal precedence, SLA design
- [CVE Reference](/CVE_REFERENCE.md) — CVE program architecture, CVSS v3.1/v4.0 scoring mechanics, EPSS/KEV API code, notable case studies including CitrixBleed
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) — the operational machinery around triage: scanners, ticketing, exception handling, patch execution
- [CTEM Reference](/CTEM_REFERENCE.md) — the continuous exposure-management loop that repeated triage feeds
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md) — why the KEV ransomware flag multiplies priority, and what to do beyond patching
- [Security Metrics Reference](/SECURITY_METRICS_REFERENCE.md) — measuring the program with tier-scoped MTTR and SLA compliance instead of raw counts

**Authoritative external resources:**

- [CISA SSVC guide and calculator](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) — the decision points, values, and tree this guide's Step 7 walks
- [CERT/CC SSVC documentation](https://certcc.github.io/SSVC/) — the underlying methodology, all stakeholder models, and machine-readable decision tables
- [FIRST EPSS FAQ](https://www.first.org/epss/faq) — what EPSS is and is not, from its stewards
- [BOD 26-04 and implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) — the federal timeline matrix and forensic-triage requirement

---

*Guides are procedures: endpoints, field names, catalog counts, and calculator behavior were verified against official documentation as of 2026-09-25 and will drift — verify commands against current official docs before production use.*
