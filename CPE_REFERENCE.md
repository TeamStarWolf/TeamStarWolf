# CPE Reference: Common Platform Enumeration

> What it is, where it sits, and why a threat-informed program cares. CPE is the asset/product-identity layer of the vulnerability-management stack: the standardized name that ties a CVE to the actual products in your environment. It is *not* an adversary-behavior model like ATT&CK — it answers "which product is this?", so that exposure (CVE/KEV/EPSS) can be matched to assets and prioritized.

CPE (Common Platform Enumeration) is a NIST-maintained naming scheme for IT products — operating systems, applications, and hardware. It is part of the SCAP family and underpins the NVD: every CVE's *applicability* is expressed as CPE match criteria, so CPE is how a vulnerability feed becomes an asset-specific risk.

## Where CPE fits in the ecosystem

| Layer | Framework | Question it answers |
|---|---|---|
| Adversary behavior | MITRE ATT&CK | *How* would an adversary act? |
| Defensive countermeasure | D3FEND / CAR / Engage | *How* do I detect / counter / engage it? |
| Weakness | CWE | *What* flaw class enables it? |
| Attack pattern | CAPEC | *What* pattern exploits the weakness? |
| Vulnerability | CVE / KEV / EPSS | *Which* specific flaw, how exploited/urgent? |
| Product identity | CPE | *Which product/version* is affected, and do I run it? |
| Control | NIST 800-53 / CTEM | *What* control governs it, and what's my exposure posture? |

CPE is the join key between CVE <-> asset. Without it, a CVE feed is just a list; with it, you can answer "am I affected, on which hosts, and how many?"

## The CPE 2.3 name

CPE 2.3 defines a product name two equivalent ways:

Formatted string binding (the one you'll see in NVD):
```
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
```
Example:
```
cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
```

Well-Formed Name (WFN) is the abstract model the string binds to; there is also a legacy URI binding (`cpe:/a:apache:http_server:2.4.51`) from CPE 2.2.

### The 11 components

| Component | Meaning | Notes |
|---|---|---|
| part | `a` = application, `o` = operating system, `h` = hardware | the only three "types" of CPE |
| vendor | producer | e.g. `apache`, `microsoft` |
| product | product name | e.g. `http_server`, `windows_10` |
| version | version string | `2.4.51` |
| update | update/patch level | `sp1`, `*` |
| edition | (legacy) edition | usually `*` |
| language | RFC-5646 language tag | `en`, `*` |
| sw_edition | how the product is tailored | `enterprise`, `*` |
| target_sw | software environment it runs in | `wordpress`, `*` |
| target_hw | hardware it runs on | `x64`, `*` |
| other | vendor-/product-specific | `*` |

Special values: `*` = ANY, `-` = NA (not applicable). Colons inside a component are escaped with `\`.

## CPE applicability: how CVEs map to products

An NVD CVE carries a configurations block of CPE match criteria, not a single CPE. A match node can be:

- an exact CPE (`cpe:2.3:a:apache:http_server:2.4.51:*:...`), or
- a range using `versionStartIncluding` / `versionStartExcluding` / `versionEndIncluding` / `versionEndExcluding` around a `cpe:2.3:a:apache:http_server:*:*:...`, and
- combined with AND / OR operators and a `vulnerable: true|false` flag (e.g. "this OS AND that app, where only the app is vulnerable").

Your asset inventory's CPEs are matched against these criteria to decide applicability. This is where precision matters: a too-broad asset CPE over-reports; a missing `target_sw`/`target_hw` under-reports.

## Why it matters to this program (vulnerability management)

- Exposure -> asset: KEV/EPSS/CVE tell you *what's dangerous*; CPE tells you *whether you run it*. Prioritization is only real once exposure is intersected with an accurate CPE-based inventory.
- SBOM: an SBOM's components resolve to CPEs (or PURLs) to be matched against CVE feeds — CPE is one of the two dominant identity schemes (with Package URL / purl, which is often better for open-source packages).
- CTEM / attack surface: continuous exposure management depends on knowing the product identity of every asset; CPE (plus purl) is that identity.
- Scanner accuracy: vulnerability scanners map detected software to CPEs; CPE-matching errors are a leading cause of both false positives and missed findings.

## Relationship to ATT&CK

CPE does not map to ATT&CK techniques — different abstraction (product identity vs adversary behavior). The nearest cousin is ATT&CK's coarse `platforms` field (Windows, Linux, macOS, IaaS, Containers...), which is a behavior-scoping hint, not a product identifier. Use CPE to scope *exposure* to assets; use ATT&CK to scope *behavior/detection* to platforms.

## Practical notes & pitfalls

- The dictionary is huge and imperfect. The Official CPE Dictionary has well over a million entries; vendor/product strings are inconsistent, and new products lag. Don't assume a clean 1:1 for every asset.
- Prefer ranges over enumerating versions. Match on `versionStartIncluding`/`versionEndExcluding` rather than listing every version CPE.
- Deprecations exist. CPE entries get deprecated/superseded; reconcile periodically against the NVD CPE API.
- purl for OSS. For open-source packages/containers, Package URL (purl) is frequently a cleaner identity than CPE; many modern tools carry both.
- Never treat a CPE as a secret or an asset locator: it's a public product name, not host/inventory data.

## Sources & tooling

- NIST NVD: CPE Dictionary + the CPE and CVE (2.0) APIs (`services.nvd.nist.gov`).
- NIST IR 7695/7696 (CPE 2.3 naming & matching specifications).
- Tools: the NVD CPE API, `cpe-guesser`, SCAP scanners; and purl (Package URL) as the complementary OSS identity.

## See also

- [CVE Reference](CVE_REFERENCE.md), [CWE Reference](CWE_REFERENCE.md), [CAPEC Reference](CAPEC_REFERENCE.md)
- [Vulnerability Management Reference](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization Reference](VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CTEM Reference](CTEM_REFERENCE.md)
- [Supply Chain Security Reference](SUPPLY_CHAIN_SECURITY_REFERENCE.md), [MITRE Enriched Pages](mitre/README.md)

---

*Independent reference summary. CPE, CVE and the NVD are products of NIST/MITRE; consult the upstream specifications (NIST IR 7695) and the NVD for authoritative content.*
