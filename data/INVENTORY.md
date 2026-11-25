# Vendor and Capability Inventory

A structured inventory of security capabilities and the companies and products that
document them. It is **data first**: three hand-authored source files under
`data/inventory/`, validated and rolled up by
[`scripts/build_inventory.py`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/scripts/build_inventory.py).
The inventory reuses the shared entity vocabulary (see
[VOCABULARIES.md](/data/VOCABULARIES.md)): a company id **is** a `vendor:<slug>` in the
vocabulary, and a product is tied to the vocabulary by `vocab_product`.

"Every company" is a direction, not a claim. The inventory is built in tranches and its
counts are published as they stand; it is never described as complete.

## What this is, and is not

- A **capability** maps to a framework item (a NIST CSF 2.0 Function and its Subcategories,
  a CIS Controls v8.1 Control and its Safeguards, or a MITRE D3FEND countermeasure) only
  where that framework's own text supports it. The validator checks the Function / Control
  id and name against the framework, and checks that each cited Subcategory / Safeguard sits
  under it.
- A **product-to-capability mapping means the vendor documents this function** on a page the
  editor read, and records the vendor's own term for it (`documented_as`). It is not a
  statement that the product does it, does it well, or ranks it against another product. A
  mapping that could not be confirmed on a vendor page is `unverified` with a note and **no**
  source.
- Wording is run through a **word filter**, not a claim checker. The filter fails ranking and
  marketing words and the unsourced security words "vulnerable", "breached", "insecure",
  "hacked" and "compromised" in free text, and em dashes (`docs/VOICE.md`). It cannot tell a
  true claim from a false one; a security claim about a named company belongs in a case study
  with a CVE, advisory or regulator source, not here.

## Source files (hand-authored)

### `data/inventory/capabilities.jsonl` - the capability taxonomy

| Field | Meaning |
|---|---|
| `id` | `capability:<slug>`, unique across the file. |
| `name` | Display name of the capability. |
| `category` | One of the ten locked categories (see below). |
| `definition` | A short, own-words, neutral definition. |
| `synonyms` | Other names for the same thing. |
| `components` | Narrower parts or wider terms (e.g. SSE lists SWG, CASB, ZTNA and the wider SASE). |
| `frameworks` | Framework items this capability maps to, each cited (see *Framework items*). May be empty. |
| `library_refs` | Library pages that cover the capability; each must be a repository file. |
| `reviewed_at` | The date a person last reviewed the row (`YYYY-MM-DD`, not in the future). |

Locked categories: `endpoint-xdr`, `vuln-exposure`, `siem-soar`, `email-network`,
`firewall-appliance`, `identity-access`, `appsec-crowdsourced`, `cloud-container`,
`ot-ics`, `backup-resilience`.

### `data/inventory/companies.jsonl` - one row per company

| Field | Meaning |
|---|---|
| `id` | A `vendor:<slug>` id that already exists in `data/vocab/`. Unique. |
| `name` | The company's name as its own site uses it today. |
| `former_names` | Earlier names; sourced if present. |
| `status` | `public`, `private`, `pe-owned` (owned by a private-equity firm), `acquired` (part of or majority-held by another company), `public-controlled` (listed but controlled by a named holder), or `defunct`. |
| `holder` / `holder_name` | The parent or controlling holder: a `vendor:<slug>` when it is a vocabulary vendor, else a name. Required for `pe-owned`, `acquired`, `public-controlled`; absent for `public`/`private`. |
| `ownership_since` | `YYYY`, `YYYY-MM` or `YYYY-MM-DD` of the acquisition; required for `acquired`/`pe-owned`. |
| `ticker` | Exchange and ticker, where known, for a listed company. |
| `announced_acquisition` | An announced-but-unclosed deal: `{ acquirer, acquirer_name, announced_date, source }`. The company's status is still what it is **today**. |
| `domains` | The company's own hostnames (used to check that product pages and mapping sources are vendor pages). |
| `holder_domains` | The holder's or acquirer's hostnames, where a status source lives there. |
| `official_url` | The company's own site (`https`, on `domains`). |
| `sources` | Per-fact provenance. A `status` source is required for every company. |
| `reviewed_at` | Review date (`YYYY-MM-DD`, not in the future). |

### `data/inventory/products.jsonl` - one row per named product

| Field | Meaning |
|---|---|
| `id` | `product:<slug>`, unique. If the id is itself a vocabulary product, it must equal `vocab_product` (no parallel slug). |
| `vocab_product` | The vocabulary `product:<slug>` this product is, or rolls up to, of the same vendor; `null` only where the vocabulary does not cover it yet. |
| `company` | The `vendor:<slug>` id of its company's row. |
| `name` | The product's name as the vendor's page uses it today. |
| `former_names` | Earlier product names; sourced if present. |
| `platform` | The suite or platform the product belongs to. |
| `status` | `current`, `renamed`, `eol` or `discontinued`. |
| `official_url` | The product's own vendor page (`https`, on the company's `domains`). |
| `capabilities` | The capabilities the vendor documents for this product (see *Capability mappings*). |
| `sources` | Per-fact provenance for the product's own fields (`former_names` sourced if present). |
| `reviewed_at` | Review date. |

## Framework items

A `frameworks` entry is one of three shapes; a capability may carry more than one entry per
framework where it spans several Controls or Functions.

| `framework` | `ref` | `name` | `items` | Citation |
|---|---|---|---|---|
| `nist-csf-2.0` | A Function id (`GV`,`ID`,`PR`,`DE`,`RS`,`RC`) | the Function name | Subcategory ids under that Function (e.g. `PR.AA-05`) | `source_url` + `read_date` (NIST CSWP 29) |
| `cis-controls-v8.1` | A Control number `1`-`18` | the Control title | Safeguard ids under that Control (e.g. `13.7`) | `source_url` + `read_date` (CIS Controls v8.1) |
| `d3fend-1.6.0` | a countermeasure id (e.g. `D3-MFA`) | its name | - (`scope` is `full` or `part`) | the pinned release `data/attack/d3fend_countermeasures.jsonl` |

The CSF Function names, CIS Control titles and D3FEND names are checked against the framework;
`items` are checked for shape and that they sit under the cited Function / Control. A D3FEND
entry says whether it covers the whole capability (`full`) or one `part` of it.

## Sourcing

A `sources` object maps a fact key to `{ "url": <https>, "read_date": <YYYY-MM-DD> }`. A
company `status` source is required and may be on the company's `domains` or its
`holder_domains` (the acquirer's page for an acquisition). A product's `official_url` and
every documented mapping's `source_url` must be on the company's own `domains` - a mapping
must cite the vendor's own page. URLs must be clean `https` (no embedded credentials, ASCII
host); dates must be real and not in the future.

### Capability mappings

Each entry in a product's `capabilities` is one of:

- **documented**: `{ "capability_id", "status": "documented", "documented_as", "source_url", "read_date" }`.
  The vendor documents the function on that page, read on that date; `documented_as` is the
  vendor's own term there, so a reader can find it.
- **unverified**: `{ "capability_id", "status": "unverified", "note" }`. The function was not
  confirmed on a vendor page. The note carries no URL and does not claim it was confirmed.

## Generated roll-up

`data/inventory/inventory.json` is written by `build_inventory.py` from the three sources
joined to the vocabulary. It is not edited by hand; `source_sha256` lets a consumer verify it.
CI runs `build_inventory.py --self-test` (planted bad-record controls) and `--check` (the
roll-up matches its sources), and `validate_jsonl.py` checks each source file's `id`.

To add a company, ensure its `vendor:<slug>` exists in `data/vocab/`, then add rows with a
source for every fact, run `python scripts/build_inventory.py` and
`python scripts/build_manifest.py`, and commit the sources, `inventory.json` and
`data/MANIFEST.json` together.

*TeamStarWolf Cybersecurity Reference Library*
