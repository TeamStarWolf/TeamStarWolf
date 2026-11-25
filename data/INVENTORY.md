# Vendor and Capability Inventory

A structured inventory of security capabilities and the companies and products that
document them. It is **data first**: three hand-authored source files under
`data/inventory/`, validated and rolled up by
[`scripts/build_inventory.py`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/scripts/build_inventory.py).
The inventory reuses the shared entity vocabulary (see
[VOCABULARIES.md](/data/VOCABULARIES.md)) rather than inventing its own ids, so the
library names each vendor and product once.

"Every company" is a direction, not a claim. The inventory is built in tranches and its
counts are published as they stand; it is never described as complete.

## What this is, and is not

- A **capability** is mapped to a framework item (NIST CSF 2.0, CIS Controls v8.1 or
  MITRE D3FEND) only where that framework's own published text supports it, and the
  mapped id and name must match the framework. A capability is a function a buyer is
  shopping for, not a score.
- A **product-to-capability mapping means the vendor documents this function** on a page
  the editor read. It is not a statement that the product does it, does it well, or does
  it better than another. A mapping that could not be confirmed on a vendor page is
  recorded `unverified` with a note and **no** source, so it is never a name written from
  memory.
- Wording is **neutral**. Ranking and marketing words ("best", "leading", "world-class",
  and the like) fail validation, as do the words "vulnerable" and "breached" (a security
  claim about a named company belongs in a case study with a CVE, advisory or regulator
  source, not here). There are no rankings and no market-share claims. Em dashes fail
  (`docs/VOICE.md`).

## Source files (hand-authored)

### `data/inventory/capabilities.jsonl` - the capability taxonomy

Seeded from the ten platform categories in [platforms/README.md](/platforms/README.md).

| Field | Meaning |
|---|---|
| `id` | `capability:<slug>`, unique across the file. |
| `name` | Display name of the capability. |
| `category` | One of the ten locked categories (see below). |
| `definition` | A short, own-words, neutral definition (one or two sentences). |
| `aka` | Other names and acronyms practitioners search for. |
| `frameworks` | Framework items this capability maps to, each cited (see *Framework items*). May be empty. |
| `library_refs` | Library pages that cover the capability; each must be a repository file. |
| `reviewed_at` | The date a person last reviewed the row (`YYYY-MM-DD`). |

Locked categories: `endpoint-xdr`, `vuln-exposure`, `siem-soar`, `email-network`,
`firewall-appliance`, `identity-access`, `appsec-crowdsourced`, `cloud-container`,
`ot-ics`, `backup-resilience`.

### `data/inventory/companies.jsonl` - one row per company

| Field | Meaning |
|---|---|
| `id` | A `vendor:<slug>` id that already exists in `data/vocab/` (the one model). Unique. |
| `name` | The company's name as its own site uses it today. |
| `former_names` | Earlier names, where an acquisition or rename changed them. Sourced if present. |
| `status` | `independent`, `subsidiary`, `merged` or `defunct`. |
| `parent` | The acquirer's `vendor:<slug>` id when it is a vocabulary vendor, else null. |
| `parent_name` | The acquirer's display name when it is not a vocabulary vendor, else null. |
| `acquired_on` | `YYYY`, `YYYY-MM` or `YYYY-MM-DD` for a `subsidiary`/`merged` company, else null. |
| `official_url` | The company's own site (`https`). |
| `sources` | Per-fact provenance (see *Sourcing*). A source for `status` is required. |
| `reviewed_at` | The date a person last reviewed the row (`YYYY-MM-DD`). |

### `data/inventory/products.jsonl` - one row per product

| Field | Meaning |
|---|---|
| `id` | `product:<slug>`, unique across the file. |
| `company` | The `vendor:<slug>` id of its company's row. |
| `name` | The product's name as the vendor's page uses it today. |
| `former_names` | Earlier product names, where a rename or acquisition changed them. Sourced if present. |
| `status` | `current`, `renamed`, `eol` or `discontinued`. |
| `official_url` | The vendor's own page for the product (`https`). |
| `capabilities` | The capabilities the vendor documents for this product (see *Capability mappings*). |
| `sources` | Per-fact provenance for the product's own fields (optional; `former_names` sourced if present). |
| `reviewed_at` | The date a person last reviewed the row (`YYYY-MM-DD`). |

## Framework items

A `frameworks` entry on a capability is one of three shapes, and the validator checks the
id and name against the framework itself:

| `framework` | `ref` | `name` | Citation |
|---|---|---|---|
| `nist-csf-2.0` | A Function id: `GV`, `ID`, `PR`, `DE`, `RS`, `RC` | The Function's name | `source_url` + `read_date` (NIST CSF 2.0, NIST CSWP 29) |
| `cis-controls-v8.1` | A Control number `1`-`18` (as a string) | The Control's title | `source_url` + `read_date` (CIS Controls v8.1) |
| `d3fend-1.6.0` | A D3FEND countermeasure id (e.g. `D3-MFA`) | The countermeasure's name | `dataset`: the pinned release `data/attack/d3fend_countermeasures.jsonl` |

The CSF Function names and CIS Control titles are held in `build_inventory.py` from the
cited pages; a D3FEND id and name must appear in the pinned D3FEND 1.6.0 release the
library already vendors.

## Sourcing

A `sources` object maps a fact key to `{ "url": <https>, "read_date": <YYYY-MM-DD> }`.
Company source keys: `status` (required), `former_names` (required when present), `name`,
`parent`, `acquired_on`, `official_url`. Product source keys: `name`, `former_names`
(required when present), `official_url`, `status`.

### Capability mappings

Each entry in a product's `capabilities` is one of:

- **documented**: `{ "capability_id", "status": "documented", "source_url": <https>, "read_date": <YYYY-MM-DD> }`.
  The vendor documents the function on that page, read on that date.
- **unverified**: `{ "capability_id", "status": "unverified", "note": <why> }`.
  The function was not confirmed on a vendor page. It carries a note and no source, and is
  reported as unverified rather than asserted.

## Generated roll-up

`data/inventory/inventory.json` is written by `build_inventory.py` from the three sources
joined to the vocabulary: counts, the taxonomy by category, and the companies and products
with their capability and vendor names resolved. It is not edited by hand. `source_sha256`
is the LF-normalised SHA-256 of each source file, so a consumer can verify the roll-up
against the sources. CI runs `build_inventory.py --self-test` (planted bad-record controls)
and `--check` (the roll-up matches its sources), and `validate_jsonl.py` checks that each
source file's `id` is present and unique.

To add a company, first ensure its `vendor:<slug>` exists in `data/vocab/` (see
VOCABULARIES.md), then add rows to `companies.jsonl` and `products.jsonl` with a source for
every fact, run `python scripts/build_inventory.py` and `python scripts/build_manifest.py`,
and commit the sources, `inventory.json` and `data/MANIFEST.json` together.

*TeamStarWolf Cybersecurity Reference Library*
