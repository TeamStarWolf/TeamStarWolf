"""Create or update GitHub Stars Lists from the STARRED_REPOS.md categories.

Maintainer helper. With --apply it WRITES TO THE AUTHENTICATED GITHUB ACCOUNT: it
creates one PUBLIC Stars List per major STARRED_REPOS.md section on whatever account
`gh` is logged into, and replaces each list's full repository set (updateUserList is
a replace, not an append). Without --apply it only prints the plan and never calls gh.

Usage (from anywhere in the clone):
    python research/create_starred_lists.py            # dry run: print planned lists
    gh auth refresh -s user                            # only needed for --apply
    python research/create_starred_lists.py --apply    # create/update the lists

All values reach GitHub as GraphQL variables, never by string interpolation, so repo
names parsed from the Markdown cannot alter a query.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

# STARRED_REPOS.md lives at the repository root, one level above research/.
INDEX = Path(__file__).resolve().parents[1] / "STARRED_REPOS.md"

# owner/name as GitHub allows it; anything else parsed from the Markdown is skipped.
REPO_RE = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")

# Major-section -> Stars List name (under GitHub's UI 50-character limit)
SECTION_TO_LIST = {
    "Frameworks & Standards": "1. Frameworks & Standards",
    "Threat Intelligence": "2. Threat Intelligence",
    "Detection Engineering": "3. Detection Engineering",
    "Vulnerability Management": "4. Vulnerability Management",
    "DFIR - Digital Forensics & Incident Response": "5. DFIR & Incident Response",
    "Malware Analysis & Reverse Engineering": "6. Malware Analysis & RE",
    "Red Team - Offensive Security": "7. Red Team & Offensive",
    "Network Security": "8. Network Security",
    "Cloud, Container & Identity": "9. Cloud & Container Security",
    "Cryptography & Passwords": "10. Crypto & Passwords",
    "AI / LLM Security": "11. AI & LLM Security",
    "Smart Contracts / Web3": "12. Web3 & Smart Contracts",
    "Threat Modeling": "13. Threat Modeling",
    "Vendor & Platform Repos": "14. Vendor Tooling",
    "Hardware, OS, Lab": "15. Hardware, OS & Lab",
    "Honeypots & Deception": "16. Honeypots & Deception",
    "Learning & Content": "17. Learning & Content Creators",
    "Anthropic & AI Skills": "18. Anthropic & AI Skills",
}

Q_LISTS = "query { viewer { lists(first: 100) { nodes { id name } } } }"
Q_REPO = "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }"
M_CREATE = """mutation($name: String!, $description: String!) {
  createUserList(input: {name: $name, description: $description, isPrivate: false}) {
    list { id name }
  }
}"""
M_SET = """mutation($listId: ID!, $repositoryIds: [ID!]!) {
  updateUserList(input: {listId: $listId, repositoryIds: $repositoryIds}) {
    list { id name }
  }
}"""


def parse_index():
    """Parse STARRED_REPOS.md into {major_section: [owner/name, ...]}."""
    content = INDEX.read_text(encoding="utf-8")
    sections = {}
    cur_major = None
    for line in content.splitlines():
        m = re.match(r"^## (.+?)$", line)
        if m and not m.group(1).startswith("Table"):
            cur_major = m.group(1).strip()
            sections.setdefault(cur_major, [])
            continue
        m = re.match(r"^- \[([^\]]+)\]\(https://github\.com/", line)
        if m and cur_major:
            name = m.group(1).strip()
            if REPO_RE.match(name):
                sections[cur_major].append(name)
            else:
                print(f"  ! Skipping unparseable repo name in '{cur_major}': {name!r}")
    return sections


def gql(query, variables=None):
    """Run a GraphQL request through `gh api graphql`, passing values as variables."""
    body = json.dumps({"query": query, "variables": variables or {}})
    r = subprocess.run(
        ["gh", "api", "graphql", "--input", "-"],
        input=body, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None, r.stderr.strip()
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None, r.stdout
    if out.get("errors"):
        return None, out["errors"]
    return out, None


def get_existing_lists():
    """Return {name: list_id} for the authenticated account."""
    out, err = gql(Q_LISTS)
    if not out:
        raise SystemExit(f"Could not read existing Stars Lists: {err}")
    return {n["name"]: n["id"] for n in out["data"]["viewer"]["lists"]["nodes"]}


def create_list(name, description):
    """Create a public Stars List. Returns its ID or None."""
    out, err = gql(M_CREATE, {"name": name, "description": description})
    if not out:
        print(f"  ! Failed to create '{name}': {err}")
        return None
    return out["data"]["createUserList"]["list"]["id"]


def get_repo_id(full_name):
    owner, name = full_name.split("/", 1)
    out, _ = gql(Q_REPO, {"owner": owner, "name": name})
    if not out or out.get("data", {}).get("repository") is None:
        return None
    return out["data"]["repository"]["id"]


def set_list_repos(list_id, repo_full_names):
    """Replace the list's full repository set in one mutation."""
    repo_ids = [rid for rid in (get_repo_id(f) for f in repo_full_names) if rid]
    out, err = gql(M_SET, {"listId": list_id, "repositoryIds": repo_ids})
    return bool(out), len(repo_ids), err


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true",
                    help="create/update the Stars Lists on the account gh is logged into "
                         "(default: dry run, no gh calls)")
    args = ap.parse_args()

    sections = parse_index()
    print(f"Parsed {sum(len(r) for r in sections.values())} repos across {len(sections)} sections "
          f"from {INDEX}.")

    if not args.apply:
        print("DRY RUN: no changes made. Re-run with --apply to write these PUBLIC lists "
              "(each list's repository set is replaced, not appended).")
        for major, list_name in SECTION_TO_LIST.items():
            repos = sections.get(major, [])
            print(f"  {list_name}: {len(repos)} repos" if repos
                  else f"  {list_name}: skipped (no repos)")
        return

    existing = get_existing_lists()
    print(f"Existing lists: {len(existing)}")

    for major, list_name in SECTION_TO_LIST.items():
        repos = sections.get(major, [])
        if not repos:
            print(f"  - Skipping (no repos): {list_name}")
            continue

        if list_name in existing:
            list_id = existing[list_name]
            print(f"[Updating] '{list_name}' ({len(repos)} repos)")
        else:
            list_id = create_list(list_name, f"Auto-curated: {major}")
            if not list_id:
                continue
            print(f"[Created] '{list_name}' ({len(repos)} repos)")

        ok, count, err = set_list_repos(list_id, repos)
        print(f"  Set {count} repos" if ok else f"  FAILED: {err}")


if __name__ == "__main__":
    main()
