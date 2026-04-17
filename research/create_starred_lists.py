"""Create GitHub Stars Lists from STARRED_REPOS.md categories.

Prerequisite: Refresh gh CLI auth with the 'user' scope:
    gh auth refresh -s user

Then run:
    python create_starred_lists.py

This creates one GitHub Stars List per major category and adds the relevant repos.
"""
import subprocess
import json
import re
import sys
from pathlib import Path

INDEX = Path(__file__).parent / "STARRED_REPOS.md"

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


def parse_index():
    """Parse STARRED_REPOS.md into {major_section: [repo_full_names]}."""
    content = INDEX.read_text(encoding="utf-8")
    sections = {}
    cur_major = None
    for line in content.splitlines():
        m = re.match(r"^## (.+?)$", line)
        if m and not m.group(1).startswith("Table"):
            cur_major = m.group(1).strip()
            if cur_major not in sections:
                sections[cur_major] = []
            continue
        m = re.match(r"^- \[([^\]]+)\]\(https://github\.com/", line)
        if m and cur_major:
            sections[cur_major].append(m.group(1))
    return sections


def gql(query):
    """Run a GraphQL query via gh CLI."""
    r = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        return None, r.stderr
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, r.stdout


def get_existing_lists():
    """Return {name: list_id}."""
    out, err = gql('query { viewer { lists(first: 100) { nodes { id name } } } }')
    if not out:
        return {}
    return {n["name"]: n["id"] for n in out["data"]["viewer"]["lists"]["nodes"]}


def create_list(name, description):
    """Create a Stars List. Returns list ID or None."""
    desc_escaped = description.replace('"', '\\"')
    q = f'''mutation {{
        createUserList(input: {{
            name: "{name}",
            description: "{desc_escaped}",
            isPrivate: false
        }}) {{ list {{ id name }} }}
    }}'''
    out, err = gql(q)
    if not out or "errors" in out:
        print(f"  ! Failed to create '{name}': {err or out.get('errors')}")
        return None
    return out["data"]["createUserList"]["list"]["id"]


def get_repo_id(full_name):
    owner, name = full_name.split("/", 1)
    q = f'query {{ repository(owner: "{owner}", name: "{name}") {{ id }} }}'
    out, _ = gql(q)
    if not out or out.get("data", {}).get("repository") is None:
        return None
    return out["data"]["repository"]["id"]


def add_to_list(list_id, repo_id):
    q = f'''mutation {{
        updateUserList(input: {{
            listId: "{list_id}",
            repositoryIds: ["{repo_id}"]
        }}) {{ list {{ id }} }}
    }}'''
    # NOTE: updateUserList replaces the full set of repo IDs each call.
    # For bulk inserts, batch them up. See helper below.
    out, err = gql(q)
    return bool(out and "errors" not in out), err


def set_list_repos(list_id, repo_full_names):
    """Set the full repo set for a list in one mutation."""
    repo_ids = []
    for full in repo_full_names:
        rid = get_repo_id(full)
        if rid:
            repo_ids.append(rid)
    ids_str = ",".join(f'"{rid}"' for rid in repo_ids)
    q = f'''mutation {{
        updateUserList(input: {{
            listId: "{list_id}",
            repositoryIds: [{ids_str}]
        }}) {{ list {{ id name }} }}
    }}'''
    out, err = gql(q)
    return bool(out and "errors" not in out), len(repo_ids), err


def main():
    sections = parse_index()
    print(f"Parsed {sum(len(r) for r in sections.values())} repos across {len(sections)} sections.")

    existing = get_existing_lists()
    print(f"Existing lists: {len(existing)}")

    for major, list_name in SECTION_TO_LIST.items():
        repos = sections.get(major, [])
        if not repos:
            print(f"  - Skipping (no repos): {list_name}")
            continue

        if list_name in existing:
            list_id = existing[list_name]
            print(f"\n[Updating] '{list_name}' ({len(repos)} repos)")
        else:
            list_id = create_list(list_name, f"Auto-curated: {major}")
            if not list_id:
                continue
            print(f"\n[Created] '{list_name}' ({len(repos)} repos)")

        ok, count, err = set_list_repos(list_id, repos)
        if ok:
            print(f"  Added {count} repos")
        else:
            print(f"  FAILED: {err}")


if __name__ == "__main__":
    main()
