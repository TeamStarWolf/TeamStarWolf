# Git Command Reference

Git is a distributed version control system that tracks changes in source trees. Every clone holds the full history, so most operations run locally and offline. This page covers the everyday commands plus the history, branching, and remote operations that teams rely on. It assumes Git 2.23 or later, where `switch` and `restore` split the old `checkout` behavior.

## What it is and where it runs

Git runs as a command-line tool on Linux, macOS, Windows, and the BSDs. A repository is a working tree plus a hidden `.git` directory that stores objects, refs, and config. Commands act on the local repository first; `fetch`, `pull`, and `push` are the only ones that talk to a remote. Hosting platforms (GitHub, GitLab, Bitbucket) add access control and review on top of the same protocol.

## Core commands

Create or copy a repository.

```bash
git init                     # start a new repository here
git clone <url>              # copy a remote repository and its history
git clone --depth 1 <url>    # shallow clone, latest commit only
```

Stage and record changes.

```bash
git add <path>               # stage a file or directory
git add -p                   # stage selected hunks interactively
git commit -m "message"      # record staged changes
git commit --amend           # replace the previous commit
```

Inspect state and history.

| Command | Purpose |
| --- | --- |
| `git status` | show staged, unstaged, and untracked paths |
| `git diff` | unstaged changes vs the index |
| `git diff --staged` | staged changes vs the last commit |
| `git log --oneline --graph` | compact history with branch topology |
| `git show <ref>` | details of one commit or object |

Branch and move between lines of work.

```bash
git branch                   # list branches
git branch <name>            # create a branch
git switch <name>            # move to an existing branch
git switch -c <name>         # create and move to a branch
git checkout <ref>           # older combined form, still valid
```

Integrate changes.

```bash
git merge <branch>           # join another branch into the current one
git rebase <branch>          # replay current commits on top of <branch>
git cherry-pick <commit>     # apply one commit here
git revert <commit>          # new commit that undoes <commit>
```

Undo and set aside work.

```bash
git reset --soft HEAD~1      # undo last commit, keep changes staged
git reset --hard <ref>       # discard commits and working changes
git stash                    # shelve working changes
git stash pop                # reapply the most recent stash
```

Tags and remotes.

```bash
git tag -a v1.0 -m "release" # annotated tag
git remote -v                # list remotes and URLs
git remote add origin <url>  # register a remote
git fetch origin             # download refs without merging
git pull                     # fetch then merge or rebase
git push origin <branch>     # upload commits to a remote
```

Configuration, cleanup, and search.

```bash
git config --global user.name "Name"
git config --global user.email "you@example.com"
git clean -n                 # preview untracked files to remove
git clean -fd                # remove untracked files and directories
git bisect start             # binary-search history for a bad commit
```

## Common workflows

Start a feature branch, commit, and push for review.

```bash
git switch -c feature/login
git add src/auth.py
git commit -m "Add login handler"
git push -u origin feature/login
```

Update a branch against main without a merge commit.

```bash
git switch feature/login
git fetch origin
git rebase origin/main
git push --force-with-lease
```

Find the commit that introduced a regression.

```bash
git bisect start
git bisect bad                 # current commit is broken
git bisect good v1.0           # this older tag worked
# Git checks out midpoints; mark each good or bad until it reports the culprit
git bisect reset
```

Safely preview and remove untracked files after a build.

```bash
git clean -nxd                 # list what would be deleted, including ignored
git clean -fxd                 # delete after you confirm the list
```

## Flags and options worth knowing

| Flag | Applies to | Effect |
| --- | --- | --- |
| `--force-with-lease` | `push` | force only if the remote matches what you fetched |
| `-S` | `commit`, `tag` | sign with a GPG, SSH, or X.509 key |
| `--no-ff` | `merge` | always create a merge commit |
| `-p` | `add`, `log`, `stash` | operate hunk by hunk, or show patches |
| `--amend` | `commit` | rewrite the last commit instead of adding one |
| `--depth <n>` | `clone`, `fetch` | limit history to the last n commits |

Prefer `--force-with-lease` over `--force`. The lease aborts the push if someone else advanced the branch after your last fetch, which prevents overwriting their work.

## Security notes

Secrets committed to history stay in history. Deleting a file in a later commit does not remove the earlier blob, so an API key or password remains readable to anyone with the clone (CWE-540, inclusion of sensitive information in source code). Removing it requires a history rewrite with `git filter-repo` or the BFG tool, followed by a force push and credential rotation. Prevent the problem with a `.gitignore` that excludes `.env`, key files, and build secrets, and never run `git add -A` blindly.

Sign commits and tags with `git commit -S` and `git tag -s` so reviewers can verify authorship. Unsigned history lets an attacker forge a committer name. Enable branch protection that requires signed, reviewed commits on the host.

Store credentials with a credential helper (`git config --global credential.helper`) that uses the OS keychain, not a plaintext `~/.git-credentials` file (CWE-312, cleartext storage of sensitive information). Treat submodules and hooks as executable trust boundaries: a cloned repository can ship a `.git/hooks` script or a submodule URL you did not vet, so review `.gitmodules` and never run hooks from an untrusted source without reading them.

Turn on secret scanning and push protection at the host level. These block a push that contains a recognized token pattern before it reaches the shared history. See /SECURE_CODING_REFERENCE.md for secret-handling and input-validation guidance.

## Resources

- `git help <command>` and the `git(1)` man pages, installed with Git.
- Pro Git by Scott Chacon and Ben Straub, the official reference book.
- The Git Reference Manual at the project's documentation site.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/ssh.md
- /commands/curl.md
- /commands/linux-commands.md
