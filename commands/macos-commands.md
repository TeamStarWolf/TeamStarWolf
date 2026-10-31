# macOS Command Reference

macOS ships a BSD-derived Unix base with a set of Apple-specific tools layered on top. The standard POSIX commands behave as on any Unix, so this page focuses on the macOS-only utilities you run in Terminal. These manage packages, preferences, launch services, disks, code signing, and system policy. Audience: developers and administrators working at the macOS command line.

## What it is and where it runs

These commands run in Terminal or iTerm on macOS, on top of the Darwin kernel and the BSD userland. Apple supplies tools such as `launchctl`, `defaults`, `diskutil`, `codesign`, and `spctl`; Homebrew (`brew`) is the common third-party package manager. Many commands need `sudo`, and some are constrained by System Integrity Protection even for root. The base Unix commands (`ls`, `grep`, `find`) match the Linux reference page, with BSD rather than GNU flag differences.

## Core commands

Packages and software:

```bash
brew install nmap           # install a formula
brew upgrade                # upgrade all packages
softwareupdate -l           # list available OS updates
softwareupdate -ia          # install all updates
sw_vers                     # show macOS version and build
```

| Command | Purpose |
|---|---|
| `brew` | Install and manage packages |
| `softwareupdate` | Apply Apple OS and security updates |
| `sw_vers` | Report the macOS version |

Preferences and defaults:

```bash
defaults read com.apple.finder          # read an app's preferences
defaults write com.apple.finder AppleShowAllFiles -bool true
plutil -lint Info.plist                 # validate a property list
open -a Safari https://example.com      # open a file, app, or URL
```

| Command | Purpose |
|---|---|
| `defaults` | Read and write preference plists |
| `plutil` | Validate and convert plist files |
| `open` | Open files, apps, and URLs |
| `pbcopy` / `pbpaste` | Copy to and paste from the clipboard |

Services and persistence:

```bash
launchctl list                          # list loaded launchd jobs
launchctl print gui/$(id -u)            # inspect a user domain
launchctl bootout gui/$(id -u)/com.example.agent
pmset -g                                # show power management settings
```

| Command | Purpose |
|---|---|
| `launchctl` | Manage launchd daemons and agents |
| `pmset` | Configure power and sleep behavior |

Users and disks:

```bash
dscl . -list /Users                     # list local user accounts
dscl . -read /Users/alice               # read one account record
diskutil list                           # list disks and volumes
diskutil info disk0                      # detail for one device
```

| Command | Purpose |
|---|---|
| `dscl` | Query the local directory service |
| `diskutil` | Inspect and manage disks and volumes |

Code signing and policy:

```bash
codesign -dv --verbose=4 /Applications/App.app   # show signing detail
codesign --verify --deep --strict App.app        # verify a signature
spctl --assess --type execute App.app            # check Gatekeeper verdict
spctl --status                                    # is Gatekeeper enabled
```

| Command | Purpose |
|---|---|
| `codesign` | Sign and verify code signatures |
| `spctl` | Query the security assessment policy |

## Common workflows

Verify a downloaded app's signature before trusting it:

```bash
codesign --verify --deep --strict --verbose=2 ~/Downloads/App.app
spctl --assess --type execute --verbose ~/Downloads/App.app
```

Flush and reset a preference you changed, then relaunch the app:

```bash
defaults delete com.apple.dock orientation
killall Dock
```

Audit the launch agents and daemons that start automatically:

```bash
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
launchctl list | grep -v com.apple
```

Record a system baseline for an incident note:

```bash
sw_vers > host.txt
spctl --status >> host.txt
dscl . -list /Users >> host.txt
```

## Flags and options worth knowing

| Flag | Command | Effect |
|---|---|---|
| `-bool` `-int` `-string` | `defaults write` | Set the typed value of a key |
| `--deep` | `codesign` | Verify nested code and resources |
| `--strict` | `codesign` | Apply the strict validation rules |
| `-dv` | `codesign` | Display signing information |
| `-a` | `open` | Open with a named application |
| `bootout` / `bootstrap` | `launchctl` | Unload or load a job in a domain |
| `-ia` | `softwareupdate` | Install all available updates |

## Security notes

Gatekeeper and the assessment policy decide whether downloaded code runs. Never advise `spctl --master-disable`, which turns Gatekeeper off system-wide and allows unsigned code from anywhere. Use `spctl --assess` to check a specific app instead. Keep `spctl --status` reporting `assessments enabled`.

Verify signatures with `codesign --verify --deep --strict` before running downloaded software. A valid signature confirms integrity and identifies the signer; it does not by itself prove the software is safe, so pair it with notarization checks. Treat an ad-hoc or missing signature on a binary as untrusted.

System Integrity Protection (SIP) blocks writes to protected locations such as `/System` and many `/usr` paths, even for root. SIP is managed from Recovery with `csrutil`; do not disable it on production machines. Code that expects to write to those paths should use a supported location instead. See `/SECURE_CODING_REFERENCE.md` for secure file handling.

`launchctl` is the primary persistence point on macOS. A new plist in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, or `/Library/LaunchDaemons` that runs a script or an unsigned binary is a common foothold. Baseline these directories and alert on additions. Weak permissions on a launch daemon plist or its target binary can also enable privilege escalation (CWE-732); keep daemon plists owned by root and not group or world writable.

## Resources

- macOS `man` pages (`man launchctl`, `man codesign`, `man spctl`).
- Apple Platform Security guide.
- Homebrew documentation (`brew help`).

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/linux-commands.md
- /commands/ssh.md
- /commands/networking-commands.md
