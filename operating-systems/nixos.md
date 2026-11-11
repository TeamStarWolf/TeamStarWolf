<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# NixOS

> A declarative distribution built on the Nix package manager: the whole system is described in configuration and rebuilt from it.

Part of [Operating systems](/operating-systems/README.md) (Independent distributions). Support dates come from the [endoflife.date](https://endoflife.date/nixos) API (`https://endoflife.date/api/nixos.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 26.05 | Yarara | 2026-05-30 | Not published | Not published | 2026-12-31 | Not published | Supported |
| 25.11 | Xantusia | 2025-11-30 | Not published | Not published | 2026-06-30 | Not published | Ended |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 26.05 | Linux 6.18 (default kernel package) | x86_64, aarch64 | Independent (nixpkgs) | nixos-26.05 channel |
| 25.11 | Linux 6.12 (default since 25.05) | x86_64, aarch64 | Independent (nixpkgs) | nixos-25.11 channel |

## Where its advisories live

- [Nixpkgs security tracker](https://tracker.security.nixos.org/).
- [NixOS Discourse security announcements](https://discourse.nixos.org/c/announcements/security).

NixOS publishes no numbered advisory series; the security team names the tracker and the Discourse announcements as its channels (NixOS security team page).

## How it patches

Package manager: Nix (`nixos-rebuild`).

A stable release gets fixes on its release channel; `--upgrade` updates the channel before rebuilding. Releases come every six months (May and November) and each stays supported for about seven months.

```sh
sudo nixos-rebuild switch --upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `nixos-version` | Release, revision and codename |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 26.05 | `ID=nixos`, `VERSION_ID=26.05` | nixpkgs `version.nix` (sets `ID` to `nixos` and `VERSION_ID` to the release) |
| 25.11 | `ID=nixos`, `VERSION_ID=25.11` | nixpkgs `version.nix` (sets `ID` to `nixos` and `VERSION_ID` to the release) |

## Security relevance

NixOS builds the whole system declaratively from a configuration, so its distinctive property is a reproducible, auditable host where changes are explicit and rollbacks are clean. That reduces configuration drift, a common source of weakness, but the build inputs and the Nix channels are a supply-chain surface to trust. As a running host it still presents the standard Linux foothold surface of SSH, sudo, and kernel escalation.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for NixOS is `product:nixos`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [NixOS release notes](https://nixos.org/manual/nixos/stable/release-notes)
- [NixOS security team](https://nixos.org/community/teams/security/)
- [NixOS download](https://nixos.org/download/)
- [nixpkgs: os-release generator (version.nix)](https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/misc/version.nix)

<!-- os-pages:end -->
