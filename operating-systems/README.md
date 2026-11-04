<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Operating systems

> The Linux distributions defenders run, patch, and have to identify: one page per system with its versions and support dates, where its security advisories are published, how it takes updates, and the terminal commands that tell you which one you are on.

Support dates come from the [endoflife.date](https://endoflife.date/) API, fetched on 2026-11-03; everything else comes from the vendor and project pages each page cites. For hardening steps, start with the [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md) and the [Harden a Linux Host](/guides/HARDEN_A_LINUX_HOST.md) guide; for what each offensive, forensic, and privacy distribution is for, see [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md).

## Debian family

Debian and Ubuntu, whose archive draws on Debian; both patch with apt and dpkg.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Debian](/operating-systems/debian.md) | 13, 12, 11 | `apt` and `dpkg` | Debian Security Advisories (DSA), Debian LTS Advisories (DLA), Debian Security Tracker |
| [Ubuntu](/operating-systems/ubuntu.md) | 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS | `apt` and `dpkg` | Ubuntu Security Notices (USN) |

## Red Hat Enterprise Linux family

Red Hat Enterprise Linux, the distributions that follow its releases, and Fedora, patched with dnf and rpm.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Red Hat Enterprise Linux](/operating-systems/rhel.md) | 10, 9, 8 | `dnf` and `rpm` | Red Hat Security Advisories (RHSA) |
| [AlmaLinux](/operating-systems/almalinux.md) | 10, 9, 8 | `dnf` and `rpm` | AlmaLinux Security Advisories (ALSA) |
| [Rocky Linux](/operating-systems/rocky-linux.md) | 10, 9, 8 | `dnf` and `rpm` | Rocky Linux Security Advisories (RLSA) |
| [Oracle Linux](/operating-systems/oracle-linux.md) | 10, 9, 8 | `dnf` and `rpm` | Oracle Linux Security Advisories (ELSA) |
| [Fedora](/operating-systems/fedora.md) | 45, 44 | `dnf` and `rpm` | Fedora updates (Bodhi), security type |

## SUSE family

SUSE Linux Enterprise and the openSUSE distributions, patched with zypper and rpm.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [SUSE Linux Enterprise Server](/operating-systems/sles.md) | 16.0, 15 SP7 | `zypper` and `rpm` | SUSE security updates (SUSE-SU) |
| [openSUSE Leap](/operating-systems/opensuse-leap.md) | 16.0 | `zypper` and `rpm` | openSUSE security updates (openSUSE-SU), SUSE security updates (SUSE-SU) |
| [openSUSE Tumbleweed](/operating-systems/opensuse-tumbleweed.md) | Rolling | `zypper` and `rpm` | openSUSE security updates (openSUSE-SU) |

## Independent distributions

Distributions with their own package managers and release models.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Arch Linux](/operating-systems/arch-linux.md) | Rolling | `pacman` | Arch Linux Security Advisories (ASA) |
| [Alpine Linux](/operating-systems/alpine-linux.md) | 3.24, 3.23 | `apk` | Alpine secdb |
| [Gentoo Linux](/operating-systems/gentoo.md) | Rolling | Portage (`emerge`) | Gentoo Linux Security Advisories (GLSA) |
| [NixOS](/operating-systems/nixos.md) | 26.05, 25.11 | Nix (`nixos-rebuild`) | Nixpkgs security tracker, NixOS Discourse security announcements |

## Cloud provider distributions

Distributions a cloud provider builds and patches for its own platform.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Amazon Linux](/operating-systems/amazon-linux.md) | 2023, 2 | `dnf` on AL2023, `yum` on AL2 (both rpm) | Amazon Linux Security Center (ALAS) |
| [Azure Linux](/operating-systems/azure-linux.md) | 3.0, 2.0 (CBL-Mariner) | `tdnf` and `rpm` | Azure Linux vulnerability data (OVAL), Microsoft Security Update Guide API |

## Container and immutable hosts

Systems built to run containers: a container base with no kernel, and hosts that update by swapping whole images.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Wolfi](/operating-systems/wolfi.md) | Rolling | `apk` | Wolfi advisories repository, Wolfi security database (secdb) |
| [Flatcar Container Linux](/operating-systems/flatcar.md) | Stable channel | None; whole-image updates through `update_engine` | Flatcar release notes, Flatcar security advisories on GitHub |
| [Bottlerocket](/operating-systems/bottlerocket.md) | 1.x | None; whole-image updates through the Bottlerocket API | Bottlerocket security advisories (BRSA) |

## Security testing distributions

Distributions for penetration testing and security research, built on Debian.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Kali Linux](/operating-systems/kali-linux.md) | Rolling (2026.3 snapshot) | `apt` and `dpkg` | No numbered advisories |
| [Parrot OS](/operating-systems/parrot-os.md) | 7.x (7.4) | `apt` and `dpkg` | No numbered advisories |

## About the catalog

Every page here is written by `scripts/build_os_pages.py` from `data/os/os-catalog.jsonl`, one row per system and major version. Edit the catalog, then run `python scripts/build_os_pages.py`; `--refresh-eol` re-reads the support dates from endoflife.date, and CI runs `--check`. The vocabulary ids in each page's last section are the `product:` rows of `data/vocab/entities.jsonl`.

<!-- os-pages:end -->
