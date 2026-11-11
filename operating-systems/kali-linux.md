<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Kali Linux

> A penetration-testing distribution based on Debian Testing, published as dated snapshots of its kali-rolling branch.

Part of [Operating systems](/operating-systems/README.md) (Security testing distributions). This is a rolling release: it has no numbered versions that reach end of life.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| Rolling (2026.3 snapshot) | kali-rolling | 2026-10-26 | 2026.3 | Not applicable | Not applicable | Not applicable | Rolling release |

- Rolling (2026.3 snapshot): Snapshots are not supported separately; keeping kali-rolling current is the support model.

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| Rolling (2026.3 snapshot) | Linux 7.1 in the 2026.3 snapshot | amd64, arm64, armhf | Debian Testing | kali-rolling (http.kali.org) |

## Where its advisories live

Kali publishes no numbered security advisories. It imports most packages from Debian Testing as-is (Kali's relationship with Debian), so for the shared packages the [Debian Security Tracker](https://security-tracker.debian.org/tracker/) shows each CVE's status in the testing suite. Fixes reach a Kali host through the kali-rolling branch.

## How it patches

Package manager: `apt` and `dpkg`.

kali-rolling is the default branch most users should run; it pulls from kali-dev once packages are judged stable (Kali Branches).

```sh
sudo apt update
sudo apt full-upgrade -y
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `dpkg-query -W 'linux-image-*'` | Installed kernel image packages and their versions |
| `cat /etc/debian_version` | `kali-rolling` |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| Rolling (2026.3 snapshot) | `ID=kali`, `VERSION_ID=2026.3` | Lab host over SSH, 2026-11-03 (`VERSION_CODENAME=kali-rolling`, kernel `7.1.5+kali-amd64`) |

## Security relevance

Kali is an offensive and testing distribution, so it is the practitioner's platform rather than a target: it ships the toolset for authorized assessment work. The relevant disciplines are keeping the testing host itself clean and segregated, operating only within an authorized scope, and protecting the engagement data it holds. The penetration testing methodology and red team references below set the ground rules.

## Hardening

- [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md)
- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)

Case studies that discuss Kali Linux:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)
- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)
- [The Multipath TCP Attack Surface: A 2026 Case Study](/case-studies/MPTCP_ATTACK_SURFACE_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Kali Linux is `product:kali-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Kali Linux releases](https://www.kali.org/releases/)
- [Kali branches](https://www.kali.org/docs/general-use/kali-branches/)
- [Updating Kali](https://www.kali.org/docs/general-use/updating-kali/)
- [Kali's relationship with Debian](https://www.kali.org/docs/policy/kali-linux-relationship-with-debian/)
- [Get Kali](https://www.kali.org/get-kali/)

<!-- os-pages:end -->
