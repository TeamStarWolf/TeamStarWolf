<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Amazon Linux

> AWS's own distribution for EC2 and other AWS services; AL2023 keeps its own lifecycle, independent of Fedora, and reports `ID_LIKE=fedora`.

Part of [Operating systems](/operating-systems/README.md) (Cloud provider distributions). Support dates come from the [endoflife.date](https://endoflife.date/amazon-linux) API (`https://endoflife.date/api/amazon-linux.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 2023 | None | 2023-03-01 | 2023.12.20261102.0 | 2027-06-30 | 2029-06-30 | Not published | Supported |
| 2 | None | 2018-06-26 | 2.0.20261102.0 | 2026-06-30 | 2026-06-30 | Not published | Ended |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 2023 | Linux 6.1 by default; 6.12 and 6.18 also offered | x86_64, aarch64 | Independent (AWS), RPM-based | AL2023 repositories, versioned per release |
| 2 | Linux 4.14 or 5.10 | x86_64, aarch64 | Independent (AWS), RPM-based | AL2 repositories |

## Where its advisories live

- [Amazon Linux Security Center (ALAS)](https://alas.aws.amazon.com/): IDs take the form `ALAS2-YYYY-NNNN (AL2), ALAS2023-YYYY-NNNN (AL2023)` (for example `ALAS2023-2026-3338`). Machine-readable: [AL2 RSS](https://alas.aws.amazon.com/AL2/alas.rss), [AL2023 RSS](https://alas.aws.amazon.com/AL2023/alas.rss).

## How it patches

Package manager: `dnf` on AL2023, `yum` on AL2 (both rpm).

AL2023 pins each host to a repository release version, so updates beyond it need an explicit `--releasever` (AL2023 deterministic upgrades).

```sh
sudo dnf check-release-update        # AL2023: is a newer release available?
sudo dnf upgrade --releasever=<version>  # AL2023: move to that release
sudo yum update --security          # AL2
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -q kernel` | Installed kernel packages; more than one means a reboot may be pending |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 2023 | `ID=amzn`, `VERSION_ID=2023` | AWS documentation, Identifying Amazon Linux with os-release |
| 2 | `ID=amzn`, `VERSION_ID=2` | AWS documentation, Identifying Amazon Linux with os-release |

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)
- [Cloud Security Reference Library](/CLOUD_SECURITY_REFERENCE.md)

Case studies that discuss Amazon Linux:

- [A Linux kernel TCP flaw and an AI-written exploit (2026 case study)](/case-studies/LINUX_TCP_UAF_2026.md)

## On the Intelligence Hub

The library's vocabulary id for Amazon Linux is `product:amazon-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Provided by AWS for use on AWS; the packages are open-source licensed.

Vendor and project pages read for this page (2026-11-03):

- [Amazon Linux Security Center](https://alas.aws.amazon.com/)
- [AL2023: Identifying Amazon Linux with os-release](https://docs.aws.amazon.com/linux/al2023/ug/ident-os-release.html)
- [AL2023: kernel changes from AL2](https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2-kernel.html)
- [AL2023: package management tool](https://docs.aws.amazon.com/linux/al2023/ug/package-management.html)
- [AL2023: deterministic upgrades](https://docs.aws.amazon.com/linux/al2023/ug/deterministic-upgrades.html)
- [AL2023: relationship to Fedora](https://docs.aws.amazon.com/linux/al2023/ug/relationship-to-fedora.html)
- [Amazon Linux 2 FAQs](https://aws.amazon.com/amazon-linux-2/faqs/)

<!-- os-pages:end -->
