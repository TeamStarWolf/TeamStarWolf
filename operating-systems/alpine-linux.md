<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Alpine Linux

> A small, security-oriented distribution built on musl libc and BusyBox.

Part of [Operating systems](/operating-systems/README.md) (Independent distributions). Support dates come from the [endoflife.date](https://endoflife.date/alpine-linux) API (`https://endoflife.date/api/alpine-linux.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 3.24 | None | 2026-06-09 | 3.24.3 | Not published | 2028-06-01 | Not published | Supported |
| 3.23 | None | 2025-12-04 | 3.23.7 | Not published | 2027-11-01 | Not published | Supported |

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 3.24 | linux-lts 6.18 series | aarch64, armhf, armv7, loongarch64, ppc64le, riscv64, s390x, x86, x86_64 | Independent | v3.24 main and community |
| 3.23 | linux-lts 6.18 series | aarch64, armhf, armv7, loongarch64, ppc64le, riscv64, s390x, x86, x86_64 | Independent | v3.23 main |

## Where its advisories live

- [Alpine secdb](https://secdb.alpinelinux.org/): IDs take the form `CVE-YYYY-NNNN (per package)`. Machine-readable: [v3.24 main (JSON)](https://secdb.alpinelinux.org/v3.24/main.json), [v3.23 main (JSON)](https://secdb.alpinelinux.org/v3.23/main.json).

Alpine publishes no numbered advisories: each package's APKBUILD records the CVEs it fixes (`secfixes`), and secdb collects them per branch and repository. The Alpine Security Tracker (security.alpinelinux.org) combines those records with the CVE dictionary and NVD data.

## How it patches

Package manager: `apk`.

Run as root. In containers the fix is usually a rebuild on an updated base image rather than `apk upgrade` in a running container.

```sh
apk update
apk upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `cat /etc/alpine-release` | Full release, for example `3.24.3` |
| `uname -r` | Release of the running kernel |
| `apk info -v linux-lts` | Installed LTS kernel package (absent in containers) |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 3.24 | `ID=alpine`, `VERSION_ID=3.24.x` | Not checked on a running system |
| 3.23 | `ID=alpine`, `VERSION_ID=3.23.x` | Not checked on a running system |

## Security relevance

Alpine is a minimal, musl-based image that shows up inside containers far more than on bare metal, so its relevance is as the base layer of a workload rather than an interactive host. The small footprint reduces the attack surface, but musl and BusyBox behave differently from glibc and coreutils, which can change how an exploit or a hardening control behaves. The main concern is image provenance and the packages pulled from the apk repositories. See the container security reference below.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)

Case studies that discuss Alpine Linux:

- [The XZ Utils Backdoor: A 2024 Supply-Chain Case Study](/case-studies/XZ_UTILS_BACKDOOR_2024.md)

## On the Intelligence Hub

The library's vocabulary id for Alpine Linux is `product:alpine-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Community distribution; free to download. Each package keeps its own open-source licence.

Vendor and project pages read for this page (2026-11-03):

- [Alpine Linux releases](https://alpinelinux.org/releases/)
- [About Alpine Linux](https://alpinelinux.org/about/)
- [Alpine Linux downloads](https://alpinelinux.org/downloads/)
- [Alpine secdb](https://secdb.alpinelinux.org/)
- [linux-lts package, v3.24](https://pkgs.alpinelinux.org/packages?name=linux-lts&branch=v3.24&arch=x86_64)
- [linux-lts package, v3.23](https://pkgs.alpinelinux.org/packages?name=linux-lts&branch=v3.23&arch=x86_64)

<!-- os-pages:end -->
