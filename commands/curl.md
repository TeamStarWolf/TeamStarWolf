# curl Command Reference

`curl` transfers data to and from a server over HTTP, HTTPS, FTP, and many other protocols. It is the default tool for testing APIs, scripting downloads, and debugging requests from the command line. This page covers the request, output, authentication, and TLS options you reach for daily. Examples assume HTTP or HTTPS, the most common case.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers, administrators and testers who send HTTP and other URL requests from a terminal

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (815 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the curl commands for a task at hand, you want a common workflow to copy and adapt, you are looking up a flag or option worth knowing, or you need the security notes that go with them

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Core commands](#core-commands), [Common workflows](#common-workflows), [Security notes](#security-notes)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [jq Command Reference](/commands/jq.md), [SSH Command Reference](/commands/ssh.md), [Networking Command Reference](/commands/networking-commands.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it runs

`curl` is a command-line client built on the libcurl library. It ships on Linux, macOS, and recent Windows, and builds on most other systems. It reads a URL, sends a request, and writes the response to standard output unless told otherwise. It does not run JavaScript or render pages; it moves bytes.

## Core commands

Basic requests.

```bash
curl https://api.example.com/status   # GET, print body to stdout
curl -I https://example.com            # headers only (HEAD)
curl -i https://example.com            # response headers plus body
curl -s https://example.com            # silent, no progress meter
```

Set the method, headers, and body.

```bash
curl -X POST https://api.example.com/items
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/me
curl -H "Content-Type: application/json" \
     -d '{"name":"widget"}' https://api.example.com/items
curl -F "file=@report.pdf" https://api.example.com/upload
```

Save output and follow redirects.

| Command | Purpose |
| --- | --- |
| `curl -o out.html <url>` | write body to a named file |
| `curl -O <url>` | save using the remote file name |
| `curl -L <url>` | follow HTTP redirects |
| `curl -s -o /dev/null -w "%{http_code}" <url>` | print only the status code |

Authentication, cookies, and proxies.

```bash
curl -u user:pass https://api.example.com   # HTTP basic auth
curl -c jar.txt https://example.com/login   # save cookies to a jar
curl -b jar.txt https://example.com/account # send cookies from a jar
curl -x http://proxy:3128 https://example.com  # route through a proxy
```

TLS and name resolution.

```bash
curl --cacert ca.pem https://internal.example.com   # trust a custom CA
curl --resolve api.example.com:443:10.0.0.5 https://api.example.com
curl --retry 3 --retry-delay 2 https://api.example.com   # retry on failure
```

## Common workflows

Post JSON to an API and inspect the status and body.

```bash
curl -i -X POST https://api.example.com/orders \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"sku":"A1","qty":2}'
```

Download a release and follow the redirect to the mirror.

```bash
curl -L -O https://downloads.example.com/app/latest.tar.gz
```

Log in, keep the session cookie, then fetch a protected page.

```bash
curl -c jar.txt -d "user=me&pass=$PW" https://example.com/login
curl -b jar.txt https://example.com/dashboard
```

Health-check an endpoint in a script and act on the status code.

```bash
code=$(curl -s -o /dev/null -w "%{http_code}" https://api.example.com/health)
if [ "$code" != "200" ]; then echo "unhealthy: $code"; exit 1; fi
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `-X <method>` | set the request method |
| `-H <header>` | add a request header |
| `-d` / `--data` | send a request body (implies POST) |
| `--data-urlencode` | URL-encode a body field safely |
| `-F` | send a multipart form, `@file` reads a file |
| `-L` | follow redirects |
| `-w <format>` | print selected response variables |
| `--fail` | exit non-zero on an HTTP error status |

Add `--fail` in scripts so a 404 or 500 returns a non-zero exit code instead of writing an error page to your output.

## Security relevance

This section is the threat-facing view of `curl`: how it appears in offensive work and in defender telemetry. The safe-use guidance for your own scripts is in the "Security notes" section that follows.

### Where it appears

- Payload staging. Once on a host, `curl` is a living-off-the-land way to pull a second stage from attacker infrastructure, often piped straight into a shell so nothing lands on disk first. It avoids shipping a toolkit up front.
- Server-side request forgery. When a service builds a `curl` target from user input, an attacker steers it at `http://169.254.169.254/` or an internal host to reach a cloud metadata endpoint or a service behind the firewall.
- Exfiltration. A POST over HTTPS carries stolen data out while blending into normal web traffic.
- Telemetry. Defenders see it in process-creation logs that capture the remote URL on the command line, in proxy and DNS records, and in endpoint alerts when `curl` is spawned by a web-server account or writes to a temp path.

### Dominant weakness classes

`curl` is a userspace client, so the risks are trust and exposure rather than memory corruption.

- Server-side request forgery ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)) when a destination URL comes from untrusted input.
- Download of code without an integrity check ([CWE-494](https://cwe.mitre.org/data/definitions/494.html)), the fetch-and-run pattern.
- Inclusion of functionality from an untrusted control sphere ([CWE-829](https://cwe.mitre.org/data/definitions/829.html)) when fetched content is executed directly.
- Improper certificate validation ([CWE-295](https://cwe.mitre.org/data/definitions/295.html)) whenever `-k` suppresses TLS checks.

### Why it matters

Spotting `curl` spawned by a service account, or fetching a URL into a pipe to a shell, is a high-value signal for initial access and staging. For an auditor, a `curl` call that takes a user-supplied URL is the first place to probe for SSRF. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for SSRF and request-handling guidance.

## Security notes

The `-k` and `--insecure` flags turn off TLS certificate verification. The transfer still looks encrypted, but any host can impersonate the server, which defeats the purpose of HTTPS (CWE-295, improper certificate validation). Use `--cacert` to trust an internal CA instead of disabling checks. Never ship `-k` in production scripts.

Credentials on the command line are exposed. A `-u user:pass` argument or a token in the URL appears in the process list (`ps`), in shell history, and often in server logs (CWE-214, invocation of process with sensitive arguments; CWE-532, sensitive information in logs). Pass secrets through environment variables, a `-H @file` header file, or `--netrc`, and avoid putting tokens in the query string.

Scripting `curl` against a URL that comes from untrusted input is a server-side request forgery vector. An attacker can supply `http://169.254.169.254/` or an internal address to reach a cloud metadata service or an internal host (CWE-918). Validate and allowlist destination hosts, disable unexpected redirects with `--max-redirs 0` where appropriate, and never pass a user-supplied URL straight into `curl -L`. See /SECURE_CODING_REFERENCE.md for input-validation and SSRF guidance.

## Resources

- The `curl(1)` man page, installed with curl.
- The curl project documentation and the "everything curl" book by Daniel Stenberg.
- The libcurl API reference for programmatic use.

## Related pages

- [Command reference](/commands/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [jq Command Reference](/commands/jq.md)
- [SSH Command Reference](/commands/ssh.md)
- [Networking Command Reference](/commands/networking-commands.md)
