# curl Command Reference

`curl` transfers data to and from a server over HTTP, HTTPS, FTP, and many other protocols. It is the default tool for testing APIs, scripting downloads, and debugging requests from the command line. This page covers the request, output, authentication, and TLS options you reach for daily. Examples assume HTTP or HTTPS, the most common case.

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

## Security notes

The `-k` and `--insecure` flags turn off TLS certificate verification. The transfer still looks encrypted, but any host can impersonate the server, which defeats the purpose of HTTPS (CWE-295, improper certificate validation). Use `--cacert` to trust an internal CA instead of disabling checks. Never ship `-k` in production scripts.

Credentials on the command line are exposed. A `-u user:pass` argument or a token in the URL appears in the process list (`ps`), in shell history, and often in server logs (CWE-214, invocation of process with sensitive arguments; CWE-532, sensitive information in logs). Pass secrets through environment variables, a `-H @file` header file, or `--netrc`, and avoid putting tokens in the query string.

Scripting `curl` against a URL that comes from untrusted input is a server-side request forgery vector. An attacker can supply `http://169.254.169.254/` or an internal address to reach a cloud metadata service or an internal host (CWE-918). Validate and allowlist destination hosts, disable unexpected redirects with `--max-redirs 0` where appropriate, and never pass a user-supplied URL straight into `curl -L`. See /SECURE_CODING_REFERENCE.md for input-validation and SSRF guidance.

## Resources

- The `curl(1)` man page, installed with curl.
- The curl project documentation and the "everything curl" book by Daniel Stenberg.
- The libcurl API reference for programmatic use.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/jq.md
- /commands/ssh.md
- /commands/networking-commands.md
