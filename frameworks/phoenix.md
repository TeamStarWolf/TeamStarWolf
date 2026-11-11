# Phoenix

Phoenix is a web framework for Elixir that runs on the Erlang virtual machine, the BEAM. It follows an MVC-like structure and uses a composable request pipeline built from plugs. Its distinguishing feature is Phoenix LiveView, which renders real-time interactive pages from the server without hand-written client JavaScript.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Phoenix, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,379 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Phoenix application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Elixir](/languages/elixir.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Phoenix was created by Chris McCord and reached 1.0 in 2015. It builds on the BEAM's strengths in concurrency and fault tolerance, so a single node can hold large numbers of lightweight processes. Each connection and each LiveView runs in its own process.

The framework grew alongside LiveView, introduced around 2019, which shifted much interactive UI work back to the server. Contexts, added in Phoenix 1.3, pushed teams toward grouping business logic by domain. Together these shape how modern Phoenix applications are organized.

## Architecture

A request enters through the endpoint, which is the top of the plug pipeline. Plugs are small composable functions that each take a connection and return a connection. The endpoint runs application-wide plugs, then hands off to the router.

The router matches the path and method, then runs a pipeline of plugs (for example `:browser` or `:api`) before dispatching to a controller action. Controllers call into contexts and render a view or JSON. Views and templates produce the response body.

Contexts are plain Elixir modules that expose a domain's public functions. They hide schema and query details behind named operations like `Accounts.create_user/1`. This boundary keeps web code thin and business logic reusable.

## Routing, data, and key subsystems

The router maps verbs and paths to controller actions or LiveViews. `resources "/users", UserController` expands to the standard set of routes. Pipelines attach cross-cutting plugs such as session handling and CSRF protection.

Ecto is the data layer. It separates schemas, changesets, and the repository. Changesets validate and cast incoming data before it reaches the database, and `Ecto.Repo` runs the queries. Ecto builds parameterized queries by default.

Phoenix LiveView holds UI state in a server process and sends diffs over a WebSocket. Event handlers like `handle_event/3` respond to clicks and form input, update socket assigns, and the framework re-renders only what changed. HEEx templates describe the markup.

Channels and PubSub carry real-time messaging. A channel is a process that clients join by topic, and `Phoenix.PubSub` broadcasts messages across topics and nodes. This powers chat, notifications, and live dashboards.

## A minimal example

```elixir
defmodule MyAppWeb.CounterLive do
  use MyAppWeb, :live_view

  def mount(_params, _session, socket) do
    {:ok, assign(socket, count: 0)}
  end

  def handle_event("inc", _params, socket) do
    {:noreply, update(socket, :count, &(&1 + 1))}
  end

  def render(assigns) do
    ~H"""
    <button phx-click="inc">Count: {@count}</button>
    """
  end
end
```

## Ecosystem and tooling

The `mix phx.new` generator scaffolds a full application, and `mix phx.gen.*` tasks create contexts, schemas, and LiveViews. Code reloading and a long-running server come from `mix phx.server`. The generators wire routes and migrations into place.

Ecto ships with its own migration and query tooling through `mix ecto.*` tasks. `Phoenix.LiveDashboard` gives a runtime view of metrics, processes, and Ecto queries. Telemetry events expose timing data for instrumentation.

Testing uses `ExUnit` with Phoenix helpers for connection and LiveView tests. `Phoenix.ConnTest` drives controllers, and `Phoenix.LiveViewTest` interacts with live pages in tests. The BEAM's process model makes concurrent test runs straightforward.

## Security relevance

This section is the threat-facing view of Phoenix: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing web applications and real-time LiveView pages. A Phoenix app is recognizable from the outside: `phx-` attributes and a LiveView WebSocket in the rendered HTML, a `_csrf_token` in forms, and the default Phoenix error pages. The server often sits behind Cowboy or Bandit.
- Offensive interest centers on LiveView: a crafted WebSocket message can call any `handle_event/3`, so testers probe whether each handler re-checks authorization rather than trusting the client. Burp Suite and OWASP ZAP drive the HTTP surface.
- Audit tooling is written for the framework. Sobelow is the static analysis scanner built for Phoenix, and `mix_audit` checks the Hex dependency tree against known advisories.
- The dependency surface is the Hex package manager, pinned through `mix.lock`.

### Dominant weakness classes

Phoenix runs on [Elixir](/languages/elixir.md) on the BEAM, a memory-managed runtime, so the dominant classes are logic and injection flaws rather than memory corruption. The fixes for each are in the section below.

- Missing authorization ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)) in LiveView handlers, since a crafted WebSocket event can reach a handler that assumed a mount-time check still held.
- SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) through `Ecto.Adapters.SQL.query` or a `fragment` built from raw input, rather than parameterized `Repo` calls.
- Cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) through `raw/1` on untrusted content in a HEEx template.
- Exposure of the signing secret ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)), the endpoint `secret_key_base`, which lets an attacker forge signed session cookies.

### Why it matters

Recognizing Phoenix, usually through its `phx-` attributes and LiveView socket, tells a tester which pivots to try first: send crafted events to LiveView handlers to test per-event authorization, look for `raw/1` and raw Ecto fragments, and check whether the signing secret is committed. Sobelow is the framework-specific static analyzer to reach for. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Phoenix enables cross-site request forgery protection by default in the `:browser` pipeline through `protect_from_forgery`. Forms generated by the framework include the token automatically. Removing this plug or building forms by hand without the token reintroduces CWE-352 (cross-site request forgery). The `/WEB_APPLICATION_SECURITY_REFERENCE.md` covers CSRF defenses.

HEEx templates escape interpolated values by default, which prevents most cross-site scripting. The `~H` sigil treats `{...}` content as data and HTML-escapes it. Bypassing this with `raw/1` on user input, or injecting unescaped attributes, causes CWE-79 (cross-site scripting). Keep `raw/1` for trusted, already-sanitized content only. See `/SECURE_CODING_REFERENCE.md` for output-encoding rules.

Ecto parameterizes queries, so ordinary `Repo` calls resist SQL injection. The risk returns with `Ecto.Adapters.SQL.query/4` and interpolated strings, or `fragment` built from raw input, which is CWE-89 (SQL injection). Always pass values as parameters rather than string-building the SQL.

LiveView authorization is the subtle area. The server trusts nothing that arrives from the client, including which events fire. Authorize every `handle_event/3` and `handle_params/3` against the current user, not against hidden form fields or disabled buttons. Skipping these checks produces CWE-862 (missing authorization), since a crafted WebSocket message can call any handler. The `/API_SECURITY_REFERENCE.md` describes per-action authorization.

Socket assigns are server state, but they are only as trustworthy as what set them. Do not treat a value copied from client params into assigns as validated. Re-check identity and permissions on each event rather than assuming mount-time checks still hold.

Sessions are signed, and can be encrypted, using the endpoint's secret key base. Keep that secret out of source control and rotate it if exposed. A leaked key lets an attacker forge session cookies.

## Performance and scaling

The BEAM schedules large numbers of processes across cores with preemptive scheduling. A slow request cannot starve others, because the scheduler interrupts long-running work. This gives steady latency under load.

LiveView keeps a process and its state in memory per connected client. This is cheap per connection but adds up, so size memory for peak concurrent sessions. Diff-based rendering keeps the data sent over the wire small.

PubSub and distribution let Phoenix scale across nodes. Topics broadcast cluster-wide, so a message published on one node reaches subscribers on another. Horizontal scaling mostly means adding nodes behind a load balancer with sticky sessions for sockets.

## Common pitfalls

Putting business logic in controllers or LiveViews defeats contexts. Keep queries and rules in context modules so they stay testable and reusable. Thin web layers age better.

Overusing `raw/1` to render dynamic content is a frequent XSS source. Sanitize first, or restructure so the dynamic part is plain escaped data. Treat `raw/1` as a flag during review.

Assuming mount-time authorization covers later events is a LiveView trap. The process lives on, and new events arrive independently. Re-authorize at each handler.

Large LiveView assigns sent on every render waste bandwidth. Use temporary assigns for lists and streams for large collections. Measure the diff payload when pages feel slow.

## Resources

- The Phoenix Framework documentation and guides
- The Ecto documentation
- *Programming Phoenix LiveView* by Bruce Tate and Sophie DeBenedetto, and *Programming Phoenix* by Chris McCord, Bruce Tate, and Jose Valim

## Related pages

- Language: [Elixir](/languages/elixir.md)
- [Software frameworks](/frameworks/README.md)
- Security references: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)
- Siblings: [Ruby on Rails](/frameworks/rails.md), [Django](/frameworks/django.md), [Laravel](/frameworks/laravel.md)
