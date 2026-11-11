# Laravel

Laravel is a server-side web framework written in PHP. It follows the model-view-controller pattern and ships with an opinionated set of components for routing, persistence, templating, and background work. Its goals are developer ergonomics and convention over configuration. Laravel is one of the most widely used PHP frameworks for full-stack and API applications.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Laravel, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,222 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Laravel application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[PHP](/languages/php.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Taylor Otwell released Laravel in 2011 as an alternative to CodeIgniter. The framework grew around a few ideas: expressive syntax, batteries-included defaults, and a clear request lifecycle. Major releases now follow a yearly cadence with long-term support on selected versions.

Laravel sits on top of several Symfony components, including the HTTP foundation. It adds its own routing, ORM, template engine, and command-line tooling. The ecosystem includes starter kits, first-party packages, and hosting tools that cover common application needs.

## Architecture

A Laravel request enters through `public/index.php` and is handled by the HTTP kernel. The kernel runs a stack of middleware, dispatches to a controller or closure, and returns a response. The service container wires dependencies together and resolves them on demand.

The service container is the core of the framework. It performs dependency injection and supports binding interfaces to concrete classes. Service providers register bindings and bootstrap packages during startup. Facades give a static-looking accessor over container-resolved services.

Configuration lives in `config/` and reads from environment variables defined in `.env`. The `APP_KEY` value seeds encryption and must be set per environment. Code organizes into `app/`, routes into `routes/`, and views into `resources/views/`.

## Routing, data, and key subsystems

Routes are declared in `routes/web.php` and `routes/api.php`. Each route maps an HTTP verb and URI to a controller action or closure. Route model binding resolves URL segments into Eloquent model instances automatically.

Eloquent is Laravel's active-record ORM. Each model maps to a table, and relationships are defined as methods. The query builder provides a fluent interface for SQL when you want more control than Eloquent offers.

Blade is the template engine. Templates compile to plain PHP and cache for reuse. Other subsystems include queues for deferred jobs, events and listeners, the cache layer, and the task scheduler. Artisan is the command-line tool for migrations, code generation, and maintenance.

## A minimal example

```php
// routes/web.php
use Illuminate\Support\Facades\Route;
use App\Models\Post;

Route::get('/posts/{post}', function (Post $post) {
    return view('posts.show', ['post' => $post]);
});
```

## Ecosystem and tooling

Composer manages dependencies and autoloading. Artisan handles migrations, seeding, queue workers, and scaffolding. The testing stack builds on PHPUnit and the Pest runner, with HTTP and database test helpers.

First-party packages extend the core. Sanctum and Passport cover token and OAuth authentication. Horizon manages Redis queues, Telescope aids local debugging, and Breeze or Jetstream scaffold authentication UI. Forge and Vapor handle provisioning and serverless deployment.

## Security relevance

This section is the threat-facing view of Laravel: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing PHP web applications and JSON APIs. Laravel is often recognizable from the `laravel_session` and `XSRF-TOKEN` cookies, a `419` "Page Expired" response on a missing CSRF token, and, when `APP_DEBUG` is on, the Ignition error page with its stack traces and environment values.
- Exposed first-party dashboards are a reconnaissance prize: an unprotected `/telescope` or `/horizon` leaks requests, jobs, and configuration.
- Offensive interest centers on an exposed debug page and a leaked `APP_KEY`. Audit and defensive tooling is written for the framework: Larastan runs PHPStan with Laravel-aware rules, Enlightn scans a project for security and configuration issues, and `composer audit` checks dependencies against the PHP advisory database.
- The dependency surface is Composer resolving Packagist. A compromised or typosquatted package runs with full application privilege, the pattern covered in [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Laravel runs on [PHP](/languages/php.md), a memory-managed language, so the dominant classes are injection, deserialization, and logic flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Insecure deserialization and object injection ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), the highest-severity historical class, where `unserialize` on attacker-controlled data drives a gadget chain to code execution, the pattern traced in [the PHP2SHELL case study](/case-studies/PHP2SHELL_OCTOBER_2026.md).
- Code injection through exposed debug tooling ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)), where a left-on Ignition debug page has a documented remote code execution path.
- Mass assignment ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)), where `Model::create($request->all())` lets an attacker set a protected column such as an `is_admin` flag.
- SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) through `DB::raw`, `whereRaw`, or string interpolation that bypasses Eloquent's parameterized defaults.

### Why it matters

Laravel is a large share of the PHP web estate, so fingerprinting it tells a tester which pivots to try first: a leaked `APP_KEY` to forge signed cookies and reach a deserialization sink, an exposed debug page, and mass-assignment on model writes. Larastan and Enlightn are the framework-specific audit tools to reach for. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Laravel ships with defenses that work when you use the defaults. Blade's `{{ }}` syntax escapes output and blocks reflected cross-site scripting (CWE-79). The `{!! !!}` syntax prints raw HTML and must never wrap untrusted input. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for output-encoding guidance.

The `VerifyCsrfToken` middleware protects state-changing web routes against cross-site request forgery (CWE-352). Forms include `@csrf`, and the framework validates the token on each POST, PUT, and DELETE. API routes using token auth are exempt and rely on their own credential checks.

Eloquent and the query builder parameterize values by default, which prevents SQL injection (CWE-89). Risk returns with `DB::raw`, raw `whereRaw` clauses, and string interpolation into queries. Bind user input as parameters instead of concatenating it. `/SECURE_CODING_REFERENCE.md` covers safe query construction.

Mass assignment is a frequent weakness (CWE-915). Calling `Model::create($request->all())` lets an attacker set unexpected columns, such as an `is_admin` flag. Define `$fillable` to allow-list writable attributes, or `$guarded` to block-list them. Never pass unfiltered request data into `create` or `fill`.

Encrypted cookies and sessions depend on `APP_KEY`. A leaked or missing key breaks cookie integrity and session confidentiality. Rotate the key carefully, since rotation invalidates existing encrypted values. Laravel has a history of object-injection and deserialization remote code execution tied to `unserialize` on attacker-controlled data (CWE-502). Keep the framework patched and never deserialize untrusted input. For token issuance and API authorization, see `/API_SECURITY_REFERENCE.md`.

## Performance and scaling

Route, config, and view caching cut per-request overhead in production. The `php artisan optimize` family writes compiled caches. OPcache should be enabled on the PHP runtime.

Eloquent's lazy loading causes N+1 query patterns under iteration. Use eager loading with `with()` to batch related queries. Queues move slow work such as email and image processing off the request path. Horizontal scaling runs stateless app servers behind a load balancer with shared Redis and database backends.

## Common pitfalls

Debug mode left on in production leaks stack traces and environment values. Set `APP_DEBUG=false` and restrict error output. The `.env` file must stay out of version control.

Using `{!! !!}` or `DB::raw` with request data reintroduces injection flaws the defaults prevent. Calling `->all()` on request input invites mass assignment. Forgetting to run queue workers silently strands jobs. Storing large session payloads in cookies hits size limits and slows requests.

## Resources

- The Laravel documentation
- OWASP Cheat Sheet Series
- OWASP Top 10
- *Laravel: Up and Running* by Matt Stauffer

## Related pages

- [PHP](/languages/php.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API Security Reference Library](/API_SECURITY_REFERENCE.md)
- [Symfony](/frameworks/symfony.md)
- [Ruby on Rails](/frameworks/rails.md)
- [Django](/frameworks/django.md)
