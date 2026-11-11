# Symfony

Symfony is a server-side web framework written in PHP, built from a set of reusable components. It can run as a full-stack framework or supply individual components to other projects. Many PHP tools, including parts of Laravel and Drupal, depend on Symfony components. Its design favors explicit configuration, dependency injection, and standards compliance.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Symfony, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,210 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Symfony application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

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

Fabien Potencier released Symfony in 2005. The project introduced decoupled components that could be used on their own. This component model shaped much of the modern PHP ecosystem and influenced the PSR standards.

Symfony follows a predictable release schedule with long-term support versions every two years. The framework separates stable components from the full-stack distribution. Applications choose only the parts they need through Composer and the Flex plugin.

## Architecture

The `HttpKernel` component drives the request-response flow. A `Request` object enters, the kernel dispatches events, a controller returns a `Response`, and the kernel sends it back. Kernel events let listeners act at defined points, such as before controller resolution or during exception handling.

Reusable components are the foundation. Examples include Routing, HttpFoundation, Security, Console, and the EventDispatcher. Bundles package components and configuration into installable units, though modern applications favor a single application bundle.

The service container manages dependency injection. Services are defined in configuration or discovered through autowiring and autoconfiguration. The container compiles to cached PHP for fast resolution in production.

## Routing, data, and key subsystems

Routes map URIs to controller actions, declared with PHP attributes or in YAML and XML. The Routing component matches requests and generates URLs from named routes. Controllers are plain classes that return a `Response`.

Doctrine ORM is the common persistence layer. Entities map to tables, and the entity manager tracks and flushes changes. Doctrine uses the data-mapper pattern, which keeps entities separate from persistence logic.

Twig is the template engine. It compiles templates to PHP and escapes output by default. Other subsystems include the Security component for authentication and authorization, the Messenger component for queues and buses, the Form component, and the Console component for commands.

## A minimal example

```php
// src/Controller/PostController.php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class PostController extends AbstractController
{
    #[Route('/posts/{id}', name: 'post_show')]
    public function show(int $id): Response
    {
        return $this->render('post/show.html.twig', ['id' => $id]);
    }
}
```

## Ecosystem and tooling

Composer and Symfony Flex manage dependencies and apply recipe-based configuration. The `bin/console` command runs migrations, clears caches, and generates code. The Profiler and web debug toolbar surface request detail during development.

The wider ecosystem includes API Platform for REST and GraphQL APIs, and Doctrine for persistence and migrations. Testing uses PHPUnit with the `BrowserKit` and `DomCrawler` components for functional tests. Messenger integrates with transports such as AMQP and Redis.

## Security relevance

This section is the threat-facing view of Symfony: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing PHP web applications and APIs. Because many PHP projects embed Symfony components, including parts of Laravel and Drupal, a single component advisory has wide reach. Symfony is recognizable from `X-Debug-Token` and `X-Debug-Token-Link` headers when the profiler is exposed, the `/_profiler` path, and Twig error pages.
- Offensive interest centers on object injection. Burp Suite and OWASP ZAP drive endpoint testing, and PHPGGC builds PHP gadget-chain payloads for `unserialize` sinks.
- Audit and defensive tooling is the PHP set: composer audit or the Local PHP Security Checker for the dependency tree, and Psalm or PHPStan with Semgrep for static analysis.
- The dependency surface is Composer and Packagist, pinned through `composer.lock`. The surface extends below the framework to the PHP interpreter itself: the PHP2Shell wave put every internet-facing PHP server in scope regardless of framework, covered in [the PHP2Shell case study](/case-studies/PHP2SHELL_OCTOBER_2026.md) and [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Symfony application code runs on PHP, a memory-managed language, so the dominant classes in that code are injection and access-control flaws rather than memory corruption, though the C interpreter beneath it has had memory-corruption flaws of its own. The fixes for each are detailed in the section below.

- PHP object injection and insecure deserialization ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)) when `unserialize` runs on attacker-controlled data, reachable through published gadget chains.
- SQL injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) when user input is concatenated into DQL or native SQL instead of bound as a parameter.
- Cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) through the Twig `raw` filter applied to untrusted input.
- Broken access control ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)) when voters and access-control rules are incomplete and an endpoint is reachable without the intended check.

### Why it matters

Fingerprinting Symfony from an exposed profiler or debug headers tells a tester where to look first: pull the profiler for internal detail, probe `unserialize` and DQL sinks, test the Twig `raw` paths, and audit both the Composer tree and the PHP runtime version for known flaws. composer audit and the Local PHP Security Checker are the engine-specific audit tools for that dependency tree. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Twig autoescapes variables in HTML context, which blocks reflected cross-site scripting (CWE-79). The `raw` filter disables escaping and must never apply to untrusted input. Choose the correct escaping strategy for non-HTML contexts such as JavaScript. See `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Symfony provides CSRF token helpers for forms and manual checks (CWE-352). The Form component injects and validates tokens automatically. For custom POST handlers, validate the token with the CSRF manager before acting.

The Security component handles authentication and authorization (CWE-287). Authenticators verify credentials, voters make fine-grained access decisions, and access control rules guard URL patterns and roles. Prefer voters over scattered inline checks, and hash passwords with the configured password hasher. `/API_SECURITY_REFERENCE.md` covers token and stateless API auth.

Doctrine parameterizes queries through prepared statements, which prevents SQL injection (CWE-89). The query builder and DQL bind values safely. Risk returns when you concatenate user input into DQL or native SQL strings. Bind parameters instead. `/SECURE_CODING_REFERENCE.md` covers safe query patterns.

The secrets vault stores sensitive values encrypted in the repository, decrypted at runtime with a key kept out of version control. This keeps API keys and credentials out of plain `.env` files in production. Symfony and Doctrine have had object-injection and deserialization advisories tied to `unserialize` on attacker data (CWE-502 context). Keep components patched and avoid deserializing untrusted input.

## Performance and scaling

The compiled container and cached routes keep per-request work low. Run `cache:clear` and warmup during deployment so the first request is not slow. OPcache and preloading further reduce startup cost.

Doctrine's lazy associations produce N+1 queries under iteration. Use DQL joins or fetch-join hints to batch loads. The Messenger component moves slow work to asynchronous transports. Stateless application servers scale horizontally behind a load balancer with shared storage.

## Common pitfalls

Leaving the app in `dev` environment or the debug toolbar enabled in production leaks internal detail. Set `APP_ENV=prod` and disable debug. Keep decryption keys and `.env.local` out of version control.

Applying the Twig `raw` filter to user input reopens cross-site scripting. Building DQL by string concatenation reopens injection. Forgetting to run Messenger workers strands queued messages. Overbroad access control rules can grant more than intended, so test authorization paths.

## Resources

- The Symfony documentation and its Security guide
- The Twig documentation
- The Doctrine documentation
- OWASP Cheat Sheet Series
- OWASP Top 10

## Related pages

- [PHP](/languages/php.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API Security Reference Library](/API_SECURITY_REFERENCE.md)
- [Laravel](/frameworks/laravel.md)
- [Spring Boot](/frameworks/spring-boot.md)
- [Django](/frameworks/django.md)
