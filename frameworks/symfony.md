# Symfony

Symfony is a server-side web framework written in PHP, built from a set of reusable components. It can run as a full-stack framework or supply individual components to other projects. Many PHP tools, including parts of Laravel and Drupal, depend on Symfony components. Its design favors explicit configuration, dependency injection, and standards compliance.

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

- `/languages/php.md`
- `/frameworks/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/WEB_APPLICATION_SECURITY_REFERENCE.md`
- `/API_SECURITY_REFERENCE.md`
- `/frameworks/laravel.md`
- `/frameworks/spring-boot.md`
- `/frameworks/django.md`
