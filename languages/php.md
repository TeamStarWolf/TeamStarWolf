# PHP

PHP is a dynamically typed, garbage-collected, multi-paradigm language created by Rasmus Lerdorf and first released in 1995. It was designed to embed in HTML for server-side web pages and remains focused on the web, where it runs much of the public internet through applications such as WordPress. It runs on an interpreter (the reference implementation is the Zend-based PHP engine) and is used for web back ends, content management systems, APIs, and command-line scripting.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, object-oriented, procedural |
| Typing | Dynamic, with optional scalar and return type declarations |
| First appeared | 1995 |
| Memory model | Automatic: reference counting plus a cycle collector |
| Reference implementation | [PHP (Zend Engine)](https://github.com/php/php-src) |
| Typical uses | Web back ends, content management, APIs, command-line scripts |
| Governance | [PHP RFC process](https://wiki.php.net/rfc) with voting by core contributors |

Related: [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

PHP began as a set of Common Gateway Interface scripts that Rasmus Lerdorf wrote to track visits to his page, originally called Personal Home Page tools. The name is now a recursive acronym for PHP: Hypertext Preprocessor. PHP 3 and the Zend Engine behind PHP 4 (2000) turned it into a general web language. PHP 7 (2015) brought a large performance jump and scalar type declarations, and PHP 8 (2020) added the JIT compiler, named arguments, attributes, enums, and other modern features.

The reference implementation is the Zend Engine in `php-src`. Language changes go through a public Request for Comments (RFC) process with a vote. The runtime commonly serves requests through PHP-FPM behind a web server, or through an embedded module.

## Paradigm and type system

PHP is dynamically typed, but since PHP 7 a function can declare parameter and return types, and `declare(strict_types=1)` at the top of a file turns implicit scalar coercion into type errors. The type system includes scalar types, classes and interfaces, union types, intersection types, enums, and nullable types written with a leading `?`.

```php
<?php
declare(strict_types=1);

function total(array $prices, float $tax = 0.0): float {
    return array_sum($prices) * (1 + $tax);
}
```

Without `strict_types`, PHP coerces between compatible scalars, which can mask bugs; most current codebases enable strict types.

## Toolchain and ecosystem

- Interpreter: `php` runs scripts and a `-a` interactive shell; `php -S` starts a built-in development server.
- Packaging: libraries publish to [Packagist](https://packagist.org/) and install with [Composer](https://getcomposer.org/), which resolves and locks dependencies through `composer.json` and `composer.lock`.
- Standards: the [PHP-FIG](https://www.php-fig.org/) group publishes PSR recommendations, including PSR-4 autoloading and PSR-12 coding style.
- Formatting and linting: [PHP_CodeSniffer](https://github.com/PHPCSStandards/PHP_CodeSniffer) checks style, [PHP CS Fixer](https://cs.symfony.com/) reformats, and [PHPStan](https://phpstan.org/) and [Psalm](https://psalm.dev/) perform static analysis.

```bash
composer require guzzlehttp/guzzle
php -l script.php   # syntax check without running
```

## Syntax tour

```php
<?php
declare(strict_types=1);

// Variables and string interpolation
$name = "world";
echo "hello, {$name}\n";

// Arrays serve as both lists and maps
$squares = array_map(fn($n) => $n * $n, range(0, 4)); // [0,1,4,9,16]
$lookup  = ["a" => 1, "b" => 2];

// Functions with typed, named arguments
function greet(string $who, bool $excited = false): string {
    return "hi {$who}" . ($excited ? "." : ".");
}

// Classes, enums, and readonly properties
enum Suit { case Hearts; case Spades; }

final class Point {
    public function __construct(
        public readonly int $x,
        public readonly int $y,
    ) {}
}

// Exceptions
try {
    $value = intdiv(1, 0);
} catch (\DivisionByZeroError $e) {
    $value = 0;
}
```

## Idioms and different approaches

- Start new files with `declare(strict_types=1);` so scalar type mismatches raise errors.
- Use Composer and PSR-4 autoloading rather than manual `require` chains.
- Prefer the array functions (`array_map`, `array_filter`, `array_reduce`) and arrow functions for transformations.
- Use the null coalescing operator `??` and null-safe operator `?->` to handle missing values without nested checks.
- Separate business logic from templates; frameworks such as Laravel and Symfony enforce this structure.

## Design principles

PHP's guiding idea has always been pragmatism for the web: lower the distance between a request and a response, and ship features that solve common server tasks. The language grew organically, which left inconsistencies in the standard-library naming and argument order, but the RFC process and the PHP 7 and 8 lines have tightened the type system, improved performance, and added modern constructs while keeping backward compatibility a priority.

## Standard library and notable frameworks

The built-in functions cover strings, arrays, the file system, PCRE regular expressions, and database access through PDO. The ecosystem is framework-heavy: [Laravel](https://laravel.com/) and [Symfony](https://symfony.com/) are the two widely used full-stack frameworks, [WordPress](https://wordpress.org/) and [Drupal](https://www.drupal.org/) power content sites, [Guzzle](https://docs.guzzlephp.org/) handles HTTP, and [Doctrine](https://www.doctrine-project.org/) is an object-relational mapper.

## Testing and packaging

[PHPUnit](https://phpunit.de/) is the standard test framework; [Pest](https://pestphp.com/) wraps it with a terser syntax.

```php
<?php
use PHPUnit\Framework\TestCase;

final class AddTest extends TestCase {
    public function testAdd(): void {
        $this->assertSame(5, 2 + 3);
    }
}
```

A distributable package declares metadata in `composer.json`, tags a release in version control, and registers on Packagist so Composer can install it.

## Performance and concurrency

PHP's classic model is shared-nothing: each request starts with a clean state, runs, and tears down, which simplifies reasoning but means long-lived state lives in a database, cache, or session store. PHP 8 added a just-in-time compiler that helps CPU-bound code, though most web workloads are I/O-bound. Concurrency approaches:

- Process-based scaling through PHP-FPM worker pools handles concurrent requests.
- Long-running application servers such as [Swoole](https://swoole.com/) and [RoadRunner](https://roadrunner.dev/) keep workers alive and add coroutine-style concurrency.
- Background work is usually offloaded to queue workers rather than threads.

## Common pitfalls

- Without `declare(strict_types=1)`, PHP coerces scalars silently, so `"5 apples" == 5` can evaluate in surprising ways; use `===` for strict comparison.
- Loose comparison (`==`) and type juggling have historically produced unexpected results; prefer `===` and explicit casts.
- Array functions vary in argument order (`array_map` versus `array_filter`), a legacy inconsistency to check against the manual.
- Mixing HTML output and logic in one file invites injection bugs; keep templates separate and escape on output.

## Secure coding

PHP powers a large share of public web applications, so these risks are heavily targeted:

- Cross-site scripting: escape all output into HTML with `htmlspecialchars()` or a template engine that autoescapes (Twig, Blade); never echo untrusted input directly. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- SQL injection: use PDO or mysqli prepared statements with bound parameters rather than concatenating variables into SQL, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Code and command injection: never pass untrusted input to `eval()`, `system()`, `exec()`, `shell_exec()`, or backticks; use `escapeshellarg()` and argument arrays, mapping to [CWE-94](https://cwe.mitre.org/data/definitions/94.html) and [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Insecure deserialization: do not call `unserialize()` on untrusted data because it can instantiate arbitrary objects; prefer `json_decode()`. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- File inclusion: never build `include` or `require` paths from user input, which leads to local and remote file inclusion; validate against an allowlist. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Dependency supply chain: pin packages with `composer.lock` and audit them; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [PHPStan](https://phpstan.org/) and [Psalm](https://psalm.dev/) catch type and null errors that lead to vulnerabilities, and `composer audit` checks dependencies against advisory databases. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [PHP Manual](https://www.php.net/manual/en/), the official reference, including the security chapter.
- [PHP: The Right Way](https://phptherightway.com/), a community overview of current practice.
- [PHP-FIG PSR standards](https://www.php-fig.org/psr/), the interoperability recommendations.

## Related pages

- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [JavaScript](/languages/javascript.md)
- [All languages](/languages/README.md)
