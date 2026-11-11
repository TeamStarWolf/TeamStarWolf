# Ruby on Rails

Ruby on Rails is a server-side web framework written in Ruby. It follows the Model-View-Controller pattern and favors convention over configuration. Teams use it to build database-backed web applications quickly, because sensible defaults remove most wiring decisions. It ships an opinionated full stack: an ORM, a controller layer, a view system, background jobs, and a front-end interaction layer.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Ruby on Rails, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,408 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Ruby on Rails application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ruby](/languages/ruby.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

David Heinemeier Hansson extracted Rails from the Basecamp application and released it in 2004. It popularized convention over configuration and the idea that a small team could ship a complete application fast. The framework reached 1.0 in 2005 and has shipped major versions steadily since.

Rails sets defaults for file layout, naming, and database mapping. A class named `User` maps to a `users` table without any declaration. This reduces boilerplate and makes most Rails codebases look familiar to any Rails developer.

The project values developer happiness and integrated tooling. It bundles testing, migrations, asset handling, and a console. Recent versions emphasize Hotwire for front-end interactivity without a separate JavaScript framework.

## Architecture

A request enters through Rack, the Ruby web server interface. The router matches the URL and HTTP method to a controller action. Middleware runs in order before the controller, handling sessions, cookies, parameter parsing, and CSRF checks. The controller action is the unit of request handling.

The controller loads or changes data through models, then selects a response. Most actions render a view template or return JSON. Action Controller provides the request and response objects, filters, and parameter access. Before and after filters let you run shared logic such as authentication.

Models usually inherit from `ActiveRecord::Base` and represent rows in the database. Active Record maps tables to classes and columns to attributes. It also holds validations, associations, and callbacks. Business rules often live here, which keeps controllers thin.

Views use Action View with ERB templates by default. Templates combine HTML with embedded Ruby and render partials for reuse. Rails wires these layers together by naming convention, so a `show` action looks for a `show.html.erb` template automatically.

## Routing, data, and key subsystems

Routes are declared in `config/routes.rb`. The `resources` helper generates the standard REST routes for a model in one line. Routes map to `controller#action` pairs and can be named for use in URL helpers.

Active Record is the ORM. It builds queries through a chainable API, so `User.where(active: true).order(:name)` produces parameterized SQL. Migrations are versioned Ruby files that evolve the schema over time. The schema file records the current database structure for new checkouts.

Action View handles templating, layouts, and partials. Helpers escape output and build forms, links, and tags. Action Mailer sends email with the same template model. Active Job provides a queue abstraction with adapters for Sidekiq, Resque, and others, so background work does not block requests.

Hotwire is the default front-end approach. Turbo sends HTML over the wire and updates page fragments without full reloads. Stimulus attaches small JavaScript behaviors to markup. Together they reduce the need for a separate single-page application.

## A minimal example

```ruby
# config/routes.rb
Rails.application.routes.draw do
  resources :articles, only: [:index, :show]
end

# app/controllers/articles_controller.rb
class ArticlesController < ApplicationController
  def index
    @articles = Article.where(published: true).order(created_at: :desc)
  end

  def show
    @article = Article.find(params[:id])
  end
end
```

## Ecosystem and tooling

RubyGems distributes libraries, and Bundler pins versions through a `Gemfile` and `Gemfile.lock`. Rake and the `rails` command run tasks such as migrations, the console, and the server. The generators scaffold models, controllers, and tests.

Testing is built in with Minitest, and RSpec is a widely used alternative. Devise handles authentication, Pundit and CanCanCan handle authorization, and Sidekiq runs background jobs. Brakeman is a static analysis scanner written specifically for Rails security issues.

## Security relevance

This section is the threat-facing view of Rails: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing web applications and JSON APIs. Rails is often recognizable from the outside by its conventions: default RESTful route shapes, a `_session_id` cookie, an `X-Runtime` header, 422 responses on a missing CSRF token, and fingerprinted asset paths.
- Audit and defensive tooling is written specifically for it. Brakeman is the static analysis scanner built for Rails, and bundler-audit checks the gem dependency tree against the ruby-advisory-db.
- Offensive interest centers on the signing secret. The `secret_key_base` signs cookies and sessions, so a leaked value lets an attacker forge signed data and, combined with an unsafe deserialization sink, reach code execution.
- The dependency surface is the RubyGems ecosystem, pinned through `Gemfile.lock`. A compromised or typosquatted gem runs with full application privilege, the same pattern covered in [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Rails runs on Ruby, a memory-managed language, so the dominant classes are logic and injection flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Insecure deserialization (CWE-502) is the highest-severity historical class, since a crafted object graph reaching `Marshal.load` or an unsafe `YAML.load` can execute code. See [Ruby](/languages/ruby.md) for the language-level sinks.
- Mass assignment ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)). The 2012 GitHub incident, where an attacker set a protected attribute through form data, is the canonical public example.
- SQL and code injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html)) through query methods or view paths that accept raw strings.
- Exposure of the signing secret ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)) committed to source control, which undermines every signed cookie and token at once.

### Why it matters

Convention over configuration cuts both ways: it lets an auditor trace the whole request path from `config/routes.rb` through the controllers and Active Record quickly, because the layout is predictable. Recognizing Rails in the field tells a tester which injection classes and which signing-secret pivots to try first. Brakeman is the framework-specific static analyzer to reach for, and bundler-audit covers the dependency side. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Rails ships several protections on by default, but misuse reopens classic flaws. See `/SECURE_CODING_REFERENCE.md`, `/WEB_APPLICATION_SECURITY_REFERENCE.md`, and `/API_SECURITY_REFERENCE.md` for cross-cutting guidance.

Strong parameters guard against mass assignment (CWE-915). Controllers must call `params.require(:model).permit(:field)` to allow specific attributes. Early Rails versions allowed mass assignment by default, which let attackers set fields like `admin` through form data. Permitting whole hashes or using `permit!` brings that risk back.

SQL injection (CWE-89) appears when strings are interpolated into query methods. Writing `User.where("name = '#{input}'")` is unsafe. The fixed form is `User.where("name = ?", input)` or `User.where(name: input)`, which parameterize the value. The Rails SQL Injection Guide lists the methods that accept raw SQL.

CSRF protection (CWE-352) is enabled through `protect_from_forgery` and an authenticity token embedded in forms. Disabling it, or switching to a null session for HTML endpoints, exposes state-changing actions. API-only controllers should use token or header authentication instead of cookie sessions.

Cross-site scripting (CWE-79) is mitigated because ERB escapes output by default. Calling `html_safe` or `raw` on user input disables escaping and injects unescaped markup. Only mark trusted, already-sanitized strings as safe. The `sanitize` helper allows a controlled subset of HTML.

Unsafe deserialization (CWE-502) is the most severe historical class. CVE-2013-0156 let attackers send crafted XML or YAML that Rails deserialized into arbitrary Ruby objects, leading to remote code execution. Never pass untrusted data to `YAML.load` or `Marshal.load`; use `YAML.safe_load` with an allowed-class list. The `secret_key_base` signs cookies and sessions, so leaking it lets an attacker forge signed data.

## Performance and scaling

Rails runs well behind Puma with multiple workers and threads. The N+1 query problem is the most common performance trap; use `includes` to eager-load associations. Fragment and Russian-doll caching reduce view rendering cost, backed by Redis or Memcached.

Horizontal scaling adds application servers behind a load balancer, with the database as the shared state. Read replicas and connection pooling relieve database pressure. Move slow work, such as email and image processing, into Active Job queues.

## Common pitfalls

Fat controllers and god models accumulate logic that belongs in service objects or concerns. Callbacks that trigger side effects make tests and reasoning harder. Overuse of `default_scope` surprises later queries.

Forgetting database indexes on foreign keys and lookup columns slows queries as data grows. Permitting too many parameters, or disabling CSRF for convenience, reintroduces known vulnerabilities. Leaking `secret_key_base` through committed credentials undermines every signed token.

## Resources

- Ruby on Rails Guides, the official documentation
- Ruby on Rails Security Guide, the official security chapter
- *Agile Web Development with Rails* by Sam Ruby and others
- OWASP Cheat Sheet Series
- OWASP Top 10

## Related pages

- [Ruby](/languages/ruby.md)
- [Frameworks index](/frameworks/README.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API security reference](/API_SECURITY_REFERENCE.md)
- [Django](/frameworks/django.md)
- [Laravel](/frameworks/laravel.md)
- [Phoenix](/frameworks/phoenix.md)
