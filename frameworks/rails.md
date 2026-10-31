# Ruby on Rails

Ruby on Rails is a server-side web framework written in Ruby. It follows the Model-View-Controller pattern and favors convention over configuration. Teams use it to build database-backed web applications quickly, because sensible defaults remove most wiring decisions. It ships an opinionated full stack: an ORM, a controller layer, a view system, background jobs, and a front-end interaction layer.

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
