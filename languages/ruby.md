# Ruby

Ruby is a dynamically typed, garbage-collected, object-oriented language created by Yukihiro Matsumoto (Matz) and first released in 1995. Everything in Ruby is an object, including integers and `nil`, and the language emphasizes programmer productivity and readable, expressive syntax. It runs on an interpreter (the reference implementation is CRuby, also called MRI) and is used for web back ends, scripting, automation, configuration management, and security tooling.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: object-oriented, imperative, functional |
| Typing | Dynamic, strong, with optional static types via RBS and external checkers |
| First appeared | 1995 |
| Memory model | Automatic: tracing garbage collector (generational, incremental) |
| Reference implementation | [CRuby / MRI](https://github.com/ruby/ruby) |
| Typical uses | Web back ends, scripting, automation, configuration management |
| Governance | Matz as benevolent dictator, with feature discussion on the [Ruby issue tracker](https://bugs.ruby-lang.org/) |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Ruby was designed in Japan by Yukihiro Matsumoto, who blended ideas from Perl, Smalltalk, Eiffel, and Lisp into a language that treats every value as an object and reads close to natural language. It gained a wide audience outside Japan after the release of the [Ruby on Rails](https://rubyonrails.org/) web framework in 2004, which popularized convention over configuration.

The reference interpreter is CRuby (historically called Matz's Ruby Interpreter, or MRI). Since version 1.9 it has run on the YARV bytecode virtual machine, and version 3.0 (2020) added the YJIT just-in-time compiler path later contributed by Shopify. The language has a yearly release near the end of December. Alternative implementations include [JRuby](https://www.jruby.org/) on the JVM and [TruffleRuby](https://github.com/oracle/truffleruby) on GraalVM.

## Paradigm and type system

Ruby is dynamically typed: types are checked at run time and a variable is a reference to an object. Typing is strong, so Ruby does not silently coerce unrelated types. The language is thoroughly object-oriented: methods are dispatched on the receiver, classes are open and can be reopened, and modules provide mixins for shared behavior.

Static typing is optional and lives outside the core language. Type signatures are written in [RBS](https://github.com/ruby/rbs) files, and checkers such as [Sorbet](https://sorbet.org/) and [Steep](https://github.com/soutaro/steep) analyze code against them.

```ruby
# Duck typing: any object that responds to each works here
def total(items)
  items.reduce(0) { |sum, item| sum + item.price }
end
```

## Toolchain and ecosystem

- Interpreter: `ruby` runs scripts; `irb` is the interactive read-eval-print loop.
- Packaging: libraries ship as gems to [RubyGems.org](https://rubygems.org/); `gem` installs them and [Bundler](https://bundler.io/) resolves and locks dependencies through a `Gemfile` and `Gemfile.lock`.
- Version management: [rbenv](https://github.com/rbenv/rbenv) and [RVM](https://rvm.io/) install and switch Ruby versions per project.
- Formatting and linting: [RuboCop](https://rubocop.org/) lints and can autocorrect against a shared style guide; [Standard](https://github.com/standardrb/standard) wraps it with fixed rules.

```bash
gem install bundler
bundle init
bundle add sinatra
```

## Syntax tour

```ruby
# Variables and string interpolation
name = "world"
puts "hello, #{name}"

# Collections
squares = (0...5).map { |n| n * n }        # [0, 1, 4, 9, 16]
lookup  = { a: 1, b: 2 }                    # hash with symbol keys
unique  = [1, 2, 2, 3].uniq                 # [1, 2, 3]

# Methods, default and keyword arguments
def greet(who, excited: false)
  "hi #{who}#{excited ? '.' : '.'}"
end

# Classes and modules
class Point
  attr_reader :x, :y
  def initialize(x, y)
    @x = x
    @y = y
  end
end

# Blocks release resources deterministically
File.open("data.txt", "r") do |fh|
  rows = fh.read.lines
end

# Exceptions
begin
  value = Integer("not a number")
rescue ArgumentError
  value = 0
end
```

## Idioms and different approaches

- Prefer iterator methods (`each`, `map`, `select`, `reduce`) over manual index loops.
- Blocks, procs, and lambdas pass behavior to methods; a block given to `File.open` closes the file when it returns.
- Use symbols (`:name`) for identifiers and hash keys that do not change; they are interned and compared by identity.
- The `&:method` shorthand converts a symbol to a block: `names.map(&:upcase)`.
- Guard clauses and trailing `if`/`unless` keep the common path unindented: `return unless valid?`.

## Design principles

Ruby is built around what Matz calls the principle of least surprise: the language should behave the way an experienced user expects. It optimizes for developer happiness and readability, accepts that there is often more than one way to express a thing, and keeps classes open so behavior can be extended. The flip side, that any code can reopen any class (monkey patching), asks for discipline on larger teams.

## Standard library and notable frameworks

The standard library ships modules for the file system (`File`, `Dir`, `Pathname`), serialization (`JSON`, `CSV`, `YAML`, `Marshal`), networking (`Net::HTTP`, `Socket`), and testing (`minitest`). Widely used gems include [Ruby on Rails](https://rubyonrails.org/) and [Sinatra](https://sinatrarb.com/) for the web, [RSpec](https://rspec.info/) for testing, [Nokogiri](https://nokogiri.org/) for XML and HTML parsing, and [Sidekiq](https://sidekiq.org/) for background jobs.

## Testing and packaging

The standard library provides `minitest`; [RSpec](https://rspec.info/) is a common third-party framework with a descriptive, example-based style.

```ruby
require "minitest/autorun"

class AddTest < Minitest::Test
  def test_add
    assert_equal 5, 2 + 3
  end
end
```

A distributable library declares its metadata in a `.gemspec` file, builds with `gem build`, and publishes with `gem push`. Bundler's `bundle gem` scaffolds a new gem project.

## Performance and concurrency

CRuby runs bytecode on the YARV virtual machine and, like several dynamic interpreters, serializes bytecode execution with a global VM lock (GVL), so native threads do not run Ruby code in parallel. The practical consequences:

- I/O-bound work scales with threads, because a thread releases the GVL while waiting on I/O.
- CPU-bound work scales across processes (for example the `process` module, or forking web servers) rather than threads.
- Ruby 3.0 added Ractor, an actor-style model for parallel execution with isolated object sets, and fibers plus the fiber scheduler support lightweight cooperative concurrency.
- The YJIT just-in-time compiler speeds up CPU-bound code in recent releases.

## Common pitfalls

- `nil` responds to few methods, so `NoMethodError` on `nil` is a common run-time surprise; use the safe navigation operator `&.` or explicit checks.
- Mutable string and array literals are shared when assigned; use `dup` or freeze them with `# frozen_string_literal: true` to avoid accidental mutation.
- Truthiness is simple but strict: only `nil` and `false` are falsy, so `0` and `""` are truthy.
- Reopening core classes (monkey patching) can collide with gems that patch the same method.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Code and command injection: never pass untrusted input to `eval`, `instance_eval`, backticks, `system`, or `%x{}`. Pass an argument array to `system` or `Open3.capture3` instead of a single string. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html) and, for `eval`, [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Insecure deserialization: `Marshal.load` and `YAML.load` on untrusted data can instantiate arbitrary objects. Use `JSON.parse` for untrusted input, or `YAML.safe_load` with a permitted-class allowlist. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized queries and Active Record placeholders rather than string interpolation in query fragments, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html). See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Cross-site scripting: Rails escapes by default in ERB; avoid `raw`, `html_safe`, and string concatenation into markup, which reintroduce [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Dependency supply chain: pin gems with `Gemfile.lock` and scan them; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [Brakeman](https://brakemanscanner.org/) is a static analyzer for Rails applications, [bundler-audit](https://github.com/rubysec/bundler-audit) checks gems against advisory databases, and [RuboCop](https://rubocop.org/) carries a security cop department. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Ruby documentation](https://www.ruby-lang.org/en/documentation/) and the [core API reference](https://docs.ruby-lang.org/en/master/), the primary documentation.
- [Ruby on Rails Guides](https://guides.rubyonrails.org/) for the web framework.
- [Ruby Style Guide](https://rubystyle.guide/), the community conventions that RuboCop encodes.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Perl](/languages/perl.md)
- [All languages](/languages/README.md)
