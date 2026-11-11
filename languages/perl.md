# Perl

Perl is a dynamically typed, garbage-collected, multi-paradigm language created by Larry Wall and first released in 1987. It was built for text processing and system administration, and it is known for its regular-expression support, sigil-prefixed variables, and a culture that accepts many ways to express the same thing. It runs on an interpreter (the reference implementation is simply called perl) and is used for text munging, report generation, system administration, bioinformatics, and legacy web back ends.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, procedural, object-oriented, functional |
| Typing | Dynamic, weak-ish with context-sensitive coercion |
| First appeared | 1987 |
| Memory model | Automatic: reference counting |
| Reference implementation | [perl](https://github.com/Perl/perl5) |
| Typical uses | Text processing, system administration, bioinformatics, reporting |
| Governance | Perl Steering Council under the [Perl core team](https://www.perl.org/) |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Raku](/languages/raku.md), [languages index](/languages/README.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain Perl code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,376 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing Perl code (typical uses: text processing, system administration, bioinformatics, reporting), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Raku](/languages/raku.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Perl was written by Larry Wall, a linguist by training, to fill a gap between shell scripting and C for text-processing tasks. The name is commonly expanded as Practical Extraction and Report Language. Perl 5, released in 1994, added references, modules, and object orientation and remains the line in active use. The [CPAN module archive](https://www.cpan.org/), established in 1995, became one of the earliest large open-source module repositories.

A separate language once called Perl 6 was renamed [Raku](/languages/raku.md) in 2019 and is now its own project. The reference interpreter for Perl 5 is the `perl` binary, which compiles source to an internal syntax tree and then runs it.

## Paradigm and type system

Perl is dynamically typed with three core variable kinds marked by sigils: scalars (`$x`), arrays (`@x`), and hashes (`%x`). It is weakly typed in the sense that it coerces between strings and numbers freely, and the result depends on context: an expression in list context and scalar context can evaluate differently. Object orientation is built on references, packages as classes, and the `bless` operator; modern code often uses [Moose](https://metacpan.org/pod/Moose) or the built-in `class` feature added in recent releases.

```perl
my @prices = (10, 20, 30);
my $total  = 0;
$total += $_ for @prices;   # 60
```

## Toolchain and ecosystem

- Interpreter: `perl` runs scripts; `perl -de 1` starts the interactive debugger.
- Packaging: modules publish to [CPAN](https://www.cpan.org/); `cpan` and the newer [cpanm](https://metacpan.org/pod/App::cpanminus) install them. [Carton](https://metacpan.org/pod/Carton) locks dependencies per project.
- Version management: [perlbrew](https://perlbrew.pl/) and [plenv](https://github.com/tokuhirom/plenv) install and switch interpreters.
- Linting: [Perl::Critic](https://metacpan.org/pod/Perl::Critic) checks code against the guidelines in Damian Conway's *Perl Best Practices*; [perltidy](https://metacpan.org/pod/Perl::Tidy) reformats.

```bash
cpanm Mojolicious
perl -c script.pl   # compile-check without running
```

## Syntax tour

```perl
use strict;
use warnings;

# Variables with sigils
my $name = "world";
print "hello, $name\n";

# Arrays and hashes
my @squares = map { $_ * $_ } (0 .. 4);   # (0, 1, 4, 9, 16)
my %lookup  = (a => 1, b => 2);

# Subroutines
sub greet {
    my ($who, %opts) = @_;
    my $end = $opts{excited} ? "." : ".";
    return "hi $who$end";
}

# Regular expressions, a core strength
my $text = "order 42 shipped";
if ($text =~ /order (\d+)/) {
    my $id = $1;
}

# File handling with lexical filehandle
open(my $fh, "<", "data.txt") or die "cannot open: $!";
my @rows = <$fh>;
close($fh);
```

## Idioms and different approaches

- Always begin with `use strict;` and `use warnings;`; they turn silent mistakes into reported errors.
- The default variable `$_` and the `@_` argument array keep short loops and subroutines terse.
- Context matters: `my $count = @array` gives the length, while `my @copy = @array` copies elements.
- Use `map`, `grep`, and `sort` with blocks for list transformations.
- The slogan "there is more than one way to do it" (TMTOWTDI) is cultural; teams usually settle on a subset and enforce it with Perl::Critic.

## Design principles

Perl's design borrows from natural language: common things should be short, and the language should not force one style on everyone. Larry Wall framed the three chief virtues of a programmer as laziness, impatience, and hubris, meaning automation of toil, responsiveness, and pride in maintainable work. The trade-off is that unconstrained code can be hard to read, so disciplined projects adopt `use strict`, a style guide, and linting.

## Standard library and notable packages

The core distribution ships modules for the file system (`File::Spec`, `File::Find`), data handling (`Data::Dumper`, `Storable`), and testing (`Test::More`). Widely used CPAN distributions include [Mojolicious](https://mojolicious.org/) and [Dancer2](https://metacpan.org/pod/Dancer2) for the web, [DBI](https://metacpan.org/pod/DBI) for database access, [Moose](https://metacpan.org/pod/Moose) for object orientation, and [BioPerl](https://bioperl.org/) for bioinformatics.

## Testing and packaging

The core `Test::More` module and the TAP (Test Anything Protocol) output format drive most Perl testing; `prove` runs test files.

```perl
use Test::More tests => 1;
is(2 + 3, 5, "addition works");
```

A distributable module uses `ExtUtils::MakeMaker` (a `Makefile.PL`) or [Dist::Zilla](https://metacpan.org/pod/Dist::Zilla) to build and package, then uploads to CPAN through [PAUSE](https://pause.perl.org/).

## Performance and concurrency

The `perl` interpreter compiles source to an internal tree and walks it; it is fast at text processing and regular expressions but slower than compiled languages on numeric loops. Concurrency options:

- `fork` creates separate processes on Unix-like systems and is the common model for parallel work.
- Interpreter threads (`use threads`) exist but copy interpreter state per thread and are generally discouraged for new code.
- Event-driven I/O through frameworks such as Mojolicious and [AnyEvent](https://metacpan.org/pod/AnyEvent) handles many concurrent connections in one process.

For hot numeric code, the `Inline::C` module or an XS extension drops down to C.

## Common pitfalls

- Omitting `use strict;` lets a typo in a variable name create a new global silently; always enable it.
- List versus scalar context can surprise: a function called where a scalar is expected may return a count rather than a list.
- Numeric comparison uses `==` and `<`, while string comparison uses `eq` and `lt`; mixing them compares the wrong way.
- Regular expressions are easy to write and easy to make slow; watch for catastrophic backtracking on untrusted input.

## Security relevance

Perl reaches security practitioners as a language of system administration and glue code, as the implementation language of some long-running security tools, and as the back end of legacy web applications. Its strength at text processing put it into many older scanners and automation scripts, and its CGI heritage left web code that is still assessed today. The defensive patterns that counter each weakness are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Security and administration tooling. The [Nikto](https://github.com/sullo/nikto) web-server scanner is written in Perl, and much system-administration automation and log processing is Perl, so reading a tool or script often means reading Perl. See the [Penetration Testing Methodology](/PENETRATION_TESTING_METHODOLOGY.md).
- Legacy web back ends. Older CGI and `mod_perl` applications remain in service and are frequent assessment targets. See the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Text and data processing. Report generation, bioinformatics pipelines, and one-off data munging keep Perl in paths that handle untrusted input.

### Dominant weakness classes

Perl is memory-safe: it is garbage-collected through reference counting, so memory-corruption classes do not apply. The weaknesses are about injection, deserialization, and resource use.

- Command and code injection. `eval` on untrusted strings, backticks, a single-string `system`, and a piped `open` reach the shell or interpreter, which are [CWE-78](https://cwe.mitre.org/data/definitions/78.html) and [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Insecure deserialization. `Storable::thaw` on untrusted data, and `eval` of serialized structures, can reconstruct arbitrary state, which is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection. Interpolating variables into SQL instead of using `DBI` placeholders is [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Regular-expression denial of service. A pattern that backtracks catastrophically on crafted input can consume unbounded CPU, which is [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Dependency supply chain. CPAN modules run with the program's privileges, so unpinned or unreviewed distributions are a risk. See the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Why it matters

Reading Perl lets an analyst understand what a tool such as Nikto actually sends, audit administration scripts for shell and SQL injection, and find unsafe deserialization in long-lived services. [Perl::Critic](https://metacpan.org/pod/Perl::Critic) flags unsafe constructs through policy modules, and taint mode (`perl -T`) refuses to use untrusted data in system-affecting operations until it is explicitly cleared, as the Secure coding section details.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Code and command injection: avoid `eval EXPR` on untrusted strings and never pass user input to the shell via backticks, `system("...")` as a single string, or a piped `open`. Use the list form `system(@args)` and `open(my $fh, "-|", @args)`, which bypass the shell. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html) and [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Taint mode: run with `perl -T` on programs that handle untrusted input; Perl then refuses to use tainted data in operations that affect the system until you explicitly untaint it.
- Insecure deserialization: `Storable::thaw` on untrusted data and `eval` of serialized structures are unsafe; prefer `JSON::PP` for untrusted input. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use `DBI` placeholders and bind values instead of interpolating variables into SQL, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html). See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Dependency supply chain: pin CPAN modules with Carton and review them; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [Perl::Critic](https://metacpan.org/pod/Perl::Critic) flags unsafe constructs through policy modules, and [cpan-audit](https://metacpan.org/pod/App::cpanminus::reporter) style advisory checks compare dependencies against known issues. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [perldoc](https://perldoc.perl.org/), the official documentation, including the `perlintro` and `perlsec` pages.
- [MetaCPAN](https://metacpan.org/), the searchable CPAN module index.
- [Modern Perl](http://modernperlbooks.com/books/modern_perl_2016/) by chromatic, a freely available introduction to current practice.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Raku](/languages/raku.md)
- [Ruby](/languages/ruby.md)
- [All languages](/languages/README.md)
