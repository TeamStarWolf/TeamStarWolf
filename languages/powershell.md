# PowerShell

PowerShell is a command-line shell and scripting language from Microsoft, first released in 2006 as Windows PowerShell and built on the .NET runtime. Unlike Unix shells that pass text between programs, PowerShell pipelines pass .NET objects, so commands consume and produce structured data rather than lines to be re-parsed. Since the open-source PowerShell (version 6, 2018), it runs cross-platform on Windows, Linux, and macOS, and it is used for system administration, automation, and configuration management.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, object-oriented pipeline scripting |
| Typing | Dynamic by default, with optional .NET type constraints |
| First appeared | 2006 (Windows PowerShell); 2018 (cross-platform PowerShell) |
| Memory model | Managed by the .NET runtime: garbage-collected objects |
| Reference implementation | [PowerShell](https://github.com/PowerShell/PowerShell) |
| Typical uses | Windows and cross-platform administration, automation, CI, cloud tooling |
| Governance | Microsoft, developed in the open on GitHub |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Windows Batch (cmd)](/languages/batch.md), [Bash](/languages/bash.md), [languages index](/languages/README.md).

## Overview and history

PowerShell grew out of a Microsoft design effort (the "Monad Manifesto", 2002) to give Windows a scripting environment on par with Unix shells, but based on objects instead of text. Windows PowerShell shipped in 2006 and became a standard part of Windows. In 2016 Microsoft open-sourced the project and rebuilt it on .NET Core, releasing the cross-platform PowerShell 6 in 2018; the current line continues as PowerShell 7.

Two distinct products share the name: Windows PowerShell 5.1, which ships with Windows and uses the older .NET Framework, and PowerShell 7, which is cross-platform and based on modern .NET. They differ in available modules and some behaviors, so scripts sometimes target one specifically.

## Paradigm and type system

PowerShell is dynamically typed, but every value is a .NET object, so a variable can carry the full type information and methods of its class. You can constrain a variable or parameter to a .NET type, which adds checking and coercion.

```powershell
[int] $count = 3            # typed variable
$total = $count * 2         # 6, as an Int32
$items = Get-ChildItem      # a collection of FileInfo objects
$items[0].Length            # call a .NET property, not parse text
```

Because the pipeline carries objects, a command like `Get-Process | Where-Object CPU -gt 100 | Sort-Object CPU` filters and sorts on real properties rather than column positions in text output.

## Toolchain and ecosystem

- Shell: `pwsh` is the cross-platform executable; `powershell.exe` is Windows PowerShell 5.1.
- Packaging: modules publish to the [PowerShell Gallery](https://www.powershellgallery.com/) and install with `Install-Module`; `Install-PSResource` is the newer client.
- Editing: the [PowerShell extension for VS Code](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell) provides editing, debugging, and the integrated console.
- Linting: [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) is the static analyzer and style checker, and it also formats code.

```powershell
Install-Module -Name Pester -Scope CurrentUser
Invoke-ScriptAnalyzer -Path ./deploy.ps1
```

## Syntax tour

```powershell
#requires -Version 7.0
Set-StrictMode -Version Latest      # treat unset variables as errors

$name = "world"
Write-Output "hello, $name"

# Pipeline of objects, filtered on real properties
Get-ChildItem -File |
    Where-Object Length -gt 1kb |
    Sort-Object Length -Descending |
    Select-Object -First 3 Name, Length

# Collections and loops
$fruits = 'apple', 'banana', 'cherry'
foreach ($fruit in $fruits) {
    Write-Output "fruit: $fruit"
}

# Functions with typed parameters
function Get-Greeting {
    param([Parameter(Mandatory)] [string] $Who)
    "hi $Who"
}
Get-Greeting -Who team

# Error handling
try {
    $value = [int]'not a number'
} catch [System.FormatException] {
    $value = 0
}
```

## Idioms and different approaches

- Name functions `Verb-Noun` using approved verbs (`Get-`, `Set-`, `New-`, `Remove-`); `Get-Verb` lists them, and PSScriptAnalyzer flags unapproved verbs.
- Pass objects down the pipeline and filter on properties rather than parsing text; reach for `Select-Object`, `Where-Object`, and `ForEach-Object`.
- Turn on `Set-StrictMode -Version Latest` so that referencing an unset variable or a missing property raises an error instead of returning `$null`.
- Prefer cmdlet parameters over string parsing; most cmdlets accept pipeline input and return rich objects.
- Use `[CmdletBinding()]` and `param()` blocks to get common parameters such as `-Verbose` and `-WhatIf` for free.

## Design principles

PowerShell's defining choice is an object pipeline: because commands exchange typed objects, downstream commands do not re-parse text, which removes a whole category of fragile string handling. The command model is consistent (`Verb-Noun` with a shared parameter vocabulary), and discoverability is built in through `Get-Command`, `Get-Help`, and `Get-Member`. The design assumes an administrative context, so features such as `-WhatIf`, `-Confirm`, and remoting are part of the core rather than add-ons.

## Standard library and notable modules

The .NET base class library is available directly, so scripts can call into collections, networking, cryptography, and I/O without a wrapper. Built-in modules cover the file system, the registry and services on Windows, process and job management, and data formats through `ConvertTo-Json`, `ConvertFrom-Json`, `Import-Csv`, and `Export-Csv`. The [PowerShell Gallery](https://www.powershellgallery.com/) hosts modules such as [Pester](https://pester.dev/) for testing, [Az](https://learn.microsoft.com/powershell/azure/) for Azure, and the [AWS Tools for PowerShell](https://aws.amazon.com/powershell/).

## Testing and packaging

[Pester](https://pester.dev/) is the standard test framework and ships a behavior-style syntax.

```powershell
function Add-Numbers { param($a, $b) $a + $b }

Describe 'Add-Numbers' {
    It 'adds two numbers' {
        Add-Numbers 2 3 | Should -Be 5
    }
}
```

A reusable unit is a module: a `.psm1` file with a `.psd1` manifest that declares version and exported functions, published to the Gallery with `Publish-Module`.

## Performance and concurrency

Object construction and .NET interop make PowerShell slower than a native binary for tight numeric loops; when performance matters, move hot work into a .NET method call or a compiled assembly. Avoid growing arrays in a loop with `+=`, which copies each time; collect into a `[System.Collections.Generic.List[object]]` or let the pipeline stream.

For concurrency, PowerShell 7 offers `ForEach-Object -Parallel`, which runs script blocks on runspace threads, and background jobs (`Start-Job`, process-isolated) and thread jobs (`Start-ThreadJob`). Runspaces give finer control for pooling. State is not shared implicitly between parallel runspaces, so pass inputs in and collect outputs rather than relying on shared variables.

## Common pitfalls

- Without `Set-StrictMode`, a misspelled variable is `$null` rather than an error, so bugs pass silently.
- A function that writes intermediate values to the pipeline returns them all; unintended output pollutes the result, so suppress it with `[void]` or `$null =`.
- A single returned object and a collection are easy to confuse; wrap with `@( ... )` when you need an array regardless of count.
- Comparison operators are words (`-eq`, `-lt`, `-match`), and `-eq` against an array filters it rather than returning a boolean; know which side is the collection.
- Windows PowerShell 5.1 and PowerShell 7 differ in modules and behavior; test on the version you target.

## Secure coding

PowerShell runs with real privileges and can reach the whole .NET surface, so injection and execution control are central:

- Code injection through `Invoke-Expression`: passing assembled or untrusted strings to `Invoke-Expression` (`iex`) executes them as code. Avoid it; call commands with parameters or splatting instead. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Operating-system command injection: when invoking external programs, pass arguments as separate array elements rather than building one string, so that spaces and metacharacters are not reinterpreted. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Execution policy is not a security boundary: `Set-ExecutionPolicy` controls convenience, not trust, and is easily bypassed. Use code signing (`Set-AuthenticodeSignature`) and application control (such as Windows Defender Application Control) for real enforcement.
- Credential and secret handling: use `[SecureString]` and the [SecretManagement](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview) module rather than plaintext in scripts, to avoid [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
- Module supply chain: install from trusted repositories, pin versions, and review scripts pulled from the internet before running; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) includes rules that flag `Invoke-Expression`, plaintext credentials, and other risky constructs, and should run in continuous integration.

## Learning resources

- [PowerShell documentation](https://learn.microsoft.com/powershell/), the official reference and guides.
- about_ topics, the built-in conceptual help available through `Get-Help about_*`.
- [PowerShell Gallery](https://www.powershellgallery.com/), the module repository.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Windows Batch (cmd)](/languages/batch.md)
- [Bash](/languages/bash.md)
- [All languages](/languages/README.md)
