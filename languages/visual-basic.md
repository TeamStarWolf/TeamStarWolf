# Visual Basic (classic)

Visual Basic (classic) is an event-driven, object-based language and development environment from Microsoft, first released in 1991 and ending with Visual Basic 6.0 in 1998. It combined a BASIC-derived language with a drag-and-drop form designer and the COM component model, and it was widely used to build Windows graphical and business applications through the 1990s and early 2000s. Microsoft ended mainstream support for the VB6 runtime era and moved the line to the .NET-based VB.NET, which is a distinct language.

| Attribute | Value |
|---|---|
| Paradigm | Event-driven, object-based, imperative |
| Typing | Static with a dynamic `Variant` type; weak where `Variant` and implicit conversion are used |
| First appeared | 1991 (classic line ended with VB6 in 1998) |
| Memory model | Automatic via COM reference counting |
| Reference implementation | Microsoft Visual Basic 6.0, the final classic version |
| Typical uses | Windows GUI and business applications, COM automation, rapid application development |
| Governance/standard | Proprietary, Microsoft; no open standard; superseded by VB.NET |

Related: [BASIC](/languages/basic.md), [Delphi (Object Pascal)](/languages/delphi.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Visual Basic brought a visual, form-based model to Windows development: a programmer draws controls on a form and writes code in event handlers such as a button's `Click`. Versions 1 through 6 (1991 to 1998) built on a BASIC-derived language and the Component Object Model (COM), so applications could consume and expose ActiveX components. VB6 became one of the most used tools for Windows business software of its time.

With .NET, Microsoft introduced Visual Basic .NET, a redesigned language on the common language runtime that is source-incompatible with VB6 in many respects; it is covered separately and is not the same as classic VB. Visual Basic for Applications (VBA), the macro language embedded in Microsoft Office, shares the classic VB language core and remains supported in Office. Classic VB6 applications still run on current Windows through the shipped runtime, though the development tool is long out of mainstream support.

## Paradigm and type system

Classic Visual Basic is event-driven and object-based rather than fully object-oriented: it supports classes and interfaces through COM but not implementation inheritance. It is statically typed when variables are declared with explicit types, but the `Variant` type holds any value and drives implicit conversions, which makes parts of a program effectively dynamically typed. `Option Explicit` forces declaration and avoids accidental new variables.

```vb
Option Explicit

Private Sub Command1_Click()
    Dim total As Currency
    total = Val(Text1.Text) * 1.08
    MsgBox "Total with tax: " & total
End Sub
```

## Toolchain and ecosystem

- IDE: the Visual Basic 6.0 IDE hosts the form designer, code editor, and compiler, producing native Windows executables or COM components.
- Components: functionality is extended with ActiveX controls (`.ocx`) and COM libraries registered on the system.
- Data: classic VB uses data access layers such as ADO and DAO to talk to databases.

Modern development on this line is limited to maintaining existing projects; there is no active package manager, and components are distributed as registered COM binaries.

## Syntax tour

```vb
Option Explicit

' A simple class module: Circle.cls
Private mRadius As Double

Public Property Let Radius(value As Double)
    mRadius = value
End Property

Public Function Area() As Double
    Area = 3.14159265 * mRadius * mRadius
End Function

' In a standard module
Public Sub Main()
    Dim c As New Circle
    c.Radius = 2#
    Debug.Print "area: " & c.Area
End Sub
```

## Idioms and different approaches

- Put `Option Explicit` at the top of every module so undeclared names are errors, not silent `Variant` variables.
- Declare specific types (`Long`, `Double`, `Currency`, `String`) instead of relying on `Variant`, which is slower and loosely typed.
- Use `Currency` or scaled integers for money, not `Single` or `Double`.
- Organize reusable logic into class modules and COM components rather than copying code between forms.
- Handle errors with `On Error` and a labeled handler, and clean up object references in the handler.

## Design principles

Visual Basic was designed for fast construction of Windows applications by a broad audience: a visual designer for the interface, event handlers for behavior, and a language that kept BASIC's approachability. The COM component model let developers assemble applications from prebuilt controls. The trade-offs, such as the loosely typed `Variant` and the lack of implementation inheritance, followed from favoring approachability and the component model of its era.

## Standard library and notable packages

Classic VB's capabilities come from its runtime (`msvbvm60.dll`), the Windows API accessed through `Declare` statements, and COM components. Built-in functions cover strings, math, dates, and file I/O; forms and controls provide the user interface. There is no package registry; third-party ActiveX controls and COM libraries, installed and registered on the machine, filled the roles that packages fill in newer languages.

## Testing and packaging

Classic Visual Basic has no built-in unit-test framework; testing was typically manual or through driver programs and, later, third-party add-ins. Applications are packaged as native executables with the VB runtime and any required ActiveX components, historically installed with the Package and Deployment Wizard or a third-party installer that registers the COM dependencies.

## Performance and concurrency

VB6 compiles to native code (or optionally p-code) and performs adequately for typical business and interface work, though numeric and tight-loop code is slower than C or Delphi. Concurrency is not a first-class feature: the model is single-threaded apartment (STA) COM, and most code runs on one UI thread. Background work and true multithreading require careful use of COM threading models or helper components, and are error-prone, so long operations should be designed not to block the interface.

## Common pitfalls

- Overuse of `Variant` and implicit conversions, which hides type errors and slows execution.
- Omitting `Option Explicit`, so a mistyped variable name silently creates a new empty `Variant`.
- Resource and reference leaks: failing to release object references (set to `Nothing`) or to close files in error handlers.
- "DLL hell": COM components registered system-wide create versioning conflicts between applications.
- Using floating-point types for currency, producing rounding errors.

## Secure coding

Classic VB applications run as native Windows programs and often call the Windows API and build SQL, so they carry those risks:

- SQL injection: ADO or DAO queries assembled by concatenating user input are injectable; use parameterized commands, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Buffer handling across API calls: passing fixed-length strings or mis-sized buffers to `Declare`d Windows API functions can overflow memory; size buffers correctly, which relates to [CWE-120](https://cwe.mitre.org/data/definitions/120.html).
- Input validation: data from text boxes, files, and COM callers is unchecked until validated; check type and range, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Unmaintained runtime: the classic VB toolchain no longer receives feature updates, so new platform mitigations are not available to it; plan migration for exposed applications.

Dedicated static analysis for classic VB is scarce. Review API interop, data access, and input handling manually, and isolate internet-facing logic. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) where VB components back a web tier.

## Learning resources

- [Microsoft documentation for Visual Basic 6.0](https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-basic-6/visual-basic-6.0-documentation), the archived official reference.
- [Office VBA language reference](https://learn.microsoft.com/en-us/office/vba/api/overview/language-reference), for the related VBA dialect that shares the classic VB language core.

## Related pages

- [BASIC](/languages/basic.md)
- [Delphi (Object Pascal)](/languages/delphi.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
