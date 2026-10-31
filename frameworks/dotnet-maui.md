# .NET MAUI

.NET MAUI (Multi-platform App UI) is Microsoft's cross-platform framework for building native apps from one `csharp` codebase. It targets iOS, Android, macOS, and Windows from a single project. MAUI is the evolution of Xamarin.Forms, rebuilt on modern .NET. Teams use it to share UI and logic across mobile and desktop while reaching native controls.

## Overview and history

MAUI shipped with .NET 6 in 2022 as the successor to Xamarin.Forms. It uses `csharp` and compiles to native binaries per platform through the .NET runtime. Xamarin's renderers were replaced by a lighter handler architecture.

The framework shares .NET libraries, dependency injection, and tooling with the wider .NET ecosystem. UI is written in XAML or in `csharp`, and Blazor Hybrid lets web UI run inside a native shell. This page covers the mobile storage, transport, and permission concerns.

## Architecture

MAUI uses a single project that holds shared code and per-platform assets and entry points. The app builds from `MauiProgram`, which configures services, fonts, and the dependency injection container. One build produces platform-specific app packages.

UI is typically XAML backed by a code-behind or a view model, following the MVVM pattern. A view binds to a view model that exposes observable properties and commands. The `[ObservableProperty]` and `[RelayCommand]` source generators reduce the boilerplate.

Each cross-platform control maps to a native control through a handler. A handler creates and updates the underlying `UIView`, Android `View`, or Windows control. This keeps rendering native while the shared code stays platform-agnostic.

## Navigation, state, and platform integration

Shell navigation provides a URI-based routing model with a flyout, tabs, and typed routes. `GoToAsync` pushes routes and passes parameters, and routes can map to deep links. A `NavigationPage` stack is also available for simpler flows.

State flows through view models bound to views, with `INotifyPropertyChanged` driving UI updates. Dependency injection supplies services to pages and view models from the configured container. The MVVM Toolkit supplies messaging and observable helpers.

Platform integration uses the `Microsoft.Maui.Essentials` APIs for sensors, storage, and device features. Partial classes and conditional compilation reach platform-specific code when needed. Blazor Hybrid hosts Razor components in a `BlazorWebView` for web-style UI inside the app.

## A minimal example

```xml
<ContentPage xmlns="http://schemas.microsoft.com/dotnet/2021/maui"
             xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
             x:Class="DemoApp.CounterPage">
    <VerticalStackLayout>
        <Label Text="{Binding CountText}" />
        <Button Text="Add" Command="{Binding AddCommand}" />
    </VerticalStackLayout>
</ContentPage>
```

## Ecosystem and tooling

Visual Studio and the `dotnet` command-line tool build, run, and package MAUI apps. NuGet supplies libraries, including the MVVM Toolkit and platform SDK wrappers. Hot Reload updates XAML and `csharp` in a running app during development.

The .NET base class library covers networking, serialization, and storage. .NET Essentials wraps device features behind one API. Visual Studio ships emulators, device deployment, and a profiler.

## Security model and common vulnerabilities

MAUI apps compile `csharp` to assemblies that ship inside the app and can be decompiled. Align controls with the OWASP Mobile Top 10 and MASVS, and see /SECURE_CODING_REFERENCE.md for the shared baseline. Treat the shipped assemblies as readable.

Store secrets and tokens with `SecureStorage`, which uses the iOS Keychain and the Android Keystore. Do not keep sensitive values in `Preferences`, which writes to `UserDefaults` on iOS and `SharedPreferences` on Android in plaintext (CWE-312, cleartext storage of sensitive information). Keep only non-sensitive settings in `Preferences`.

Hardcoded API keys, connection strings, and signing secrets in `csharp` or XAML are CWE-798 (use of hard-coded credentials). IL in shipped assemblies decompiles cleanly, so obfuscation only slows an attacker and does not hide embedded secrets. Move secrets server-side and fetch short-lived tokens at runtime.

Use HTTPS for all traffic and pin certificates when the threat model needs it. Implement pinning with an `HttpClientHandler` (or the platform message handler) that validates the server certificate or public key and rejects a mismatch (CWE-295, improper certificate validation). Do not override `ServerCertificateCustomValidationCallback` to always return `true`.

Request the minimum platform permissions, and check and request them at runtime through Essentials rather than assuming they are granted. A `BlazorWebView` in a Blazor Hybrid app runs web content with a bridge to native code, which is a trust boundary. Serve only trusted local content, avoid loading remote or user-controlled HTML, and validate any data passed across the bridge. Validate incoming deep links and app links, confirming the host and path before acting.

## Performance

AOT and trimming reduce startup time and app size for release builds on mobile. Enable trimming carefully, since reflection-heavy code can break when members are removed. Profile startup to find slow service registration and heavy page initialization.

Use compiled bindings with `x:DataType` so bindings resolve at build time rather than through reflection. Virtualize long lists with `CollectionView` instead of stacking many views. Keep handlers and view models light so navigation stays responsive.

## Common pitfalls

Storing secrets in `Preferences` is a common mistake; use `SecureStorage` instead. Shipping API keys in assemblies exposes them to anyone who decompiles the app. Overriding the certificate validation callback to accept all certificates disables transport security.

Aggressive trimming can strip types that reflection or serialization needs at runtime. Using classic reflection-based bindings instead of compiled bindings slows the UI. Loading untrusted content in a `BlazorWebView` opens an injection path into the native bridge.

## Resources

- The .NET MAUI documentation on Microsoft Learn (official).
- The OWASP .NET Security Cheat Sheet.
- The OWASP Mobile Application Security project, including the MASVS and MASTG.

## Related pages

- /languages/csharp.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /frameworks/flutter.md
- /frameworks/aspnet-core.md
- /frameworks/swiftui.md
