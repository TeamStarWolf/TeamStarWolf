# React Native

React Native is an open-source framework from Meta for building native iOS and Android apps with React. The UI is written in `javascript` or `typescript` and renders through real native views, not a web view. It shares the React component model and much of the web ecosystem. Teams use it to reuse React skills and ship one codebase to both mobile platforms.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with React Native, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,263 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a React Native application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[TypeScript](/languages/typescript.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Flutter](/frameworks/flutter.md), [React](/frameworks/react.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

React Native appeared in 2015 and brought the React declarative model to mobile. UI logic runs in `javascript`, while layout maps to native `UIView` and `View` objects. For years a serialized bridge connected the two worlds asynchronously.

The new architecture replaces that bridge with JSI, Fabric, and TurboModules for synchronous, typed access. The JavaScript now runs on Hermes, an engine tuned for mobile startup and memory. Expo, a managed toolchain and library set, is a common way to start and ship apps.

## Architecture

A React Native app is a tree of React components that return native views. Components use hooks such as `useState` and `useEffect` to hold state and run side effects. The reconciler diffs the component tree and updates only the changed native views.

The old bridge passed JSON messages between the JavaScript thread and the native thread asynchronously. The new architecture uses the JavaScript Interface (JSI), a C++ layer that lets JavaScript call native methods directly. Fabric is the new rendering system, and TurboModules are the new native module system with lazy loading.

Hermes parses and runs the JavaScript bundle, producing compact bytecode ahead of time. Native modules expose platform APIs, such as the camera or storage, to the JavaScript layer. Each platform keeps its own UI thread that applies the view updates.

## Navigation, state, and platform integration

Navigation commonly uses React Navigation, which models stacks, tabs, and drawers in `javascript`. The library maps navigation state to native transitions and handles deep links. Expo Router adds file-based routing on top of React Navigation.

State management uses React hooks, Context, and libraries such as Redux Toolkit, Zustand, or Jotai. Server state often uses TanStack Query for caching and refetching. These keep data above the components that read it and trigger re-renders on change.

Platform integration uses native modules written in Kotlin, Swift, or C++. A TurboModule exposes typed methods that JavaScript calls across JSI. Expo modules wrap many native capabilities so apps avoid writing platform code directly.

## A minimal example

```tsx
import React, { useState } from 'react';
import { View, Text, Button } from 'react-native';

export function Counter() {
  const [count, setCount] = useState(0);
  return (
    <View>
      <Text>Count: {count}</Text>
      <Button title="Add" onPress={() => setCount(count + 1)} />
    </View>
  );
}
```

## Ecosystem and tooling

The React Native CLI and the Expo CLI create and build projects. Metro bundles the `javascript` into a single file for each platform. Flipper and the React Native DevTools help inspect components, network calls, and logs.

The npm ecosystem supplies most libraries, with native modules distributed alongside. Expo provides a managed workflow, over-the-air updates, and prebuilt native modules. TypeScript is the common choice for typing props, state, and native interfaces.

## Security relevance

This section is the threat-facing view of React Native: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Mobile apps on iOS and Android. The JavaScript bundle ships inside the app package and can be extracted, so the attack surface is the client itself, the local data it stores, and the network calls it makes. An unpacked APK or IPA is recognizable from `index.android.bundle` or `main.jsbundle`, Hermes bytecode, and the `react-native` directory layout.
- Offensive and audit tooling targets the package: MobSF (Mobile Security Framework) performs static and dynamic analysis of the APK or IPA, apktool unpacks it, and Frida and objection instrument the running app.
- The dependency surface is npm plus the native modules bundled with each package, and every one runs with full app permissions. See [the npm supply chain attacks study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md).

### Dominant weakness classes

The UI runs in JavaScript on the Hermes engine, memory-managed, so the dominant classes are insecure storage, exposed secrets, and injection rather than memory corruption. The fixes for each are in the section below.

- Cleartext storage of sensitive data ([CWE-312](https://cwe.mitre.org/data/definitions/312.html)) when tokens are written to `AsyncStorage` instead of the iOS Keychain or Android Keystore.
- Hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)) embedded in the shipped bundle, which minification and Hermes bytecode slow but do not hide.
- Cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) in a `WebView` that runs remote or user-controlled HTML with script enabled.
- Improper certificate validation ([CWE-295](https://cwe.mitre.org/data/definitions/295.html)) that lets a network attacker intercept traffic when pinning is absent or disabled.

### Why it matters

Recognizing a React Native app, usually by pulling the bundle from the package, tells an auditor where to look: extract and read the bundle for hardcoded secrets, check what lands in `AsyncStorage`, probe `WebView` and deep-link handlers, and intercept traffic to test certificate pinning. MobSF is the audit tool to reach for. See [the mobile security reference](/MOBILE_SECURITY_REFERENCE.md) for the cross-cutting method.

## Security model and common vulnerabilities

The JavaScript bundle ships inside the app and can be extracted and read. Treat it as public, and align controls with the OWASP Mobile Top 10 and MASVS. See /SECURE_CODING_REFERENCE.md for the shared baseline.

`AsyncStorage` is not encrypted and writes plaintext to disk, so it is wrong for tokens or secrets (CWE-312, cleartext storage of sensitive information). Use `react-native-keychain` or an Expo SecureStore binding that stores values in the iOS Keychain and the Android Keystore. Keep only non-sensitive preferences in `AsyncStorage`.

API keys and other secrets embedded in the JS bundle are CWE-798 (use of hard-coded credentials). Minification and Hermes bytecode slow an attacker but do not hide strings, so keep secrets server-side. Fetch short-lived tokens at runtime over an authenticated channel.

Deep-link handlers receive untrusted URLs, so validate the scheme, host, and path before acting. Verify link ownership with Universal Links and Android App Links rather than custom schemes alone. A link that triggers navigation or an action without validation can be abused by any app.

A `WebView` is a frequent source of injection. Treat `injectedJavaScript` and `postMessage` as a trust boundary, and never run remote or user-controlled HTML with script enabled (CWE-79, cross-site scripting). Restrict `originWhitelist`, disable file access where not needed, and sanitize any message payload the native side receives.

Use HTTPS everywhere and pin certificates when needed, rejecting a mismatched certificate or public key (CWE-295, improper certificate validation). Protect over-the-air updates: sign and verify update bundles so an attacker cannot push malicious `javascript` to installed apps. Audit native modules and third-party packages, since each runs with full app permissions.

## Performance

Hermes cuts startup time and memory by shipping bytecode instead of parsing source at launch. The new architecture removes the asynchronous bridge, so native calls and rendering are faster and more predictable. Keep heavy work off the JavaScript thread to avoid dropped frames.

Use `FlatList` with keys and item recycling for long lists instead of mapping over arrays. Memoize components with `React.memo` and stabilize callbacks with `useCallback`. Profile with the DevTools profiler to find re-render storms and slow native calls.

## Common pitfalls

Storing tokens in `AsyncStorage` is the most common storage mistake. Passing new inline objects or functions as props on every render defeats memoization. Blocking the JavaScript thread with large synchronous work freezes the UI.

Loading untrusted content in a permissive `WebView` opens a direct injection path. Forgetting to handle platform differences in permissions or layout causes crashes on one platform only. Leaving unsigned over-the-air updates enabled risks shipping tampered code to users.

## Resources

- The React Native documentation (official).
- The Expo documentation (official).
- The OWASP Mobile Application Security project, including the MASVS and MASTG.

## Related pages

- [TypeScript](/languages/typescript.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Flutter](/frameworks/flutter.md)
- [React](/frameworks/react.md)
- [SwiftUI](/frameworks/swiftui.md)
