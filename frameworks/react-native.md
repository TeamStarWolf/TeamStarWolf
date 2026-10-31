# React Native

React Native is an open-source framework from Meta for building native iOS and Android apps with React. The UI is written in `javascript` or `typescript` and renders through real native views, not a web view. It shares the React component model and much of the web ecosystem. Teams use it to reuse React skills and ship one codebase to both mobile platforms.

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

- /languages/typescript.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /frameworks/flutter.md
- /frameworks/react.md
- /frameworks/swiftui.md
