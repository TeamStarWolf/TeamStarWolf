# Objective-C

Objective-C is a general-purpose language that adds Smalltalk-style messaging to C, designed by Brad Cox and Tom Love in the early 1980s and later adopted by NeXT and then Apple. It was the primary language for macOS and iOS development before Swift, and it remains in wide use across Apple's frameworks and existing codebases. It is used for Apple platform applications, framework development, and maintaining code that predates Swift.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented (message passing) layered on procedural C |
| Typing | Static with dynamic dispatch; `id` is a dynamic object type |
| First appeared | 1984 |
| Memory model | Automatic reference counting (ARC); manual retain/release historically |
| Reference implementation | [Clang/LLVM](https://clang.llvm.org/) with Apple's runtime |
| Typical uses | Apple platform apps, framework development, legacy maintenance |
| Governance | Apple, built on the Clang/LLVM compiler |

Related: [Swift](/languages/swift.md), [Clojure](/languages/clojure.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Brad Cox and Tom Love created Objective-C in the early 1980s to add Smalltalk's object messaging to C while keeping full C compatibility. NeXT licensed it for the NeXTSTEP operating system, whose frameworks became the basis of Apple's Cocoa after Apple acquired NeXT in 1996. Objective-C was the main language for Mac and, from 2008, iOS development until Swift arrived in 2014.

The language is a strict superset of C: any C program is valid Objective-C, and the two mix freely within a file. Apple's toolchain compiles it with [Clang](https://clang.llvm.org/) and the LLVM backend, and the Objective-C runtime provides dynamic method dispatch and introspection.

## Paradigm and type system

Objective-C layers object-oriented messaging on C. Method calls are messages sent to objects at run time, written in bracket syntax, and dispatch is dynamic, so the receiver can be determined at run time and messages can be forwarded. Static types annotate pointers to objects (`NSString *`), while `id` is an untyped object pointer that accepts any message. Because C is the substrate, raw pointers, manual memory layout, and C functions are all available.

```objc
NSArray<NSNumber *> *prices = @[@1.5, @2.0, @3.25];
NSNumber *first = prices.firstObject;
NSString *greeting = [NSString stringWithFormat:@"hello, %@", @"world"];
```

Protocols declare a set of methods a class can conform to, and categories add methods to existing classes without subclassing.

## Toolchain and ecosystem

- Compiler: [Clang](https://clang.llvm.org/) compiles Objective-C; Xcode is the standard development environment on Apple platforms.
- Build and dependencies: Xcode projects build applications; [CocoaPods](https://cocoapods.org/) and [Carthage](https://github.com/Carthage/Carthage) manage third-party dependencies, and the Swift Package Manager can include Objective-C targets.
- Analysis: the Clang Static Analyzer, built into Xcode, detects memory and logic errors.

```bash
clang -framework Foundation hello.m -o hello
./hello
```

## Syntax tour

```objc
#import <Foundation/Foundation.h>

// Protocol declaration
@protocol Greeter <NSObject>
- (NSString *)greet:(NSString *)who;
@end

// Class interface
@interface Point : NSObject
@property (nonatomic) NSInteger x;
@property (nonatomic) NSInteger y;
@end

// Class implementation
@implementation Point
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        // String and message send
        NSString *name = @"world";
        NSLog(@"hello, %@", name);

        // Collections (literals)
        NSArray<NSNumber *> *squares = @[@0, @1, @4, @9, @16];
        NSDictionary *lookup = @{@"a": @1, @"b": @2};

        // Enumeration with a block
        [squares enumerateObjectsUsingBlock:^(NSNumber *n, NSUInteger i, BOOL *stop) {
            NSLog(@"%@", n);
        }];

        // Message send with nil-safety: sending to nil returns nil/zero
        Point *p = [[Point alloc] init];
        p.x = 1;
    }
    return 0;
}
```

## Idioms and different approaches

- Follow Cocoa naming conventions: descriptive method names with labeled arguments, such as `writeToFile:atomically:`.
- Sending a message to `nil` is legal and returns zero or nil, which is often used deliberately instead of explicit nil checks.
- Use properties with `@property` and dot syntax rather than hand-written accessors.
- Use blocks (closures) for callbacks and enumeration, and mark captured `self` as `__weak` to avoid retain cycles.
- Extend existing classes with categories, but avoid overriding existing methods through them.

## Design principles

Objective-C's premise is a thin, dynamic object layer over C: keep C's performance and direct hardware access while gaining Smalltalk's late binding and introspection. The dynamic runtime enables patterns such as message forwarding, key-value observing, and method swizzling, which the Cocoa frameworks rely on. The trade-off is that many errors surface at run time rather than compile time, which Swift later aimed to reduce.

## Standard library and notable frameworks

The Foundation framework provides the base object model, collections (`NSArray`, `NSDictionary`, `NSSet`), strings, dates, and networking. On Apple platforms, [AppKit](https://developer.apple.com/documentation/appkit) and [UIKit](https://developer.apple.com/documentation/uikit) build desktop and mobile user interfaces, and Core Data, Core Animation, and Grand Central Dispatch cover persistence, animation, and concurrency. Objective-C code interoperates with Swift through generated interface headers.

## Testing and packaging

[XCTest](https://developer.apple.com/documentation/xctest) is the test framework, run through Xcode or `xcodebuild`.

```objc
#import <XCTest/XCTest.h>

@interface CalculatorTests : XCTestCase
@end

@implementation CalculatorTests
- (void)testAddsTwoNumbers {
    XCTAssertEqual(2 + 3, 5);
}
@end
```

Code packages as frameworks or static libraries and is distributed through CocoaPods, Carthage, or the Swift Package Manager. Applications bundle as `.app` packages for distribution through the App Store.

## Performance and concurrency

Objective-C compiles to native code and performs close to C for straight-line code; message dispatch adds a small runtime cost compared with a direct C function call, which the runtime caches. Memory is managed by automatic reference counting, so objects free deterministically and reference cycles must be broken with `weak` references. Concurrency uses:

- Grand Central Dispatch (`dispatch_async`, queues) to schedule work across cores.
- `NSOperation` and `NSOperationQueue` for dependency-aware task graphs.
- Shared mutable state across queues needs synchronization; serial queues are a common way to confine access.

## Common pitfalls

- Retain cycles between objects, and blocks that strongly capture `self`, leak memory; break them with `__weak` references.
- Sending a message to a deallocated object (in manual memory code) crashes; automatic reference counting reduces but does not eliminate pointer errors in C interop.
- Because sending to `nil` is silent, a nil receiver can mask a logic error rather than raising one.
- Method swizzling and category method collisions produce behavior that is hard to trace; use them sparingly.
- Format-string mismatches in `NSLog` and `stringWithFormat:` cause crashes or disclosure; keep format specifiers and arguments aligned.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Memory safety: because Objective-C includes C, buffer overflows and use-after-free in C portions are possible, mapping to [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and [CWE-416](https://cwe.mitre.org/data/definitions/416.html); prefer Foundation collections over raw buffers and enable the sanitizers.
- Format-string injection: never pass user input as the format argument to `NSLog` or `stringWithFormat:`; use a constant format with `%@` placeholders, which addresses [CWE-134](https://cwe.mitre.org/data/definitions/134.html).
- SQL injection: use parameterized SQLite statements with bound values rather than building query strings, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Insecure data storage: store secrets in the Keychain rather than `NSUserDefaults` or plain files, addressing [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Dependency supply chain: review and pin CocoaPods and Carthage dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the [Clang Static Analyzer](https://clang-analyzer.llvm.org/) in Xcode detects memory and logic flaws, and the address and thread sanitizers catch runtime memory and race errors. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Programming with Objective-C](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/Introduction/Introduction.html), Apple's language guide.
- [Apple Developer documentation](https://developer.apple.com/documentation/) for Foundation and the platform frameworks.
- [Clang documentation](https://clang.llvm.org/docs/) for compiler behavior and language extensions.

## Related pages

- [Swift](/languages/swift.md)
- [Clojure](/languages/clojure.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
