# Modern C++ Features and Google-Specific Magic

Scope: The "Other C++ Features" and "Google-Specific Magic" sections of the Google C++ Style
Guide: ownership and smart pointers, rvalue references, friends, exceptions, noexcept, RTTI,
casting, streams, preincrement, const, constexpr/constinit/consteval, integer types, floating-point
types, architecture portability, preprocessor macros, 0 and nullptr/NULL, sizeof, type deduction,
CTAD, designated initializers, lambdas, template metaprogramming, concepts, C++20 modules,
coroutines, disallowed library features, third-party libraries, nonstandard extensions, aliases,
switch statements, and cpplint.

## Ownership and Smart Pointers
<!-- tier: portable -->
Give every dynamically allocated object a single, fixed owner, and transfer ownership with
smart pointers.
- Keep ownership with the allocating code; give other code a copy or non-owning pointer.
- Use `std::unique_ptr` for exclusive ownership. Never copy it; move it to transfer ownership.
- Avoid shared ownership without a very good reason: expensive copies of an immutable object.
- Prefer `std::shared_ptr` only when sharing is genuinely required.
- Never use `std::auto_ptr`. Prefer smart pointers over raw `new`/`delete`; the owner deletes.
```cpp
std::unique_ptr<Foo> FooFactory();
void FooConsumer(std::unique_ptr<Foo> ptr);
```

## Rvalue References
<!-- tier: portable -->
Use rvalue references only for move constructors and move assignment operators; for `&&`-qualified
methods that consume `*this`; in forwarding references with `std::forward`; and in overload pairs.
```cpp
// Good: a move constructor.
Foo(Foo&& other) : data_(std::move(other.data_)) {}

// Bad: && on an ordinary parameter that is not consumed.
void Process(Foo&& f);
```
The `&&` qualifier exception applies only to method qualifiers; to consume an ordinary parameter,
pass it by value. Write performance-motivated complexity only with evidence that it helps.

## Friends
<!-- tier: portable -->
Allow friend classes and functions, within reason.
- Define friends in the file of the class granting friendship, so readers need not search.
- Prefer public members. Friendship extends the encapsulation boundary instead of breaking it.
- Typical uses: a builder class constructing inner state, and a unit test class friended with it.

## Exceptions
<!-- tier: google-internal -->
Google does not use C++ exceptions. This is a Google-internal policy, not a universal C++ rule.
Pros: higher levels of an application can decide how to handle "can't happen" failures in deeply
nested functions without error-code bookkeeping; exceptions match other modern languages; some
third-party libraries use them; they are the only way for a constructor to fail; they are handy in
testing frameworks.
Cons: adding a `throw` forces examination of all transitive callers, which must either provide the
basic exception safety guarantee or accept termination; control flow becomes hard to evaluate;
exception safety requires RAII plus a commit phase isolating writes to persistent state; exceptions
add data to every binary; they encourage throwing on bad input and recovering unsafely.
- Do not use C++ exceptions in Google C++ code, nor introduce them into exception-free code.
- Where allowed, give callers the basic exception safety guarantee, isolate writes to persistent
  state into a commit phase, and rely on RAII.
- The guide's decision is practical rather than moral, and it still advises against exceptions in
  Google open-source projects, since they integrate poorly with exception-free code. Its claim that
  the benefits outweigh the costs in new projects is not reconciled with the prohibition; apply it.

### Exception carve-out for Windows
<!-- tier: platform-specific -->
Windows code is exempt from the prohibition on exceptions. Keep the exemption scoped to Windows
targets.

## noexcept
<!-- tier: portable -->
Specify `noexcept` when it is useful and correct.
- Use it when it reflects intent: an escaping exception is fatal and calls `std::terminate`, so a
  destructor must not throw.
- Assume `noexcept` on move constructors has a real benefit: `std::vector<T>::resize()` then moves.
- Prefer interface simplicity to complicated clauses: document that the component does not support
  throwing hash functions and make the function `noexcept`.
- `noexcept` is hard to undo: it removes a guarantee callers may rely on, and is hard to verify.

### Google-specific noexcept practice
<!-- tier: google-internal -->
- Prefer unconditional `noexcept` when exceptions are disabled, the case in most Google C++ code.
- Otherwise use conditional `noexcept` with simple conditions false only where the function could
  throw: `std::is_nothrow_move_constructible`, `absl::default_allocator_is_nothrow`.
- Treat allocation failure as a fatal error; move constructors should not throw for other reasons.
- Discuss any other significant `noexcept` performance benefit with the project leads.

## Run-Time Type Information (RTTI)
<!-- tier: portable -->
Avoid run-time type information, that is `typeid` and `dynamic_cast`.
- Use it freely in unit tests, to verify a factory's dynamic type or to manage mocks.
- Prefer virtual methods to select code paths per subclass; they put the work inside the object.
- Prefer double dispatch, such as the Visitor pattern, when the work belongs outside the object.
- Use `dynamic_cast` freely only when the logic guarantees the instance really is the derived type.
- Never hand-implement an RTTI-like workaround such as a type-tagged hierarchy; the same arguments
  apply and the workaround disguises the true intent.
```cpp
// Bad: a type-based decision tree.
if (typeid(*data) == typeid(D1)) {
  ...
} else if (typeid(*data) == typeid(D2)) { ... }
```

### Google-specific RTTI practice
<!-- tier: google-internal -->
Prefer `absl::down_cast` over `dynamic_cast` when the derived type is known. It is a faster,
compile-time-checked downcast.

## Casting
<!-- tier: portable -->
Do not use C-style casts, except for a cast to `void`. Use C++-style casts or brace
initialization instead, choosing the first option that applies.
1. Use brace initialization to convert arithmetic types, for example `int64_t{x}`. It is safest:
   the code does not compile when the conversion loses information.
2. Use a function-style cast to convert to a class type, e.g. `std::string(some_cord)`.
3. Use `static_cast` for value conversions equivalent to a C-style cast, for explicit upcasts to a
   superclass, and for downcasts to a subclass when the object is an instance of it.
4. Use `const_cast` to remove the `const` qualifier.
5. Use `reinterpret_cast` for unsafe conversions between pointer types and integers, and to or from
   `void*`. Use it only when you understand the aliasing issues, and prefer dereferencing the
   pointer and using `std::bit_cast` on the result.
6. Use `std::bit_cast` to reinterpret the raw bits of a value as another type of the same size.
See the RTTI section for `dynamic_cast`.
```cpp
// Good.
int64_t y = int64_t{1} << 42;
void* p = static_cast<void*>(q);
// Bad: a C-style cast.
int x = (int)y;
```

### Google-specific cast helpers
<!-- tier: google-internal -->
- Use `absl::implicit_cast` to cast safely up a hierarchy, e.g. `Foo*` to a superclass or
  `const Foo*`.
- Use `absl::down_cast` to cast a superclass pointer to a subclass; the object must be an instance.

## Streams
<!-- tier: portable -->
Use streams where appropriate, and stick to simple usages.
- Overload `<<` only for value types, and write the user-visible value, never implementation
  details. To print internals for debugging, use named functions; `DebugString()` is the convention.
- Use streams for ad-hoc, local, human-readable output for developers, not end users; prefer a
  logging library over `std::cerr`.
- Do not use streams for external-user or untrusted-data I/O; use templating libraries for i18n,
  localization, and security hardening.
- Avoid the stateful parts of the streams API beyond error state: `imbue()`, `xalloc()`,
  `register_callback()`. Use `absl::StreamFormat()`, not manipulators or flags.
- Be consistent with the surrounding code. If the project has an established tool, use it.

### Google-specific string libraries
<!-- tier: google-internal -->
Prefer the string libraries in `absl/strings`, or their equivalent, over `std::stringstream`.

## Preincrement and Predecrement
<!-- tier: portable -->
Use the prefix form (`++i`, `--i`) unless the code explicitly needs the value of the postfix
expression. The prefix form is more readable and never less efficient: it need not copy the
pre-modification value.
```cpp
for (int i = 0; i < n; ++i) { ... }  // Good.
int old = i++;                       // Use i++ only when the old value is needed.
```

## Use of const
<!-- tier: portable -->
Use `const` in APIs wherever it is meaningful and accurate: on function parameters, methods, and
non-local variables. This gives mostly compiler-verified documentation of what an operation can
mutate, which matters for thread safety.
- If a function does not modify a by-reference or by-pointer argument, take it as
  `const T&`/`const T*`.
- Do not add `const` to a by-value parameter in a declaration; it has no effect on the caller.
- Declare methods `const` unless they alter the object's logical state or return a mutable
  reference.
- All of a class's `const` operations must be concurrency-safe; otherwise document it as unsafe.
- Using `const` on local variables is neither encouraged nor discouraged.
```cpp
// Good: the parameter is not modified.
void Print(const std::string& text);
```

### Where to put the const
<!-- tier: portable -->
Write the leading form, `const int* foo`, rather than `int const* foo`: it reads like English,
adjective before noun. The guide does not require this form, but it does require consistency with
the surrounding code. Its two rules, to use `const` on parameters and to omit it on by-value
parameters, are reconciled by scope: the by-value exception applies to declarations only.

## Use of constexpr, constinit, and consteval
<!-- tier: portable -->
- Use `constexpr` to define true constants and the functions and constructors supporting them.
- Use `constinit` to ensure constant initialization for non-constant variables.
- Use `consteval` for code that must not be invoked at runtime.
- Do not use `constexpr` or `consteval` to force inlining.
- Do not complexify function definitions merely to enable their use with `constexpr`.
```cpp
constexpr int kMaxUsers = 100;
constexpr int Sum(int a, int b) { return a + b; }
const int kTotal = Sum(2, 3);
constinit int g_counter = 0;  // Constant-initialized, but not a constant.
consteval int OnlyAtCompileTime(int x) { return x * 2; }
```
`constexpr` enables constants built from floating-point expressions, user-defined types, and
function calls. Marking something `constexpr` prematurely creates migration problems if it must
later be downgraded.

## Integer Types
<!-- tier: portable -->
Of the built-in C++ integer types, use only `int`.
- Assume `int` is at least 32 bits but not more; use plain `int` for values like loop counters.
- For other sizes use exact-width types from `<stdint.h>`: `int16_t`, `uint32_t`, `int64_t`. Never
  `short`, `long`, or `long long`.
- If a value could reach 2^31 or more, use a 64-bit type; intermediates may need more. When in
  doubt, choose the larger type.
- If the code is a container returning a size, use a type that accommodates any possible usage.
- Do not use unsigned types except for bit patterns or defined overflow modulo 2^N, and never to
  say a number is never negative; use assertions instead.
- Standard aliases such as `size_t` and `ptrdiff_t` are welcome; omit the `std::` prefix.
- Take care when converting integer types; conversions and promotions cause undefined behavior.
Unsigned integers suit bitfields and modular arithmetic, and the standard uses them for container
sizes. But unsigned arithmetic models modular rather than ordinary arithmetic, so a significant
class of bugs escapes compiler diagnosis, and mixing signedness causes an equally large class of
problems. Prefer iterators and containers over pointers and sizes.

## Floating-Point Types
<!-- tier: portable -->
Of the built-in C++ floating-point types, use only `float` and `double`, which you may assume
represent IEEE-754 binary32 and binary64. Do not use `long double`: it is non-portable.

## Architecture Portability
<!-- tier: portable -->
Write architecture-portable code. Do not rely on CPU features specific to a single processor.
- Store memory addresses as integers in `uintptr_t`, not `uint32_t` or `uint64_t`; use braced
  initialization for 64-bit constants.
- Avoid `long double` for floating point, and `short`, `long`, `long long` for integers.
- Encode structured data moving in or out with a serialization library such as Protocol Buffers.
```cpp
int64_t my_value{0x123456789};
uint64_t my_mask{uint64_t{3} << 48};
```

### Google-specific numeric formatting
<!-- tier: google-internal -->
When printing values, use type-safe numeric formatting libraries such as `absl::StrCat`,
`absl::Substitute`, `absl::StrFormat`, or `std::ostream` instead of the `printf` family.

## Preprocessor Macros
<!-- tier: portable -->
Avoid defining macros, especially in headers. Prefer inline functions, enums, and `const`
variables. Name macros with the project's namespace as a prefix.
- Never use macros to declare pieces of a C++ API, and never use them for public API declarations.
- Use an inline function, a `const` variable, or a reference instead of a macro, per the need.
- Do not use macros to conditionally compile code, except `#define` guards against double include.
- Do not define macros in a `.h` file. Define them right before use and `#undef` them right after.
- Do not `#undef` an existing macro to replace it; pick a likely-unique name instead.
- Avoid macros that expand to unbalanced C++ constructs, or document that behavior well.
- Prefer not to use `##` to generate function, class, or variable names.
- Exporting macros from a header is extremely strongly discouraged. If one must be exported, give it
  a globally unique, upper-case, namespace-prefixed name.
```cpp
// Bad: macros used to declare an API.
class WOMBAT_TYPE(Foo) {
 public:
  EXPAND_PUBLIC_WOMBAT_API(Foo)
  EXPAND_WOMBAT_COMPARISONS(Foo, ==, <)
};
// Good: plain C++.
class WOMBAT_TYPE_Foo {
 public:
  bool operator==(const WOMBAT_TYPE_Foo&) const;
};
```
Macros mean the code you see is not the code the compiler sees, and they have global scope. Their
problems are worst when they declare API: every error message must explain how the macros formed
the interface, and refactoring tools have a harder time updating it.

### Macro waivers
<!-- tier: google-internal -->
Macros are sometimes necessary in low-level libraries, and features such as stringification and
token concatenation are not available in the language. Before adding a macro that declares an
API, contact the project leads to request a waiver.

## 0 and nullptr/NULL
<!-- tier: portable -->
Use `nullptr` for pointers, and `'\0'` for chars. Do not use the `0` literal for either.
```cpp
// Good.
Foo* p = nullptr;
char terminator = '\0';
// Bad.
Foo* p = 0;
char terminator = 0;
```
`nullptr` provides type safety for pointer values, and `'\0'` makes the null character's type
explicit. The section title mentions `NULL`, but the rule text covers only `nullptr` and `'\0'`,
and gives no instruction for `NULL` itself.

## sizeof
<!-- tier: portable -->
Prefer `sizeof(varname)` to `sizeof(type)`. `sizeof(varname)` updates automatically if the
variable's type changes later. Use `sizeof(type)` only for code unrelated to any particular
variable, such as code managing an external or internal data format where no suitable C++ variable
exists.
```cpp
// Good: tracks the variable's type.
MyStruct data;
memset(&data, 0, sizeof(data));
// Bad: breaks if MyStruct changes.
memset(&data, 0, sizeof(MyStruct));
```

## Type Deduction (including auto)
<!-- tier: portable -->
Use type deduction only when it makes the code clearer to readers unfamiliar with the project,
or safer. Never use it merely to avoid writing an explicit type. Assume readers are not on your
team: `make_unique<Foo>()`'s return type is obvious, but `MyWidgetFactory()`'s is not.

### Function template argument deduction
<!-- tier: portable -->
Almost always fine. Deduction is the expected default way to call function templates, and
templates are usually designed so that deduction is clear and safe, or does not compile at all.
```cpp
template <typename T> void f(T t);
f(0);  // Invokes f<int>(0).
```

### Local variable type deduction
<!-- tier: portable -->
Use it to remove type information that is obvious or irrelevant, so the reader can focus on the
meaningful parts.
```cpp
// Good: the type is obvious from the initializer.
auto widget = std::make_unique<WidgetWithBellsAndWhistles>(arg1, arg2);
// Good: a concrete type that carries the useful information.
WidgetWithBellsAndWhistles& widget = *it->second;
```
- Prefer explicit types when part of the type is informative: the iterator type is boilerplate, but
  the value type is useful, so name the value type.
- For map-like containers, prefer structured bindings: explicit types are easy to get wrong, and
  bindings avoid unqualified key types.
- Do not use `decltype(auto)` if a simpler option works; it is obscure and costly in clarity.
- `auto d{42};` deduces `int`, not `std::initializer_list<int>`.

### Return type deduction
<!-- tier: portable -->
Use it only when the body has very few return statements and little other code, and the function
or lambda has a very narrow scope. Deduced return types do not define an abstraction boundary:
the implementation is the interface. Public functions in headers should never have them.

### Function parameter type deduction
<!-- tier: portable -->
Avoid deduced parameter types when a specific type can be given instead.
- If the function is called with one type, make it explicit, unless called near its definition or
  it is a lambda passed to a well-known interface.
- Do not use `auto` parameters in non-lambda functions; use named template parameters so the
  function's template-ness is explicit. In a lambda, prefer a template parameter over `decltype(x)`.
```cpp
// Bad: the function is a template, but does not say so.
void F(auto arg) { ... }
// Good.
template <typename T>
void F(T arg) { ... }
```

### Lambda init captures
<!-- tier: portable -->
Covered by the more specific lambda style rules, which largely supersede the general type
deduction rules.

### Structured bindings
<!-- tier: portable -->
Structured bindings name the elements of a larger object, so they may improve readability even
where plain `auto` would not.
- They are especially beneficial for pairs and tuples, which have no meaningful field names.
- Elements of containers such as `std::map<K, V>` benefit especially: the key and value get
  specific names, avoiding unqualified key types.
- For structs, name bindings after the fields; comment when the name differs, as for parameters.
```cpp
auto [iter, success] = my_map.insert({key, value});
auto [/*field_name1=*/bound_name1, /*field_name2=*/bound_name2] = ...;
```

## Class Template Argument Deduction
<!-- tier: portable -->
Use class template argument deduction (CTAD) only with templates whose maintainers have explicitly
opted in by providing at least one explicit deduction guide. Templates in the `std` namespace are
presumed to have opted in; enforce this with a compiler warning where available.
- CTAD uses must also follow the general type deduction rules.
- Beware implicit guides from constructors, especially pre-C++17 ones; adding explicit guides to
  fix them may break code relying on the implicit ones.
```cpp
// Good: std::array provides an explicit deduction guide.
std::array a = {1, 2, 3};  // `a` is a std::array<int, 3>
```

## Designated Initializers
<!-- tier: portable -->
Use designated initializers only in their C++20-compliant form.
- Initializers must appear in struct field order: `x` then `z` is legal, `y` then `x` is not.
- Do not use the older C-style or compiler-extension forms, which allow any order.
```cpp
struct Point { float x = 0.0; float y = 0.0; float z = 0.0; };
Point p = {
  .x = 1.0,
  .y = 2.0,
  // z will be 0.0
};
```

## Lambda Expressions
<!-- tier: portable -->
Use lambda expressions where appropriate.
- Prefer explicit captures when the lambda may escape the current scope.
```cpp
// Bad: the capture of `this` is not apparent, and `foo` may be destroyed
// before the lambda runs.
executor->Schedule([&] { Frobnicate(foo); })
// Better: the capture is visible, and the compiler fails if `Frobnicate` is
// a member function.
executor->Schedule([&foo] { Frobnicate(foo); })
```
- Use default capture by reference (`[&]`) only when the lambda's lifetime is obviously shorter
  than any capture's.
- Use default capture by value (`[=]`) only for a few obvious variables in a short lambda. A
  lambda in a non-static member function must capture `this` explicitly. Avoid long lambdas with
  default capture by value.
- Use captures only for variables from the enclosing scope, never to introduce new names or change
  an existing name's meaning; declare the variable, then capture it.
- A value capture of a pointer does not deep copy it, so it has the same lifetime hazards as a
  reference capture. Capturing `this` by value is especially misleading, as its use is implicit.
```cpp
// Good: an init capture moves a move-only variable into the lambda.
std::unique_ptr<Foo> foo = ...;
[foo = std::move(foo)]() { ... }
```

## Template Metaprogramming
<!-- tier: portable -->
Avoid complicated template programming.
- Use it in a few low-level components, spreading the extra maintenance burden over many uses.
- Think twice before using recursive instantiation, type lists, metafunctions, expression templates,
  SFINAE, or the `sizeof` trick; these usually mean the code has gone too far.
- Hide metaprogramming as an implementation detail so that user-facing headers stay readable.
- Comment tricky code especially well. Document how the code is used and what code it generates.
- Treat compiler error messages as part of the user interface; tune them to be understandable
  and actionable.

## Concepts and Constraints
<!-- tier: portable -->
Use concepts and constraints sparingly.
- Use them only where templates would have been used before C++20, and not in public headers.
- Prefer predefined standard library concepts over equivalent traits: `std::integral`, not
  `std::is_integral_v`.
- Prefer `requires(Condition)` over `template<Concept T>` and over legacy constructs such as
  `std::enable_if<Condition>`.
- Do not re-implement existing concepts or traits: use `std::default_initializable<T>`.
- Keep new concept declarations rare and internal, so they are not exposed at API boundaries.
- Do not define concepts that duplicate the function body or impose obvious requirements; concepts
  must be statically verifiable by the compiler.
```cpp
// Bad: redundant with negligible benefit.
template <typename T>
concept Addable = std::copyable<T> && requires(T a, T b) { a + b; };
template <Addable T> T Add(T x, T y, T z) { return x + y + z; }
```

## C++20 Modules
<!-- tier: portable -->
Do not use C++20 modules. The guide cites immature support in build systems, compilers, and
tooling, and an unsettled best practice for writing and using them.

## Coroutines
<!-- tier: portable -->
Use C++20 coroutines only through libraries that are approved for project-wide use.
- Do not roll your own promise or awaitable types: each implementation differs, semantics are hard
  to deduce, and the customization points invite bugs.

### Google-specific coroutine approval
<!-- tier: google-internal -->
Only use coroutine libraries that your project leads have approved for project-wide use.

## Disallowed standard library features
<!-- tier: portable -->
Do not use these C++ standard library features:
- `<ratio>`, because it is tied to a more template-heavy interface style.
- `<cfenv>` and `<fenv.h>`, because many compilers do not support those features reliably.
- `<filesystem>`, because testing support is insufficient and it has security vulnerabilities.

## Third-party Libraries
<!-- tier: portable -->
Be consistent with the code around you when choosing a third-party library.
- First check whether the codebase already has a library for that kind of problem. If so, use it.
- Otherwise prefer, in decreasing priority: the standard library, existing first-party libraries,
  then third-party libraries.
- Follow the codebase's policies for third-party code.

### Google-specific library preference order
<!-- tier: google-internal -->
At Google the preference order starts with Abseil, then the C++ standard library, then existing
first-party libraries, then third-party libraries.

## Nonstandard Extensions
<!-- tier: portable -->
Do not use nonstandard extensions to C++, unless otherwise specified. This covers GCC's
`__attribute__`, intrinsics such as `__builtin_prefetch` or SIMD builtins, `#pragma`, inline
assembly, `__COUNTER__`, `__PRETTY_FUNCTION__`, compound statement expressions, VLAs, `alloca()`,
and the Elvis operator `a?:b`. They do not work in all compilers, are often poorly specified,
differ subtly between compilers, add features readers must know, and need porting.

### Google-specific portability wrappers
<!-- tier: google-internal -->
Portability wrappers implemented with nonstandard extensions are acceptable, provided they come
from a designated project-wide portability header.

## Aliases
<!-- tier: portable -->
Public aliases exist for the benefit of an API's user, and must be clearly documented.
- Use `using` rather than `typedef`; it has more consistent syntax and works with templates.
- Do not add an alias to the public API just to save typing in the implementation.
- When defining a public alias, document its intent: whether it always matches the aliased type or
  offers only limited compatibility.
- Do not put namespace aliases in the public API. Header aliases are public API unless in a function
  body, private class section, or internal namespace; those, and `.cc` files, are unrestricted.
```cpp
// Good: the alias documents how clients should use it.
// Used to store field measurements. DataPoint may change from Bar* to some internal type.
// Client code should treat it as an opaque pointer.
using DataPoint = ::foo::Bar*;
// Bad: no documentation of intended use, not meant for client use.
using ::std::unordered_set;  // Bad: just for local convenience
```

## Switch Statements
<!-- tier: portable -->
- A switch not conditional on an enumerated value must always have a `default` case; the compiler
  warns about unhandled enumerated values.
- If the `default` case should never execute, treat that as an error and fail loudly.
- Annotate fall-through with the `[[fallthrough]];` attribute at the point where the fall-through
  occurs. Consecutive case labels with no code need no annotation.
```cpp
switch (var) {
  case 0: { ... break; }
  default: {
    LOG(FATAL) << "Invalid value in switch statement: " << var;
  }
}

switch (x) {
  case 41:  // No annotation needed for consecutive labels.
  case 43:
    if (dont_be_picky) {
      [[fallthrough]];  // Or a comment saying so.
    } else {
      CloseButNoCigar();
      break;
    }
  case 42:
    DoSomethingSpecial();
    [[fallthrough]];
  default:
    DoSomethingGeneric();
}
```

## cpplint
<!-- tier: google-internal -->
Use `cpplint.py` to detect style errors. It reads a source file and identifies many style errors.
It is not perfect and has both false positives and false negatives, but it is still valuable. Some
projects document how to run it from their project tools; if yours does not, download it
separately.

---
Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Other C++ Features, Ownership and Smart Pointers, Rvalue References, Friends, Exceptions, noexcept, Run-Time Type Information (RTTI), Casting, Streams, Preincrement and Predecrement, Use of const, Use of constexpr/constinit/consteval, Integer Types, Floating-Point Types, Architecture Portability, Preprocessor Macros, 0 and nullptr/NULL, sizeof, Type Deduction (including auto), Class Template Argument Deduction, Designated Initializers, Lambda Expressions, Template Metaprogramming, Concepts and Constraints, C++20 modules, Coroutines, Disallowed standard library features, Third-party Libraries, Nonstandard Extensions, Aliases, Switch Statements, Google-Specific Magic, cpplint)
