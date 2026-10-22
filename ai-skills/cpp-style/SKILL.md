---
name: cpp-style
description: Write, review, and refactor C++ following the Google C++ Style Guide -- headers and includes, scoping and namespaces, class and function design, ownership and smart pointers, modern C++ features, naming, comments, formatting, and an anti-pattern checklist. Use whenever C++ code is written, reviewed, debugged, or refactored (any .cc, .h, .hpp, CMakeLists.txt, or Bazel target), and whenever the user mentions C++, cpp, clang, clang-format, clang-tidy, cpplint, CMake, or a C++ codebase, even if they do not ask for idiomatic code.
metadata:
  audience: agents
  auth: none
---

# Idiomatic C++: The Google C++ Way

C++ conventions that survive review, refactoring, and automation. Derived from the
Google C++ Style Guide, which covers design and readability -- not just
formatting.

## When to Activate

- Writing new C++ code, functions, classes, or headers
- Reviewing or auditing existing C++ code
- Refactoring C++ that looks like it was ported from another language
- Designing a class, a header layout, or a public API
- Choosing between raw pointers, smart pointers, and containers
- Modernizing old C++ (`auto`, `nullptr`, `constexpr`, range-for, smart pointers)
- Deciding on namespaces, include order, or naming
- Adding `RTTI`, exceptions, casts, or templates and needing to know the limits

## Rule Tiers

Not every Google C++ rule is universal. Three tiers are used throughout this
skill and its references:

| Tier | Meaning | How to apply |
|---|---|---|
| **Portable** | General Google C++ style, valid in any codebase | Apply by default |
| **Google-internal** | Google-specific practice (`absl` types, the no-exceptions policy, cpplint, google3 build rules) | Apply only in Google codebases; otherwise mention it as an option |
| **Platform-specific** | Scoped to a platform (Windows code, COM/ATL) | Apply only on that platform |

Every rule in the `references/` files carries a tier tag. Check the tag before
applying a rule to code that is not Google's.

## Core Principles

The guide's stated goals -- use them to judge a rule that seems arbitrary.

1. **Style rules should pull their weight.** The benefit must justify asking
   every engineer to remember the rule. This mostly explains the rules the
   guide does *not* have.
2. **Optimize for the reader, not the writer.** Code outlives its authors, so
   most time is spent reading it. Leave a trace for the reader when something
   surprising happens -- a `std::unique_ptr` at the call site says "ownership
   transfers here" unambiguously.
3. **Be consistent with existing code.** Consistency frees attention for real
   problems and is what makes formatting and `#include` tooling work. Apply it
   locally first (per file, per related set of interfaces). It is a tie-breaker,
   not a reason to keep an old style.
4. **Be consistent with the broader C++ community when appropriate.** A widely
   accepted idiom is a good default -- unless the standard feature is flawed or
   does not fit the codebase.
5. **Avoid surprising or dangerous constructs.** Some C++ features are more
   surprising than they look. Waivers here have a high bar.
6. **Avoid constructs the average C++ programmer would find tricky.** Code
   ownership changes over time; today's understood code is next year's
   mystery.
7. **Be mindful of scale.** At 100M+ lines, avoid polluting the global
   namespace and avoid shortcuts that scale badly.
8. **Concede to optimization when necessary.** Performance work may override
   the rules above.

### Language baseline

- Target **C++20**. Do not use C++23 features.
- Do not use non-standard extensions (GCC `__attribute__`, VLAs, `alloca`,
  statement expressions, the Elvis operator).
- Consider portability before relying on C++17/C++20 features.
- Read `references/modern-cpp.md` before using a modern feature in a codebase
  that may not be on C++20.

## Headers and Includes

Full detail: `references/headers-and-scoping.md`.

- **Headers must be self-contained.** Every header compiles on its own; include
  what you use.
- **Every header gets a `#define` guard** of the form
  `<PROJECT>_<PATH>_<FILE>_H_`, based on the full path in the source tree:

  ```cpp
  #ifndef FOO_BAR_BAZ_H_
  #define FOO_BAR_BAZ_H_
  // ...
  #endif  // FOO_BAR_BAZ_H_
  ```

- **Include what you use.** Declare forward declarations rather than pulling in
  headers you do not need.
- **Define functions in headers only when they are `inline` or templates.**
- **Include order**: related header, C system headers, C++ standard library
  headers, other libraries' headers, project headers.
- **Project headers are included relative to the project source directory** --
  `#include "base/logging.h"`, never `"."` or `".."`.
- **Angle brackets only when the library requires it.**
- `.cc` for sources, `.h` for headers, `.inc` for textually included files.

## Scoping and Namespaces

Full detail: `references/headers-and-scoping.md`.

- **Put code in a namespace** with a unique, project-based name.
- **Never use using-directives** (`using namespace foo;`) and **never use inline
  namespaces**.
- **Internal linkage lives in `.cc` files**: an unnamed namespace or `static`.
  Not in headers.
- **Nonmember functions live in the namespace of the type they operate on**;
  `static` free functions are discouraged.
- **Avoid global and static non-const variables.** Use `const`/`constexpr` for
  constants, `thread_local` for per-thread state.
- **Top-level namespaces must be globally unique**; nested namespaces must
  avoid `std` and `absl`.

## Classes

Full detail: `references/classes-and-functions.md`.

- **Do no work in constructors.** Avoid virtual calls in constructors and
  initialization that can fail without a way to signal the error -- use an
  init method or a factory instead.
- **Never define implicit conversions.** Mark single-argument constructors and
  conversion operators `explicit`.
- **Be explicit about copy and move semantics.** A type with a user-declared
  destructor or copy/move operation does not get implicit move operations.
- **`struct` for data, `class` for behavior.** `struct` defaults to public
  members; `class` defaults to private. Use a named struct rather than
  `std::pair` or `std::tuple` when the members have meaning.
- **Prefer composition over inheritance.** When you inherit, inherit publicly.
- **Overload operators only where the meaning is obvious** and matches the
  standard's meaning.
- **Access control**: `public` for the type itself, `protected` only for
  inheritance, `private` otherwise.
- **Declaration order in a class**: `public`, then `protected`, then `private`;
  types before functions; constructor, destructor, then other methods; data
  members last.

## Functions

Full detail: `references/classes-and-functions.md`.

- **Return values over output parameters.** A return value reads better and
  performs at least as well.
- **Pass large or mutable inputs by const reference.**
- **Keep functions short.**
- **Prefer overloading to default arguments.** Default arguments are allowed on
  non-virtual functions only when the default is guaranteed to be the same
  value, and when readability gain outweighs the downsides.
- **Do not use trailing return types**, except where a leading return type
  cannot be written.
- **Accessor naming**: `count()` and `set_count(int count)` are allowed in
  `snake_case`; other functions are `PascalCase`.

## Ownership and Memory

Full detail: `references/modern-cpp.md`.

- **One fixed owner per dynamically allocated object.** Transfer ownership with
  smart pointers.
- **Use `std::unique_ptr` by default.** Shared ownership is discouraged.
- **Avoid raw `new` and `delete`.** Prefer containers and smart pointers; use
  `delete` only when the lifetime cannot be expressed otherwise.
- **Leave a trace for the reader at ownership transfer points.**

```cpp
// Idiomatic: ownership transfer is visible at the call site.
std::unique_ptr<Widget> CreateWidget();

// Idiomatic: prefer a container over new/delete.
std::vector<std::string> names;
```

## Error Handling, RTTI, and Casts

Full detail: `references/modern-cpp.md`.

- **Google does not use C++ exceptions.** (Google-internal tier.) The guide
  documents the tradeoff; in a codebase that does use exceptions, use them for
  genuinely exceptional conditions, not ordinary control flow.
- **Avoid RTTI** (`typeid`, `dynamic_cast`) outside unit tests. Do not
  hand-roll an RTTI-like workaround with type tags.
- **Use C++-style casts**: `static_cast`, `dynamic_cast`, `const_cast`,
  `reinterpret_cast`, and function-style casts for class types
  (`std::string(some_cord)`). Do not use C-style casts such as `(int)x`,
  except to `void`.
- **Specify `noexcept` when it is useful and correct.** Prefer unconditional
  `noexcept` where exceptions are disabled; `noexcept` on a move constructor has
  a real performance benefit (a `std::vector` moves rather than copies).

## Types and Modern C++

Full detail: `references/modern-cpp.md`.

- **`int` is the only built-in integer type used.** Otherwise use exact-width
  types from `<cstdint>` (`int16_t`, `int64_t`). When in doubt, choose the
  larger type -- intermediate calculations may need it.
- **Use `const` whenever it makes sense** in APIs; `constexpr` for some of
  those uses.
- **Use `auto` only when it makes the code clearer or safer**, not to avoid
  writing the type.
- **Use `nullptr` for pointers** and `'\0'` for the null character -- not the `0`
  literal. `nullptr` is type-safe for address values.
- **Prefer `sizeof(varname)` to `sizeof(type)`** so the value follows the
  variable's type; use `sizeof(type)` only for external data formats.
- **Prefer `using` aliases** over `typedef`.
- **Prefer `++i`** unless postfix semantics are needed.
- **Prefer brace initialization for containers** over repeated `push_back`.
- **Use `constexpr`, `constinit`, and `consteval`** per their semantics:
  `constexpr` for compile-time values, `constinit` for constant initialization
  of otherwise mutable statics, `consteval` for immediately invoked functions.
- **Every `switch` on a non-enumerated value has a `default` case**, and a
  `default` that should never run is an error. Mark intentional fall-through
  with `[[fallthrough]];`.

## Comments and Inclusive Language

Full detail: `references/comments-and-inclusion.md`.

- **Use `//` for all comments.** Block comments only in rare cases.
- **Comment every function and class**, describing purpose and contract --
  not restating the name.
- **Explain why, not what.** A comment that adds complexity should explain the
  complexity.
- **File comments** carry the copyright and license header.
- **TODO format**: `TODO(username): description`.
- **Use inclusive language.** Avoid `master`/`slave`, `blacklist`/`whitelist`,
  `redline`, and similar, in code, names, and comments. Use gender-neutral
  pronouns for people whose gender is unspecified.

## Naming

Full detail and the complete tables: `references/naming.md`.

| Entity | Convention | Example |
|---|---|---|
| Types (class, struct, alias, enum) | `PascalCase`, no underscores | `MyExcitingClass` |
| Concepts | Same as types | `Sortable` |
| Variables, parameters, locals | `snake_case` | `table_name` |
| Class data members | `snake_case_` (trailing underscore) | `table_name_` |
| Struct data members | `snake_case` (no trailing underscore) | `name` |
| Constants (`const`/`constexpr`, fixed value) | `k` + `MixedCase` | `kDaysInAWeek` |
| Functions | `PascalCase` | `AddTableEntry()` |
| Accessors / mutators | may be `snake_case` | `count()`, `set_count(int)` |
| Namespaces | `snake_case`, project-unique | `my_project` |
| Enumerators | Like constants, not macros | `kUrlTableError` |
| Template parameters | Follow the category's rules | `T` for type params |
| Macros | `ALL_CAPS` with a project prefix | `MYPROJECT_ROUND(x)` |
| Files | lowercase with `_` or `-`; `.cc` / `.h` / `.inc` | `my_useful_class.cc` |

- **Name for a reader on another team.** Do not save horizontal space.
- **Scale descriptiveness to scope.** A header-level function should say which
  library it belongs to; a local variable should not.
- **Minimize abbreviations**, especially acronyms. Capitalize an abbreviation
  as one word: `StartRpc()`, not `StartRPC()`. Do not delete letters inside a
  word (`cstmr_id` is wrong).
- **Name after the purpose, not the type** -- `http_server_logs.h`, not
  `logs.h`.

## Formatting

Full detail: `references/formatting.md`.

- **80 columns maximum**, 2-space indent, spaces never tabs.
- ASCII only in source files.
- `clang-format` with the Google style handles most of this mechanically;
  apply the judgment rules (comment content, line-length exceptions, naming)
  by hand.

## Anti-Patterns Agents Commonly Generate

These are the usual review findings in generated C++:

- `using namespace std;` in a header
- Raw `new`/`delete` where a container or `std::unique_ptr` works
- C-style casts (`(int)x`) instead of `static_cast` and friends
- `auto` everywhere, including where the explicit type documents intent
- `unsigned int`/`long` for sizes and counters instead of `int` or
  `<cstdint>` types
- Implicit conversions from single-argument constructors
- Missing `const` on parameters and locals
- `0` instead of `nullptr` for pointers, or `0` instead of `'\0'` for the null
  character
- `i++` where `++i` is the norm
- Headers that are not self-contained, or that include `<vector>` for one
  declaration
- Missing `#define` guards, or `#pragma once`
- Vague names (`data`, `tmp`, `manager`), or names that repeat the type
- Exceptions used for ordinary control flow in a codebase that forbids them
- `dynamic_cast`/`typeid` in production code

## Tooling Map

| Tool | Enforces | Notes |
|---|---|---|
| `clang-format` (Google style) | Line length, indentation, whitespace, braced lists, initializer lists | The guide's Formatting section is largely a `clang-format` config |
| `cpplint.py` | The guide's own style checks | The guide recommends it explicitly; it has both false positives and false negatives |
| `clang-tidy` (`google-readability-*`, `google-runtime-*`, `modernize-*`, `performance-*`, `bugprone-*`) | The judgment rules a formatter cannot | Match the project's existing check selection |
| Compiler warnings (`-Wall -Wextra`, warnings as errors) | Correctness issues | On MSVC, warning level 3 or higher with warnings as errors |

## When to use me

- The user asks for idiomatic C++, or why C++ code is written a certain way
- The user is writing, reviewing, or refactoring C++ source or headers
- The user mentions C++, clang, clang-format, clang-tidy, cpplint, CMake, or Bazel
- A class, header layout, or public API is being designed
- Ownership, exceptions, RTTI, casts, or templates need a decision
- Old C++ is being modernized (`auto`, `nullptr`, `constexpr`, smart pointers)
- Code under review contains one of the anti-patterns above

## Limitations

- This skill encodes Google's conventions, not a universal C++ standard. Where
  it conflicts with the project's own conventions, follow the project --
  including its exceptions to these rules.
- It does not cover build systems, dependency management, testing frameworks,
  or performance tuning beyond what the guide says.
- Google-internal rules (`absl` types, the no-exceptions policy) are marked as
  such and are not universal.
- It does not replace the compiler, `clang-tidy`, or the project's own linters.

## Sources and Maintenance

**Original resource.** This skill is derived from the Google C++ Style Guide:
<https://google.github.io/styleguide/cppguide.html>
(upstream source: `google/styleguide`, file `cppguide.md`).

The guide's eight goals -- the reasons a rule exists when the rule alone looks
arbitrary -- are listed under [Core Principles](#core-principles) in this file.
Keep them in mind when extending the skill: a rule that serves none of them
probably does not belong.

The guide also states that its own code snippets are illustrative, not
templates: many are missing comments and technical details that real code
requires. Do not copy them verbatim into a codebase.

**Related resources:**

- Google C++ Style Guide (source of this skill) --
  <https://google.github.io/styleguide/cppguide.html>
- cpplint (the guide's own linter) -- <https://github.com/cpplint/cpplint>
- clang-format documentation -- <https://clang.llvm.org/docs/ClangFormat.html>
- clang-tidy checks list -- <https://clang.llvm.org/extra/clang-tidy/checks/list.html>
- C++ Core Guidelines -- <https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines>
  (a different guide, useful as a counterpoint; this skill follows Google's rules)

**Sibling skills:**

- `rust-style` (in this repository) -- the same distillation pattern applied to
  the Google Rust Style Guide, including the tier-tagging convention.
- `spf13/go-skills` -> `go` -- the structural template for language-guide
  skills. <https://github.com/spf13/go-skills>

**How to update this skill.**

1. Re-read the original guide and diff it against the sections above; the
   guide's own table of contents is the checklist.
2. Keep the tier tags current. A rule that moved between tiers (for example, an
   `absl`-specific practice becoming general) must have its tag changed in
   `SKILL.md` and in every `references/` file that repeats it.
3. Update the Tooling Map when a linter check is renamed or added, and verify
   names against the clang-tidy checks list.
4. Refresh the `Checked against` stamp below.
5. Preserve the guide's own principle: optimize for the reader. If a rule
   cannot be explained in one line, it probably belongs in `references/`.

Checked against: 2026-10-22 (Google C++ Style Guide as published on that date).
