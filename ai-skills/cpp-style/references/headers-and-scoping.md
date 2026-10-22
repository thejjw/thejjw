# Header Files and Scoping

Scope: Header Files (Self-contained Headers, The #define Guard, Include What You Use, Forward Declarations, Defining Functions in Header Files, Names and Order of Includes) and Scoping (Namespaces, Internal Linkage, Nonmember/Static Member/Global Functions, Local Variables, Static and Global Variables, thread_local Variables).

## Header Files

### Pair each .cc file with a .h file
<!-- tier: portable -->
Give every `.cc` file an associated `.h` file. Exceptions: unit tests, and small `.cc` files
containing only `main()`.

## Self-contained Headers

### Make headers self-contained
<!-- tier: portable -->
- Header files must compile on their own and end in `.h`. Files meant for inclusion that are not
  self-contained end in `.inc`, and are used sparingly.
- Every header must have header guards and include all other headers it needs, so users and
  refactoring tools need no special conditions to include it.
- When a header declares inline functions or templates that clients instantiate, their definitions
  must also be in the header, directly or in a header it includes. Do not move them to separately
  included `-inl.h` files; that practice is no longer allowed.
- When all instantiations of a template occur in one `.cc` file, because they are explicit or the
  definition is accessible only to that file, keep the template definition in that file.
- Rare files intended for inclusion at unusual locations, such as the middle of another file, may
  lack guards and prerequisites. Name them `.inc` and use them sparingly.

## The #define Guard

### Guard every header with a path-derived macro
<!-- tier: portable -->
Give all headers `#define` guards to prevent multiple inclusion. Format the symbol as
`<PROJECT>_<PATH>_<FILE>_H_`, derived from the full path in the project's source tree to guarantee
uniqueness. The file `foo/src/bar/baz.h` in project `foo` uses:

```cpp
#ifndef FOO_BAR_BAZ_H_
#define FOO_BAR_BAZ_H_

...

#endif  // FOO_BAR_BAZ_H_
```

## Include What You Use

### Include the header that owns each symbol you use
<!-- tier: portable -->
- If a source or header refers to a symbol defined elsewhere, directly include the header that
  provides its declaration or definition. Do not include headers for any other reason.
- Never rely on transitive inclusion. This lets maintainers delete no-longer-needed `#include`s from
  their headers without breaking clients. It applies to related headers too: `foo.cc` includes
  `bar.h` if it uses a symbol from it, even when `foo.h` includes `bar.h`.

## Forward Declarations

### Avoid forward declarations where possible
<!-- tier: portable -->
Prefer including the headers you need. A forward declaration declares an entity without an
associated definition.

```cpp
// In a C++ source file:
class B;
void FuncInB();
extern int variable_in_b;
```

- Pros: saves compile time, since `#include`s force the compiler to open more files, and avoids
  recompilation caused by unrelated changes in an included header.
- Cons: hides dependencies, blocks tooling from discovering the defining module, breaks when the
  library changes, blocks compatible API changes (widening a parameter type, migrating to a new
  namespace), and yields undefined behavior for symbols in namespace `std`. Swapping an `#include`
  for forward declarations can silently change the meaning of code:

```cpp
// b.h:
struct B {};
struct D : B {};

// good_user.cc:
#include "b.h"
void f(B*);
void f(void*);
void test(D* x) { f(x); }  // Calls f(B*)
```

With forward declarations of `B` and `D` instead of the `#include`, `test()` would call `f(void*)`.
Forward declaring multiple symbols from one header is more verbose than including it, and
structuring code to enable forward declarations, such as using pointer members instead of object
members, can make the code slower and more complex.

### Restrict forward declarations to entities you own
<!-- tier: portable -->
- Do not use forward declarations of entities your project does not own.
- For entities you do own: make the header cheap enough to include directly; if the full header is
  too expensive, speed up the header's compilation; if a forward declaration is the better fix for a
  slowdown, use it.

Ambiguity: the summary rule says to avoid forward declarations where possible, while this decision
allows them for owned entities when a header is too expensive; the guide sets no numeric threshold.

### Declare Abseil flags by forward declaration
<!-- tier: google-internal -->
Inside Google, declare Abseil flags with `ABSL_DECLARE_FLAG(flag_in_b);` rather than including the
flag header.

## Defining Functions in Header Files

### Define a function in a header only when it is short
<!-- tier: portable -->
- Include a function's definition at its point of declaration in a header only when the definition
  is short. If it must live in the header for another reason, put it in an internal part of the
  file, and mark it `inline` if needed for ODR safety.
- "Inline function" covers several overlapping situations: the definition is exposed at the point of
  declaration; the compiler may expand it inline, giving more efficient object code; and the entity
  is ODR-safe, which often requires the `inline` keyword. These rules apply to variables as well.
- Pros: less boilerplate for simple functions such as accessors and mutators; inline expansion of
  small functions yields more efficient object code; function templates and `constexpr` functions
  generally need to be defined in the header that declares them, though not necessarily in its
  public part.
- Cons: a definition in the public API makes the API harder to skim, costs readers cognitive
  overhead, and exposes implementation details.

### Keep long bodies out of the public part of a header
<!-- tier: portable -->
- Define a function at its public declaration only if it is short, say 10 lines or fewer. Put longer
  bodies in the `.cc` file unless performance or technical reasons require the header.
- Needing to be in the header is not a reason to be in the public part. Put the definition in an
  internal part of the header: the private section of a class, a namespace whose name includes
  `internal`, or below a comment like `// Implementation details only below here`.
- Every definition in a header must be ODR-safe: use the `inline` specifier, or rely on implicit
  inline-ness from being a function template or from being defined in a class body when first
  declared.

```cpp
template <typename T>
class Foo {
 public:
  int bar() { return bar_; }

  void MethodWithHugeBody();

 private:
  int bar_;
};

// Implementation details only below here

template <typename T>
void Foo<T>::MethodWithHugeBody() {
  ...
}
```

## Names and Order of Includes

### Order includes by category
<!-- tier: portable -->
Order includes as: related header, C system headers, C++ standard library headers, other libraries'
headers, your project's headers.

List project headers as descendants of the project's source directory, without UNIX directory
aliases such as `.` (the current directory) or `..` (the parent directory). The file
`google-awesome-project/src/base/logging.h` is included as `#include "base/logging.h"`.

### Use angle brackets only when the library requires it
<!-- tier: portable -->
- C and C++ standard library headers, e.g. `<stdlib.h>` and `<string>`.
- In rare cases, third_party libraries, e.g. `<Python.h>`.

### Angle-bracket POSIX, Linux, and Windows system headers
<!-- tier: platform-specific -->
Use angle brackets for POSIX, Linux, and Windows system headers, e.g. `<unistd.h>` and
`<windows.h>`. Keep platform-specific code small and localized.

### Group includes with blank lines in dir/foo.cc
<!-- tier: portable -->
In `dir/foo.cc` or `dir/foo_test.cc` whose main purpose is to implement or test `dir2/foo2.h`, order
the includes as follows:

1. `dir2/foo2.h`.
2. A blank line.
3. C system headers, and any other angle-bracketed headers with the `.h` extension, e.g.
   `<unistd.h>`, `<stdlib.h>`, `<Python.h>`.
4. A blank line.
5. C++ standard library headers, without file extension, e.g. `<algorithm>`, `<cstddef>`.
6. A blank line.
7. Other libraries' `.h` files.
8. A blank line.
9. Your project's `.h` files.

Separate each non-empty group with one blank line. With this order, a missing include in
`dir2/foo2.h` breaks the build of `dir/foo.cc` first for the people working on those files, not for
innocent people in other packages. `dir/foo.cc` and `dir2/foo2.h` are usually in the same directory,
but may sometimes live in different directories.

C headers such as `stddef.h` are essentially interchangeable with their C++ counterparts
(`cstddef`). Either style is acceptable, but prefer consistency with existing code. Order the
includes alphabetically within each section; older code that does not conform should be fixed when
convenient.

```cpp
#include "foo/server/fooserver.h"

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "base/basictypes.h"
#include "foo/server/bar.h"
#include "third_party/absl/flags/flag.h"
```

### Put conditional includes after the other includes
<!-- tier: platform-specific -->
System-specific code sometimes needs conditional includes. Put them after the other includes, and
keep the system-specific code small and localized.

```cpp
#include "foo/public/fooserver.h"

#ifdef _WIN32
#include <windows.h>
#endif  // _WIN32
```

## Namespaces

### Prefer namespaces over global scope
<!-- tier: portable -->
Place code in a namespace, with few exceptions. Namespace names must be unique, based on the project
name and possibly its path. Do not use using-directives such as `using namespace foo`. Do not use
inline namespaces.

Namespaces subdivide the global scope into distinct named scopes, preventing name collisions:
`project1::Foo` and `project2::Foo` do not collide, while code inside each project's namespace
still refers to `Foo` without a prefix. An inline namespace automatically places its names in the
enclosing scope, so `outer::inner::foo()` and `outer::foo()` are interchangeable; inline namespaces
exist mainly for ABI compatibility across versions.

Cons: namespaces complicate figuring out which definition a name refers to; inline namespaces are
more confusing, since names are not actually restricted to their namespace; some contexts require
fully qualified names, adding clutter for deeply nested namespaces.

### Wrap the file in the namespace and close it with a comment
<!-- tier: portable -->
Follow the rules on Namespace Names. Terminate multi-line namespaces with a comment. The namespace
wraps the entire source file after the includes, the flag definitions and declarations, and the
forward declarations of classes from other namespaces. Code goes against the left margin.

```cpp
// In the .h file
namespace mynamespace {

// All declarations are within the namespace scope.
// Notice the lack of indentation.
class MyClass {
 public:
  ...
  void Foo();
};

}  // namespace mynamespace

// In the .cc file
namespace mynamespace {

// Definition of functions is within scope of the namespace.
void MyClass::Foo() {
  ...
}

}  // namespace mynamespace
```

More complex `.cc` files add flags or using-declarations:

```cpp
#include "a.h"

ABSL_FLAG(bool, someflag, false, "a flag");

namespace mynamespace {

using ::foo::Bar;

...code for mynamespace...

}  // namespace mynamespace
```

### Google-internal namespace practices
<!-- tier: google-internal -->
- Place gflags definitions and declarations and Abseil flag declarations before the namespace block,
  since the namespace wraps the rest of the file.
- To place generated protocol message code in a namespace, use the package specifier in the `.proto`
  file.
- Use `::absl::container_internal::ImplementationDetail` for implementation details reachable by
  users of an Abseil API. The guide notes this internal name should not be used in non-absl code.

### Namespace prohibitions
<!-- tier: portable -->
- Never declare anything in `namespace std`, including forward declarations of standard library
  classes. Declaring entities there is undefined behavior and is not portable. Include the
  appropriate header to use standard library entities.
- Never use a using-directive to make all names from a namespace available. Use a using-declaration
  for a specific name where one is needed, as in the `.cc` example above.
- Never use inline namespaces.

```cpp
// Forbidden -- This pollutes the namespace.
using namespace foo;
```

### Allow namespace aliases only in .cc files or internal namespaces
<!-- tier: portable -->
Do not use namespace aliases at namespace scope in header files, except in explicitly marked
internal-only namespaces, because anything imported into a namespace in a header becomes part of the
public API that file exports. Aliases are allowed when those conditions do not apply, but they must
have appropriate names.

```cpp
// In a .h file, an alias must not be a separate API, or must be hidden in
// an implementation detail.
namespace librarian {

namespace internal {  // Internal, not part of the API.
namespace sidetable = ::pipeline_diagnostics::sidetable;
}

inline void my_inline_function() {
  // Local to a function.
  namespace baz = ::foo::bar::baz;
  ...
}

}  // namespace librarian

// Remove uninteresting parts of some commonly used names in .cc files.
namespace sidetable = ::pipeline_diagnostics::sidetable;
```

### Mark non-API parts of a namespace as internal
<!-- tier: portable -->
Use namespaces with `internal` in the name to document parts of an API that users of the API should
not mention. A nested `internal` namespace still risks collisions between libraries, so give each
library a unique internal namespace by adding its filename: `gshoe/widget.h` uses
`gshoe::internal_widget`, not just `gshoe::internal`.

### Prefer single-line nested namespace declarations in new code
<!-- tier: portable -->
Single-line nested namespace declarations are preferred in new code, but are not required.

```cpp
namespace my_project::my_component {

  ...

}  // namespace my_project::my_component
```

## Internal Linkage

### Give file-local definitions internal linkage
<!-- tier: portable -->
- When definitions in a `.cc` file need no reference from outside that file, give them internal
  linkage by placing them in an unnamed namespace or declaring them `static`. Do not use either
  construct in `.h` files.
- Any declaration can get internal linkage by living in an unnamed namespace; functions and
  variables can also get it by being declared `static`. Nothing declared this way is accessible from
  another file, and a same-named declaration elsewhere is a completely independent entity.
- Use internal linkage in `.cc` files for all code that does not need to be referenced elsewhere.

Ambiguity: the guide permits both an unnamed namespace and `static` in `.cc` files and does not state
which one to prefer.

### Format unnamed namespaces like named namespaces
<!-- tier: portable -->
Terminate an unnamed namespace with a comment that leaves the namespace name empty:

```cpp
namespace {
...
}  // namespace
```

## Nonmember, Static Member, and Global Functions

### Prefer namespaced free functions over global functions
<!-- tier: portable -->
Place nonmember functions in a namespace; use completely global functions rarely. A nonmember
function should not depend on external variables and should nearly always exist in a namespace.

### Do not build classes out of static members
<!-- tier: portable -->
Do not create a class consisting of static members unless there is a good reason. Free functions in
a namespace are the idiomatic way to define non-instance operations; wrapping them in a class is
often an unnecessary Java-ism. Good reasons include a policy class or a trait, giving type semantics
to a separate representation, or closing an interface to extension.

Pros: nonmember and static member functions can be useful in some situations, and putting nonmember
functions in a namespace avoids polluting the global namespace. Cons: they may make more sense as
members of a new class, especially when they access external resources or have significant
dependencies.

Do not create classes only to group static members; that is no different from giving the names a
common prefix. If a nonmember function is needed only in its `.cc` file, use internal linkage to
limit its scope.

## Local Variables

### Declare variables in the narrowest scope, with initialization
<!-- tier: portable -->
Place a function's variables in the narrowest scope possible and initialize variables in the
declaration. Declare them as close to first use as possible, so the reader finds the declaration
and sees the type and the initial value. Use initialization instead of declaration followed by
assignment.

```cpp
int i;
i = f();      // Bad -- initialization separate from declaration.


int i = f();  // Good -- declaration has initialization.


int jobs = NumJobs();
// More code...
f(jobs);      // Bad -- declaration separate from use.


int jobs = NumJobs();
f(jobs);      // Good -- declaration immediately (or closely) followed by use.
```

Prefer brace initialization over `push_back` on a fresh container:

```cpp
std::vector<int> v;
v.push_back(1);  // Prefer initializing using brace initialization.
v.push_back(2);


std::vector<int> v = {1, 2};  // Good -- v starts initialized.
```

### Declare loop variables inside the loop statement
<!-- tier: portable -->
Declare the variables needed for `if`, `while`, and `for` statements within those statements, so the
variables stay confined to those scopes.

```cpp
while (const char* p = strchr(str, '/')) str = p + 1;
```

### Hoist expensive-to-construct objects out of loops
<!-- tier: portable -->
For an object variable, the constructor runs every time it enters scope and the destructor every
time it leaves it. Declare such a variable used in a loop outside the loop when construction and
destruction are expensive.

```cpp
// Inefficient implementation:
for (int i = 0; i < 1000000; ++i) {
  Foo f;  // My ctor and dtor get called 1000000 times each.
  f.DoSomething(i);
}

// Better: hoist the object out of the loop.
Foo f;  // My ctor and dtor get called once each.
for (int i = 0; i < 1000000; ++i) {
  f.DoSomething(i);
}
```

## Static and Global Variables

### Allow static storage duration only for trivially destructible objects
<!-- tier: portable -->
- Forbid objects with static storage duration unless they are trivially destructible. Informally,
  the destructor does nothing, even taking member and base destructors into account. Formally, the
  type has no user-defined or virtual destructor and all bases and non-static members are trivially
  destructible.
- Static function-local variables may use dynamic initialization. Dynamic initialization of static
  class member variables and of namespace-scope variables is discouraged, but allowed in the limited
  circumstances below.
- Rule of thumb: a global variable satisfies these requirements if its declaration, considered in
  isolation, could be `constexpr`.

### Allow only trivial destructors for static and global objects
<!-- tier: portable -->
When destructors are trivial their execution is not subject to ordering at all, they are effectively
not run; otherwise the program is exposed to the risk of accessing objects after the end of their
lifetime. Fundamental types such as pointers and `int` are trivially destructible, as are arrays of
trivially destructible types. Variables marked `constexpr` are trivially destructible.

```cpp
const int kNum = 10;  // Allowed

struct X { int n; };
const X kX[] = {{1}, {2}, {3}};  // Allowed

void foo() {
  static const char* const kMessages[] = {"hello", "world"};  // Allowed
}

// Allowed: constexpr guarantees trivial destructor.
constexpr std::array<int, 3> kArray = {1, 2, 3};

// bad: non-trivial destructor
const std::string kFoo = "foo";

// Bad for the same reason, even though kBar is a reference (the
// rule also applies to lifetime-extended temporary objects).
const std::string& kBar = StrCat("a", "b", "c");

void bar() {
  // Bad: non-trivial destructor.
  static std::map<int, int> kData = {{1, 0}, {2, 0}, {3, 0}};
}
```

References are not objects, so they are not subject to the constraint on destructibility; the
constraint on dynamic initialization still applies. A function-local static reference of the form
`static T& t = *new T;` is allowed.

### Require constant initialization for non-local statics
<!-- tier: portable -->
Constant initialization means the initializing expression is a constant expression and, if the
object is initialized by a constructor call, that the constructor is `constexpr`. Constant
initialization is always allowed. Mark constant initialization of static storage duration variables
with `constexpr` or `constinit`; presume that any non-local static storage duration variable not so
marked has dynamic initialization, and review it very carefully.

```cpp
struct Foo { constexpr Foo(int) {} };

int n = 5;  // Fine, 5 is a constant expression.
Foo x(2);   // Fine, 2 is a constant expression and the chosen constructor is constexpr.
Foo a[] = { Foo(1), Foo(2), Foo(3) };  // Fine

// Some declarations used below.
time_t time(time_t*);      // Not constexpr!
int f();                   // Not constexpr!
struct Bar { Bar() {} };

// Problematic initializations.
time_t m = time(nullptr);  // Initializing expression not a constant expression.
Foo y(f());                // Ditto
Bar b;                     // Chosen constructor Bar::Bar() not constexpr.
```

Discourage dynamic initialization of nonlocal variables; forbid it in general. Permit it only when
no aspect of the program depends on the sequencing of this initialization with respect to all other
initializations.

```cpp
int p = getpid();  // Allowed, as long as no other static variable
                   // uses p in its own initialization.
```

Dynamic initialization of static local variables is allowed and common.

### Use the approved patterns for static data
<!-- tier: portable -->
- Global strings: for a named global or static string constant, use a `constexpr` variable of
  `string_view`, character array, or character pointer pointing to a string literal. String literals
  already have static storage duration and are usually sufficient.
- Maps, sets, and other dynamic containers: a static, fixed collection cannot use the standard
  library's dynamic containers, since they have non-trivial destructors. Use a simple array of
  trivial types instead, e.g. an array of arrays of `int` for a map from `int` to `int`, or an array
  of pairs for a map to `const char*`. For small collections linear search is entirely sufficient and
  efficient thanks to memory locality; if necessary, keep the collection sorted and use binary search.
  If a standard library dynamic container is truly required, use a function-local static pointer.
- Smart pointers (`std::unique_ptr`, `std::shared_ptr`): forbidden, because they run cleanup during
  destruction. Consider whether the use case fits another pattern here. One solution is a plain
  pointer to a dynamically allocated object that is never deleted.
- Static variables of custom types: give the type a trivial destructor and a `constexpr` constructor.
- If all else fails, create the object dynamically and never delete it with a function-local static
  pointer or reference, e.g. `static const auto& impl = *new T(args...);`.

### Use absl/algorithm/container.h for standard container operations
<!-- tier: google-internal -->
Inside Google, use the facilities from `absl/algorithm/container.h` for the standard operations on
static arrays of trivial types.

## thread_local Variables

### Prefer thread_local for thread-local data
<!-- tier: portable -->
Prefer `thread_local` over other ways of defining thread-local data. Initialize `thread_local`
variables that are not declared inside a function with a true compile-time constant, and enforce this
with the `constinit` attribute.

```cpp
thread_local Foo foo = ...;
```

A `thread_local` variable is a collection of objects: different threads access different objects.
Such variables behave much like static storage duration variables. They can be declared at namespace
scope, inside functions, or as static class members, but not as ordinary class members. Instances are
initialized separately for each thread rather than once at program startup, so function-local
`thread_local` variables are safe, while others face the same initialization-order issues as static
variables, and more besides.

`thread_local` variables have a subtle destruction-order issue: during thread shutdown they are
destroyed in the opposite order of their initialization. If code triggered by one destructor refers
to an already-destroyed `thread_local` on that thread, the result is a particularly hard to
diagnose use-after-free.

Pros: thread-local data is inherently safe from races, and `thread_local` is the only
standard-supported way to create thread-local data. Cons: accessing one may trigger an unpredictable
amount of other code during thread start or first use; they are effectively global variables with
all their drawbacks except thread-safety; their memory consumption scales with the number of running
threads; data members cannot be `thread_local` unless they are also `static`; and complex
destructors can cause use-after-free, which skipping destructors does not fix, since a `thread_local`
leak persists per terminated thread.

### Annotate namespace- and class-scope thread_local variables
<!-- tier: portable -->
`thread_local` variables at class or namespace scope must be initialized with a true compile-time
constant, that is, they must have no dynamic initialization. Annotate them with `constinit`, or with
`constexpr`, but that should be rare.

### Use function-scope thread_local variables for lazy initialization
<!-- tier: portable -->
`thread_local` variables inside a function have no initialization concerns, but still risk
use-after-free during thread exit. Use a function-scope `thread_local` to simulate a class- or
namespace-scope one by defining a function or static method that exposes it.

```cpp
constinit thread_local Foo foo = ...;

Foo& MyThreadLocalFoo() {
  thread_local Foo result = ComplicatedInitialization();
  return result;
}
```

### Prefer trivial types for thread_local storage
<!-- tier: portable -->
`thread_local` variables are destroyed whenever a thread exits. If the destructor of one refers to
another, potentially destroyed, `thread_local`, the result is a hard to diagnose use-after-free bug.
Prefer trivial types, or types that provably run no user-provided code at destruction.

---
Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Header Files, Self-contained Headers, The #define Guard, Include What You Use, Forward Declarations, Defining Functions in Header Files, Names and Order of Includes, Scoping, Namespaces, Internal Linkage, Nonmember, Static Member, and Global Functions, Local Variables, Static and Global Variables, thread_local Variables)
