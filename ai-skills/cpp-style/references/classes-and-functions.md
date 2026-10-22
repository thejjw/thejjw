# Classes and Functions

Scope: Classes (Doing Work in Constructors, Implicit Conversions, Copyable and Movable Types,
Structs vs. Classes, Structs vs. Pairs and Tuples, Inheritance, Operator Overloading, Access
Control, Declaration Order) and Functions (Inputs and Outputs, Write Short Functions, Function
Overloading, Default Arguments, Trailing Return Type Syntax).

## Doing Work in Constructors

### Do no work in constructors
<!-- tier: portable -->
- Never call virtual functions from a constructor; subclass implementations never get the call.
- Never do fallible initialization in the constructor body unless you can signal the error. A
  failed constructor leaves an object needing a `bool IsValid()` check that is easy to forget.
- If the work can fail, terminate the program, or use a factory function or an `Init()` method.
- Do not add `Init()` to an object with no other states affecting which public methods are valid.

### Google-internal error handling
<!-- tier: google-internal -->
- Treat exceptions as forbidden in Google code; terminate the program instead.

## Implicit Conversions

### Mark conversion operators and single-argument constructors explicit
<!-- tier: portable -->
- Mark every conversion operator and every single-argument constructor `explicit` in the class.
- Do not mark copy and move constructors `explicit`; they do not perform type conversion.
- Omit `explicit` on constructors that cannot be called with a single argument, and on a single
  `std::initializer_list` constructor, to support copy-initialization (`MyType m = {1, 2};`).
- Implicit conversions hide type-mismatch bugs, obscure which overload is called, and cause
  call-site ambiguities when conversions exist in both directions.

```cpp
class Foo {
  explicit Foo(int x, double y);
  ...
};

void Func(Foo f);


Func({42, 3.14});  // Error
```

### Request a waiver for intentional implicit conversions
<!-- tier: google-internal -->
- Use an implicit conversion only for interchangeable types, e.g. two spellings of one value, and
  contact your project leads to request a waiver of the `explicit` rule then.

## Copyable and Movable Types

### Declare, delete, or omit copy and move operations
<!-- tier: portable -->
- Make the public API state whether the class is copyable, move-only, or neither, and support
  copying and/or moving when those operations are clear and meaningful for the type.
- Explicitly declare the copy operations in a copyable class, explicitly declare the move
  operations in a move-only class, and explicitly delete the copy operations in a class that is
  neither copyable nor movable.
- A copyable class may also declare move operations to support efficient moves; declaring or
  deleting all four operations is permitted but not required.
- If you provide a copy or move assignment operator, also provide the matching constructor.
- Omit the declarations only when the class has no private section and copyability follows from its
  public data members, or when a base class clearly is not copyable or movable.
- An interface-only base class that leaves the operations implicit does not make concrete
  subclasses clear; if you declare one copy operation, declare or delete the other too.
- Do not expect implicit moves when you declare a copy constructor, a copy assignment operator, or
  a destructor; declare the move operations explicitly instead.
- Do not make a type copyable or movable when copying or moving is unclear to a casual user, or
  when it incurs unexpected costs. Avoid defining move operations for copyable types unless they
  are significantly more efficient than the copy operations.
- Design the class so the default copy operations are correct, and review defaulted ones as any
  other code.
- To eliminate the risk of slicing, prefer to make base classes abstract: make their constructors
  protected, declare their destructors protected, or give them a pure virtual member function.
  Prefer not to derive from concrete classes, and do not copy polymorphic base classes.

```cpp
class Copyable {
 public:
  Copyable(const Copyable& other) = default;
  Copyable& operator=(const Copyable& other) = default;

  // The implicit move operations are suppressed by the declarations above.
  // You may explicitly declare move operations to support efficient moves.
};

class MoveOnly {
 public:
  MoveOnly(MoveOnly&& other) = default;
  MoveOnly& operator=(MoveOnly&& other) = default;

  // The copy operations are implicitly deleted, but you can
  // spell that out explicitly if you want:
  MoveOnly(const MoveOnly&) = delete;
  MoveOnly& operator=(const MoveOnly&) = delete;
};

class NotCopyableOrMovable {
 public:
  NotCopyableOrMovable(const NotCopyableOrMovable&) = delete;
  NotCopyableOrMovable& operator=(const NotCopyableOrMovable&) = delete;

  // The move operations are implicitly disabled too.
  NotCopyableOrMovable(NotCopyableOrMovable&&) = delete;
  NotCopyableOrMovable& operator=(NotCopyableOrMovable&&) = delete;
};
```

## Structs vs. Classes

### Use struct only for passive objects that carry data
<!-- tier: portable -->
- Use `struct` only for passive objects that carry data; use `class` for everything else.
  `struct` members are public by default; `class` members are private by default.
- Keep all fields of a struct public, and do not give the struct invariants that relate different
  fields, since direct user access to those fields may break the invariants.
- Allow constructors, destructors, and helper methods in a struct, but do not let them require or
  enforce any invariants.
- Use a class when more functionality or invariants are required, or when the struct has wide
  visibility and is expected to evolve. If in doubt, make it a class.
- Use `struct` instead of `class` for stateless types, such as traits, template metafunctions, and
  some functors, for consistency with the STL. Struct and class members have different naming rules.

## Structs vs. Pairs and Tuples

### Prefer a named struct over a pair or a tuple
<!-- tier: portable -->
- Prefer a struct over a `std::pair` or a `std::tuple` whenever the elements can have meaningful
  names; a field name is almost always clearer than `.first`, `.second`, or `std::get<X>`, and
  `std::get<Type>` only partially mitigates that.
- Use pairs and tuples in generic code where the elements have no specific meanings, or where an
  existing code base or API requires them.

## Inheritance

### Prefer composition over inheritance
<!-- tier: portable -->
- Prefer composition; restrict inheritance to the is-a case, where `Bar` subclasses `Foo` only if
  `Bar` can reasonably be said to be a kind of `Foo`.
- Do not overuse implementation inheritance: it spreads an implementation across base and subclass,
  and a subclass cannot override non-virtual base functions.
- Prefer public inheritance. If private inheritance is what you want, include an instance of the
  base class as a member instead. Use `final` on classes you will not derive from.
- Limit `protected` to the member functions that subclasses might need to access; keep data
  members private.
- Annotate overrides of virtual functions and virtual destructors with exactly one of `override`
  or (less frequently) `final`, and do not add `virtual` when declaring an override.
- Multiple inheritance is permitted, but multiple implementation inheritance is strongly
  discouraged. Prefer interface inheritance from a pure abstract base class.

## Operator Overloading

### Overload an operator only when its meaning is obvious
<!-- tier: portable -->
- Define an overloaded operator only when its meaning is obvious, unsurprising, and consistent
  with the corresponding built-in operator. Use `|` as a bitwise-or or logical-or, not as a pipe.
- Define operators only on your own types, in the same headers, `.cc` files, and namespaces as the
  types they operate on. Avoid defining operators as templates; they must satisfy the rule for any
  possible template arguments. If you define an operator, also define the related operators that
  make sense, consistently.
- Prefer non-modifying binary operators as non-member functions: a member binary operator applies
  implicit conversions to the right-hand argument but not the left-hand one, so `a + b` would
  compile while `b + a` would not.
- For a type `T` whose values can be compared for equality, define a non-member `operator==` and
  document when two values are considered equal. Define `operator<=>` only when there is a single
  obvious notion of ordering, and keep it consistent with `operator==`. Prefer not to overload the
  other comparison and ordering operators.
- Prefer defining `==`, `=`, and `<<` rather than `Equals()`, `CopyFrom()`, and `PrintTo()`. Do not
  define operator overloads just because other libraries expect them: if a type has no natural
  ordering but must live in a `std::set`, use a custom comparator instead of overloading `<`.
- Do not overload `&&`, `||`, `,` (comma), or unary `&`, and do not overload `operator""`; do not
  introduce user-defined literals, and do not use user-defined literals provided by others,
  including the standard library. Type conversion operators follow the implicit conversion rules,
  and `=` follows the copy/move rules.

### Google-internal bans behind the literal rule
<!-- tier: google-internal -->
- The guide avoids user-defined literals partly because Google bans using-directives, and bans
  using-declarations in header files except for names that are part of the header's interface.

## Access Control

### Keep data members private
<!-- tier: portable -->
- Make class data members private unless they are constants, and provide accessors, usually
  `const`, for the state that callers need.
- Use `public:` for the type's interface, `protected:` only for what subclasses need, and
  `private:` for everything else.
- Allow data members of a test fixture class defined in a `.cc` file to be `protected` when using
  Google Test. Make them private when the fixture is defined outside the `.cc` file that uses it.

## Declaration Order

### Order the access sections and the members
<!-- tier: portable -->
- Start a class definition with a `public:` section, then `protected:`, then `private:`. Omit
  sections that would be empty, group similar declarations together, and place public parts earlier.
- Within each section, order declarations as follows: 1. Types and type aliases (`typedef`,
  `using`, `enum`, nested structs and classes, friend types); 2. (Structs only) non-static data
  members; 3. Static constants; 4. Factory functions; 5. Constructors and assignment operators;
  6. Destructor; 7. All other functions (static and non-static member functions, and friend
  functions); 8. All other data members (static and non-static).
- Do not put large method definitions inline in the class definition. Define a method inline only
  when it is trivial, very short, or performance-critical.

## Inputs and Outputs

### Prefer return values over output parameters
<!-- tier: portable -->
- Return the result rather than using output parameters; return values improve readability and
  often provide the same or better performance. Return by value, or failing that, return by
  reference. Avoid returning a raw pointer unless it can be null.
- Pass non-optional input parameters as values or const references, and non-optional output and
  input/output parameters as references, which cannot be null.
- Use `std::optional` for optional by-value inputs, and a const pointer when the non-optional form
  would have used a reference. Use non-const pointers for optional outputs and optional input/output
  parameters.
- Avoid functions that require a reference parameter to outlive the call; reference parameters can
  bind to temporaries, causing lifetime bugs. Eliminate the lifetime requirement, for example by
  copying the parameter, or pass retained parameters by pointer and document the lifetime and
  non-null requirements.
- Put all input-only parameters before any output parameters, and do not append new parameters to
  the end just because they are new. This is a soft rule: input/output parameters muddy the
  waters, consistency with related functions may require bending it, and variadic functions may
  need unusual ordering.

## Write Short Functions

### Prefer small and focused functions
<!-- tier: portable -->
- Prefer small and focused functions. No hard limit is placed on function length, but if a function
  exceeds about 40 lines, consider whether it can be broken up without harming the structure of the
  program.
- Do not be intimidated by long, complicated functions when modifying existing code. If the work is
  hard to debug, or a piece of the function is needed in several contexts, break it into smaller,
  more manageable pieces.
- Small functions are easier to read, to modify, and to test, and are less likely to break when
  someone adds behavior to them months later.

## Function Overloading

### Overload only when the call site explains itself
<!-- tier: portable -->
- Overload a function only if a reader at the call site can get a good idea of what is happening
  without first working out exactly which overload is called.
- Overload when there are no semantic differences between the variants. The variants may differ in
  types, qualifiers, or argument count; the reader must not need to know which member of the
  overload set is chosen, only that something from the set is being called.
- Prefer `std::string_view` over overloading a `const std::string&` function with a `const char*`
  one.
- Prefer a single comprehensive umbrella comment that documents the entire overload set, placed
  before the first declaration. Add a comment for a specific overload only where a reader might
  have difficulty connecting the umbrella comment to it.
- Overloading based on const or ref qualification may make utility code more usable or efficient.

```cpp
class MyClass {
 public:
  void Analyze(const std::string& text);
  void Analyze(const char* text, size_t textlen);
};
```

## Default Arguments

### Prefer overloads to default arguments
<!-- tier: portable -->
- Do not use default arguments on virtual functions. The defaults of a virtual call come from the
  static type of the target object, and there is no guarantee that all overrides declare the same
  defaults.
- Do not use a default whose value may differ between evaluations, for example
  `void f(int n = counter++);`.
- Use default arguments only when the default is guaranteed to always have the same value, and
  only when the readability gain outweighs the downsides. When in doubt, use overloads.
- Avoid default arguments where the function's address is taken: the function signature often does
  not match the call signature, which makes function pointers confusing.

## Trailing Return Type Syntax

### Use the leading return type by default
<!-- tier: portable -->
- Declare the return type before the function name in most cases. Use the trailing form only where
  it is required, such as for lambdas, or where putting the type after the parameter list makes it
  much more readable.
- The latter case should be rare and is mostly an issue in complicated template code, which is
  discouraged anyway.
- Remember that the trailing return type is in the function's scope. It makes no difference for a
  simple type such as `int`, but it matters for types declared in class scope and for types written
  in terms of the function's parameters.

```cpp
int Foo(int x);


auto Foo(int x) -> int;


template <typename T, typename U>
auto Add(T t, U u) -> decltype(t + u);
```

versus the much less readable leading form:

```cpp
template <typename T, typename U>
decltype(declval<T&>() + declval<U&>()) Add(T t, U u);
```

### Google-internal cross-references
<!-- tier: google-internal -->
- TotW ("Tip of the Week") is a Google-internal document. Relevant tips: #42 (factory functions
  and `Init()`), #116 (reference parameter lifetimes), #148 (const or ref qualified overloading),
  and #176 (return values over output parameters).

---
Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Classes, Doing Work in Constructors, Implicit Conversions, Copyable and Movable Types, Structs vs. Classes, Structs vs. Pairs and Tuples, Inheritance, Operator Overloading, Access Control, Declaration Order, Functions, Inputs and Outputs, Write Short Functions, Function Overloading, Default Arguments, Trailing Return Type Syntax)
