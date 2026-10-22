# C++ Formatting Reference

Scope: Formatting -- Line Length, Non-ASCII Characters, Spaces vs. Tabs, Function
Declarations and Definitions, Lambda Expressions, Floating-point Literals, Function
Calls, Braced Initializer List Format, Looping and Branching Statements, Pointer and
Reference Expressions and Types, Boolean Expressions, Return Values, Variable and
Array Initialization, Preprocessor Directives, Class Format, Constructor Initializer
Lists, Namespace Formatting, Horizontal Whitespace, Vertical Whitespace.

Labels: `mechanical` = a formatter such as clang-format can apply the rule;
`judgment` = an author or agent must decide.

## Formatting Overview

<!-- tier: portable -->

Enforcement: judgment.

- Style is arbitrary, but a shared style is what makes code readable to everyone;
  apply these rules to the code you write and the code you edit.
- Google publishes an emacs settings file for this guide. That tooling is
  Google-internal, so other editors need their own setup.
- The guide names Clang-Format only when disabling it around unsplittable
  literals; do not assume a formatter enforces the remaining rules.

## Line Length

<!-- tier: portable -->

Enforcement: mechanical for the limit, judgment for the exceptions.

- Keep every line of code at most 80 characters long.
- The guide records the objection that 80 columns is a 1960s mainframe
  throwback; the decision stands: 80 characters maximum.
- Exceed 80 characters only for:
  - A comment that cannot be split without harming readability, ease of cut and
    paste, or auto-linking (an example command, or a literal URL longer than
    80 characters).
  - A string literal that cannot be wrapped at 80 columns: it holds URIs or
    other semantically critical pieces, an embedded language, or significant
    newlines such as in help messages.
  - An include statement.
  - A header guard.
  - A using-declaration.
- Except in test code, place unsplittable literals at namespace scope near the
  top of the file, balancing their usability and searchability against the
  readability of the code around them.
- If a tool such as Clang-Format does not recognize the unsplittable content,
  disable the tool around it.

## Non-ASCII Characters

<!-- tier: portable -->

Enforcement: judgment for whether to hard-code the text, mechanical for the
encoding.

- Keep non-ASCII characters rare and always encode them as UTF-8.
- Do not hard-code user-facing text in source, not even English.
- Non-ASCII text is appropriate when the code parses data files from foreign
  sources (hard-code the delimiters those files use) and in unit test code,
  which is not localized.
- Hex encoding is acceptable and encouraged where it improves readability:

```cpp
"\xEF\xBB\xBF"  // UTF-8 bytes for U+FEFF.
"\uFEFF"        // Unicode escape for the same character.
```

- Avoid the `u8` prefix: it yields arrays of `char8_t` rather than `char` in
  C++20 and changes again in C++23.
- Do not use `char16_t` or `char32_t`; they are for non-UTF-8 text.

### wchar_t and the Windows API

<!-- tier: platform-specific -->

- Do not use `wchar_t` except when writing code that interacts with the
  Windows API, which uses `wchar_t` extensively.

## Spaces vs. Tabs

<!-- tier: portable -->

Enforcement: mechanical.

- Use only spaces, 2 spaces per indent level; never use tabs.
- Configure the editor to emit spaces when the Tab key is pressed.

## Function Declarations and Definitions

<!-- tier: portable -->

Enforcement: judgment for the wrapping, mechanical for the spacing.

- Put the return type and the function name on the same line, and the
  parameters on that line when they fit; wrap an oversized parameter list as
  you would wrap the arguments of a function call.

```cpp
ReturnType ClassName::FunctionName(Type par_name1, Type par_name2) {
  DoSomething();
  ...
}

ReturnType ClassName::ReallyLongFunctionName(Type par_name1, Type par_name2,
                                             Type par_name3) {
  DoSomething();
  ...
}

ReturnType LongClassName::ReallyReallyReallyLongFunctionName(
    Type par_name1,  // 4 space indent
    Type par_name2,
    Type par_name3) {
  DoSomething();  // 2 space indent
  ...
}
```

- Choose good parameter names, and omit a parameter name only when the
  parameter is unused in the definition.
- If the return type and the function name do not fit on one line, break
  between them; when you break after the return type, do not indent.
- Keep the open parenthesis on the function name's line, with no space between
  the name and the parenthesis and no space between the parentheses and the
  parameters.
- Put the open curly brace at the end of the last line of the declaration, and
  the close curly brace either on the last line by itself or on the same line
  as the open brace.
- Ambiguity: the close-brace rule allows two placements; pick one and keep it
  consistent.
- Put a space between the close parenthesis and the open curly brace.
- Align all parameters if possible; indent 2 spaces by default and wrapped
  parameters 4 spaces.
- Unused parameters that are obvious from context may omit the name; unused
  parameters that might not be obvious should have the name commented out in
  the definition:

```cpp
class Foo {
 public:
  Foo(const Foo&) = delete;
  Foo& operator=(const Foo&) = delete;
};

void Circle::Rotate(double /*radians*/) {}

// Bad - if someone wants to implement later, it's not clear what the
// variable means.
void Circle::Rotate(double) {}
```

- Ambiguity: the guide both permits omitting an unused parameter name and asks
  for the name to be commented out when it is not obvious; comment it out when
  the meaning is unclear.

### Attributes

<!-- tier: portable -->

- Put attributes, and macros that expand to attributes, at the very beginning
  of the declaration or definition, before the return type:

```cpp
[[nodiscard]] bool IsOk();
```

### absl attribute macros

<!-- tier: google-internal -->

- Google code uses absl macros that expand to attributes in the same position:

```cpp
ABSL_ATTRIBUTE_NOINLINE void ExpensiveFunction();
```

- absl is Google's open-source library set, so these macros are unavailable
  outside Google projects.

## Lambda Expressions

<!-- tier: portable -->

Enforcement: mechanical.

- Format lambda parameters and bodies as for any other function, and capture
  lists like other comma-separated lists.
- For by-reference captures, leave no space between the `&` and the variable
  name.
- Short lambdas may be written inline as function arguments.

```cpp
int x = 0;
auto x_plus_n = [&x](int n) -> int { return x + n; };
```

### absl containers in the guide's example

<!-- tier: google-internal -->

```cpp
absl::flat_hash_set<int> to_remove = {7, 8, 9};
std::vector<int> digits = {3, 9, 1, 8, 4, 7, 1};
digits.erase(std::remove_if(digits.begin(), digits.end(), [&to_remove](int i) {
               return to_remove.contains(i);
             }),
             digits.end());
```

- The container types above come from absl, Google's container library;
  substitute the project's own container types elsewhere.

## Floating-point Literals

<!-- tier: portable -->

Enforcement: mechanical.

- Give every floating-point literal a radix point with digits on both sides,
  even in exponential notation.
- It is fine to initialize a floating-point variable with an integer literal
  if the type can represent that integer exactly; a number in exponential
  notation is never an integer literal.

```cpp
// Bad
float f = 1.f;
long double ld = -.5L;
double d = 1248e6;

// Good
float f = 1.0f;
float f2 = 1.0;  // Also OK
float f3 = 1;    // Also OK
long double ld = -0.5L;
double d = 1248.0e6;
```

## Function Calls

<!-- tier: portable -->

Enforcement: judgment for how to break the arguments, mechanical for the
spacing.

- Write the call on one line, wrap the arguments at the parenthesis, or start
  the arguments on a new line indented 4 spaces and continue at that indent.
  Absent other considerations, use the minimum number of lines and place
  multiple arguments per line where appropriate.
- If the arguments do not fit on one line, break them onto multiple lines with
  each subsequent line aligned with the first argument; put no space after the
  open paren or before the close paren.
- Alternatively place all arguments on subsequent lines with a four-space
  indent:

```cpp
bool result = DoSomething(argument1, argument2, argument3);

bool result = DoSomething(averyveryveryverylongargument1,
                          argument2, argument3);

bool result = DoSomething(
    argument1, argument2,  // 4 space indent
    argument3, argument4);
```

- Put multiple arguments on one line to reduce the number of lines, unless
  there is a specific readability problem; prioritize the reader over the ease
  of editing arguments.
- When multiple arguments on one line hurt readability because the expressions
  are complex or confusing, capture the argument in a descriptively named
  variable, or put the confusing argument on its own line with an explanatory
  comment:

```cpp
int my_heuristic = scores[x] * y + bases[x];
bool result = DoSomething(my_heuristic, x, y, z);

bool result = DoSomething(scores[x] * y + bases[x],  // Score heuristic.
                          x, y, z);
```

- If one argument is still significantly more readable alone, put it alone;
  make the decision specific to that argument rather than adopting a general
  policy.
- When the arguments form a structure that matters for readability, format
  them according to that structure:

```cpp
// Transform the widget by a 3x3 matrix.
my_widget.Transform(x1, x2, x3,
                    y1, y2, y3,
                    z1, z2, z3);
```

## Braced Initializer List Format

<!-- tier: portable -->

Enforcement: judgment for the wrapping, mechanical for the placement.

- Format a braced initializer list exactly as you would format a function call
  in its place.
- If the list follows a name, format it as if the `{}` were the parentheses of
  a function call with that name; with no name, assume a zero-length name.

```cpp
// Examples of braced init list on a single line.
return {foo, bar};
functioncall({foo, bar});
std::pair<int, int> p{foo, bar};

// When you have to wrap.
SomeType variable{
    some, other, values,
    {"assume a zero-length name before {"},
    SomeOtherType{
        "Very long string requiring the surrounding breaks.",
        some, other, values},
    SomeOtherType{"Slightly shorter string",
                  some, other, values}};
MyType m = {  // Here, you could also break before {.
    superlongvariablename1,
    superlongvariablename2,
    {short, interior, list},
    {interiorwrappinglist,
     interiorwrappinglist2}};
```

## Looping and Branching Statements

<!-- tier: portable -->

Enforcement: mechanical for the spacing and braces, judgment for the one-line
exception.

- A looping or branching statement has statement keywords (`if`, `else`,
  `switch`, `while`, `do`, `for`), a condition or iteration specifier in
  parentheses, and the controlled statements.
- Separate the components with single spaces, not line breaks.
- Inside the condition or iteration specifier, put one space (or a line break)
  between each semicolon and the next token, except before a closing
  parenthesis or another semicolon.
- Put no space after the opening parenthesis or before the closing parenthesis.
- Put controlled statements in blocks, that is, use curly braces; inside the
  blocks, put one line break after the opening brace and one before the closing
  brace.

```cpp
if (condition) {                   // Good - no spaces inside parentheses, space before brace.
  DoOneThing();                    // Good - two-space indent.
  DoAnotherThing();
} else if (int a = f(); a != 3) {  // Good - closing brace on new line, else on same line.
  DoAThirdThing(a);
} else {
  DoNothing();
}

// Good - the same rules apply to loops.
while (condition) {
  RepeatAThing();
}
```

```cpp
if(condition) {}                   // Bad - space missing after `if`.
else if ( condition ) {}           // Bad - space between the parentheses and the condition.
else if (condition){}              // Bad - space missing before `{`.
for (int a = f();a == 10) {}       // Bad - space missing after the semicolon.

// Bad - `if ... else` statement does not have braces everywhere.
if (condition)
  foo;
else {
  bar;
}

// Bad - `if` statement too long to omit braces.
if (condition1 &&
    condition2)
  DoSomething();
```

- For historical reasons the braces, or the line breaks inside them, may be
  omitted when the whole statement ends up on one line (a space between the
  closing parenthesis and the controlled statement) or on two lines (a line
  break after the closing parenthesis and no braces). This exception is allowed
  but discouraged, and it does not apply to multi-keyword statements such as
  `if ... else` or `do ... while`.

```cpp
// OK - each case fits on one line.
if (x == kFoo) { return new Foo(); }
while (TrySomething()) {}

// OK - braces are optional in this case.
if (x == kFoo) return new Foo();

// OK - condition fits on one line, body fits on another.
if (x == kBar)
  Bar(arg1, arg2, arg3);
```

- Use the omitted-brace style only when the statement is brief; complex
  conditions or bodies are usually more readable with curly braces. Some
  projects require curly braces always.
- Give `case` blocks in `switch` statements curly braces or not, as you prefer;
  if you include them, place them as shown.
- Write an empty loop body as an empty pair of braces or as `continue` with no
  braces, never as a lone semicolon; empty braces still follow the general line
  breaking rules and the historic exception.

```cpp
switch (var) {
  case 0: {  // 2 space indent
    Foo();   // 4 space indent
    break;
  }
  default: {
    Bar();
  }
}

while (condition) {  // Good - `{}` indicates no logic.
}                    // A linebreak is usually required.

while (condition) {}  // But OK if it fits on one line.

while (condition) continue;  // Good - `continue` indicates no logic.

while (condition);  // Bad - looks like part of `do-while` loop.
```

## Pointer and Reference Expressions and Types

<!-- tier: portable -->

Enforcement: mechanical.

- Put no spaces around the period or arrow operator, and give pointer
  operators no trailing space.
- In declarations and definitions, arguments, return types, and template
  parameters, never put a space before the asterisk or ampersand; use a space
  to separate the type from the declared name, if a name is present.
- It is allowed, if unusual, to declare multiple variables in one declaration,
  but it is disallowed if any of them carry a pointer or reference decoration.

```cpp
x = *p;
p = &x;
x = r.y;
x = r->y;

// These are fine.
char* c;
const std::string& str;
int* GetPointer();
std::vector<char*>  // Note no space between '*' and '>'
```

```cpp
// Fine if helpful for readability.
int x, y;

int x, *y;  // Disallowed - no & or * in multiple declaration
int *x, *y;  // Disallowed - no & or * in multiple declaration
int *x;  // Disallowed - & or * must be left of the space
char * c;  // Bad - spaces on both sides of *
const std::string & str;  // Bad - spaces on both sides of &
```

## Boolean Expressions

<!-- tier: portable -->

Enforcement: judgment.

- Break a boolean expression that is longer than the standard line length
  consistently.
- Prefer the logical AND operator at the end of the line; wrapping all
  operators at the beginning of the line is also allowed, so keep the choice
  consistent within the expression.
- Insert extra parentheses judiciously; they often help readability, but
  overuse them.
- Use the punctuation operators (`&&`, `~`) rather than the word operators
  (`and`, `compl`).

```cpp
if (this_one_thing > this_other_thing &&
    a_third_thing == a_fourth_thing &&
    yet_another && last_one) {
  ...
}
```

## Return Values

<!-- tier: portable -->

Enforcement: mechanical.

- Do not needlessly surround the return expression with parentheses; use
  parentheses in a return expression only where you would use them in an
  assignment `x = expr;`.

```cpp
return result;                  // No parentheses in the simple case.
// Parentheses OK to make a complex expression more readable.
return (some_long_condition &&
        another_condition);

return (value);                // You wouldn't write var = (value);
return(result);                // return is not a function!
```

## Variable and Array Initialization

<!-- tier: portable -->

Enforcement: mechanical.

- Choose between `=`, `()`, and `{}`; all three of these are correct.
- Be careful with a braced initialization list on a type that has an
  `std::initializer_list` constructor: a nonempty braced-init-list prefers
  the `std::initializer_list` constructor whenever possible, while empty
  braces `{}` are special and call the default constructor if one is
  available. Use parentheses instead of braces to force the
  non-`std::initializer_list` constructor.
- The brace form prevents narrowing of integral types, which can prevent some
  classes of programming errors.

```cpp
int x = 3;
int x(3);
int x{3};
std::string name = "Some Name";
std::string name("Some Name");
std::string name{"Some Name"};

std::vector<int> v(100, 1);  // A vector containing 100 items: All 1s.
std::vector<int> v{100, 1};  // A vector containing 2 items: 100 and 1.

int pi(3.14);  // OK -- pi == 3.
int pi{3.14};  // Compile error: narrowing conversion.
```

## Preprocessor Directives

<!-- tier: portable -->

Enforcement: mechanical.

- Always start the hash mark of a preprocessor directive at the beginning of
  the line, even when the directive sits inside indented code.

```cpp
// Good - directives at beginning of line
  if (lopsided_score) {
#if DISASTER_PENDING      // Correct -- Starts at beginning of line
    DropEverything();
# if NOTIFY               // OK but not required -- Spaces after #
    NotifyClient();
# endif
#endif
    BackToNormal();
  }

// Bad - indented directives
  if (lopsided_score) {
    #if DISASTER_PENDING  // Wrong!  The "#if" should be at beginning of line
    DropEverything();
    #endif                // Wrong!  Do not indent "#endif"
    BackToNormal();
  }
```

## Class Format

<!-- tier: portable -->

Enforcement: mechanical for the layout, judgment for the base-class
placement.

- Order the sections `public`, `protected`, `private`, indenting each one
  space.
- Keep any base class name on the same line as the subclass name, subject to
  the 80-column limit.
- Indent the `public:`, `protected:`, and `private:` keywords by one space.
- Except for the first instance, precede these keywords with a blank line;
  this rule is optional in small classes.
- Do not leave a blank line after these keywords.
- Put the `public` section first, then `protected`, then `private`, and order
  the declarations inside each section according to the guide's Declaration
  Order section.

```cpp
class MyClass : public OtherClass {
 public:      // Note the 1 space indent!
  MyClass();  // Regular 2 space indent.
  explicit MyClass(int var);
  MyClass(const MyClass& other);
  MyClass& operator=(const MyClass& other);
  ~MyClass() {}

  void SomeFunction();
  void SomeFunctionThatDoesNothing() {}

  void set_some_var(int var) { some_var_ = var; }
  int some_var() const { return some_var_; }

 private:
  bool SomeInternalFunction();

  int some_var_;
  int some_other_var_;
};
```

## Constructor Initializer Lists

<!-- tier: portable -->

Enforcement: judgment.

- Put a constructor initializer list on one line, or indent subsequent lines
  four spaces.
- If the signature and the initializer list do not fit on one line, wrap before
  the colon and indent 4 spaces; when the list spans multiple lines, put each
  member on its own line and align them.
- As with any other code block, the close curly can be on the same line as the
  open curly, if it fits.

```cpp
// When everything fits on one line:
MyClass::MyClass(int var) : some_var_(var) {
  DoSomething();
}

// If the signature and initializer list are not all on one line,
// you must wrap before the colon and indent 4 spaces:
MyClass::MyClass(int var)
    : some_var_(var), some_other_var_(var + 1) {
  DoSomething();
}

// When the list spans multiple lines, put each member on its own line
// and align them:
MyClass::MyClass(int var)
    : some_var_(var),             // 4 space indent
      some_other_var_(var + 1) {  // lined up
  DoSomething();
}
```

## Namespace Formatting

<!-- tier: portable -->

Enforcement: mechanical.

- Do not indent the contents of a namespace; a namespace adds no level of
  indentation.

```cpp
namespace {

void foo() {  // Correct.  No extra indentation within namespace.
  ...
}

}  // namespace

namespace {

  // Wrong!  Indented when it should not be.
  void foo() {
    ...
  }

}  // namespace
```

## Horizontal Whitespace

<!-- tier: portable -->

Enforcement: mechanical.

- Never leave trailing whitespace at the end of a line. Do not introduce it;
  if you are already changing a line, remove its trailing whitespace, or do
  the removal in a separate clean-up operation, preferably when nobody else is
  working on the file.

### General

<!-- tier: portable -->

- Put two spaces before an end-of-line comment, a space before an open brace,
  and no space before a semicolon.
- Braces of a braced-init-list may have inner spaces, but put them on both
  sides or on neither.
- Put spaces around the colon in inheritance and initializer lists, but no
  spaces inside empty braces; for inline function implementations, put spaces
  between the braces and the implementation.

```cpp
int i = 0;  // Two spaces before end-of-line comments.
void f(bool b) {  // Open braces should always have a space before them.
  ...
int i = 0;  // Semicolons usually have no space before them.
int x[] = { 0 };
int x[] = {0};  // Spaces inside braces for braced-init-list are optional.
class Foo : public Bar {
 public:
  Foo(int b) : Bar(), baz_(b) {}  // No spaces inside empty braces.
  void Reset() { baz_ = 0; }  // Spaces separating braces from implementation.
}
```

### Loops and Conditionals

<!-- tier: portable -->

- Put a space after the keyword in conditions and loops, spaces around `else`,
  and usually no space inside parentheses; spaces inside parentheses are rare,
  so be consistent.
- Put a space after the semicolon in a `for` loop; a space before it is rare.
  Put a space before and after the colon of a range-based `for`.
- Put no space before the colon of a `switch` case, and a space after the colon
  when code follows it.

```cpp
if (b) {          // Space after the keyword in conditions and loops.
} else {          // Spaces around else.
}
while (test) {}   // There is usually no space inside parentheses.
for (int i = 0; i < 5; ++i) {
for (auto x : counts) {  // Range-based for: space before and after the colon.
}
switch (i) {
  case 1:         // No space before colon in a switch case.
    ...
  case 2: break;  // Use a space after a colon if there's code after it.
}
```

### Operators

<!-- tier: portable -->

- Put spaces around assignment operators, and usually around other binary
  operators; parentheses have no internal padding. Put no space between a
  unary operator and its argument.

```cpp
x = 0;            // Assignment operators always have spaces around them.
v = w * x + y / z;
v = w*x + y/z;    // Removing spaces around factors is OK.
v = w * (x + z);  // Parentheses should have no internal padding.
x = -5;           // No spaces separating unary operators and their arguments.
++x;
```

### Templates and Casts

<!-- tier: portable -->

- Put no spaces inside angle brackets, before `<`, or between `>` and `(` in a
  cast, and no space between a type and a pointer.

```cpp
std::vector<std::string> x;  // No spaces inside the angle brackets.
y = static_cast<char*>(x);   // No spaces between type and pointer.
```

## Vertical Whitespace

<!-- tier: portable -->

Enforcement: judgment.

- Use vertical whitespace sparingly; unnecessary blank lines make the overall
  code structure harder to see. Use blank lines only where they help the
  reader understand the structure.
- Do not add blank lines where indentation already delineates the code
  clearly, such as at the start or end of a code block.
- Do use blank lines to separate code into closely related chunks, analogous to
  paragraph breaks in prose.
- Within a statement or declaration, usually insert line breaks only to stay
  within the line length limit, or to attach a comment to part of the contents.

---
Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Formatting, Line Length, Non-ASCII Characters, Spaces vs. Tabs, Function Declarations and Definitions, Lambda Expressions, Floating-point Literals, Function Calls, Braced Initializer List Format, Looping and Branching Statements, Pointer and Reference Expressions and Types, Boolean Expressions, Return Values, Variable and Array Initialization, Preprocessor Directives, Class Format, Constructor Initializer Lists, Namespace Formatting, Horizontal Whitespace, Vertical Whitespace)
