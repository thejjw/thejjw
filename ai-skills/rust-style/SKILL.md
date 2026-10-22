---
name: rust-style
description: Write, review, and refactor Rust following the Google Rust Style Guide — ownership and borrowing, API design, traits, imports and naming, error handling, public-API stability, and unsafe code. Use whenever Rust code is written, reviewed, debugged, or refactored (any .rs file, Cargo.toml, crate, or Rust project), and whenever the user mentions Rust, cargo, rustc, clippy, or rustfmt, even if they do not ask for idiomatic code.
metadata:
  audience: agents
  auth: none
---

# Idiomatic Rust: The Google Rust Way

Rust conventions that hold up under review, refactoring, and automation. Derived
from the Google Rust Style Guide, which covers API and implementation design --
not just formatting.

## When to Activate

- Writing new Rust code, functions, types, or modules
- Reviewing or auditing existing Rust code
- Refactoring Rust that looks like it was ported from another language
- Designing a crate's public API (signatures, traits, error types)
- Choosing between borrowing and cloning, or between `Vec` and an iterator
- Deciding on module layout, `use` statements, and naming
- Adding `unsafe`, deciding on `#[non_exhaustive]`, or designing error handling
- Reviewing for the anti-patterns agents most often generate

## The Library vs. Application Split

Every API-design rule below is interpreted through this distinction. Decide which
side of the line the code is on before applying any of them.

| | Library code | Application code |
|---|---|---|
| Audience | Other projects (apps or other libraries) | A single application |
| Problem | Relatively general | Specific |
| API-design rules | Binding | Strong recommendation |
| Bias | Flexibility, performance, future-proofing | Simplicity and directness |

Application code should favor what the immediate need requires. Avoid premature
generalization, speculative traits, and abstraction for its own sake.

## Core Principles

### 1. Ownership over sharing

Rust can express object graphs without shared-ownership pointers. Reach for
`Rc`/`Arc` only when the alternative ownership structure is unreasonably
complex to write, read, or maintain -- and say so in review.

```rust
// Idiomatic: borrow the data.
fn first_word(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or_default()
}

// Avoid: shared ownership by default.
fn first_word(text: Arc<String>) -> Option<String> {
    text.split_whitespace().next().map(str::to_owned)
}
```

### 2. Borrow before you clone

`.clone()` is a deep copy. Use it when you genuinely need an independent copy,
not as a way around the borrow checker. If the borrowing relationships become
excessively complex, a clone is a pragmatic choice -- but a deliberate one.

```rust
// Idiomatic: borrow.
fn len_of(text: &str) -> usize {
    text.len()
}

// Avoid: clone to escape a borrow that could be restructured.
fn len_of(text: &String) -> usize {
    text.clone().len()
}
```

### 3. Accept the most flexible reference you can

Function parameters should accept borrowed data in a form that does not force
the caller into a particular container.

| Accept | Instead of | Why |
|---|---|---|
| `&T` | `&Box<T>` | Borrow the data inside the box |
| `&[T]` | `&Vec<T>` | Accept any slice, not one container |
| `&str` | `&String` | Accept a string slice, not an owned string |
| `Option<&T>` | `&Option<T>` | Borrow the data inside the Option |

Exception: non-linear character data such as `Rope`/`Cord`, where the rope *is*
the representation.

### 4. Choose the error mechanism deliberately

| Situation | Use | Example |
|---|---|---|
| Failure is obvious, caller needs no detail | `Option` | `checked_add(a, b) -> Option<u32>` |
| Failure is recoverable, caller needs to branch on the cause | `Result` | `open_file(path) -> Result<File, io::Error>` |
| An invariant was violated -- this is a bug | `panic!` | index out of bounds in `Vec::remove` |

`panic!` is for defects, not for anticipated outcomes. Panics are not a
recoverable error channel: `catch_unwind` does not work under `panic=abort`
(Chrome, Android, Fuchsia), and it is prohibited in first-party code anyway.

### 5. Make illegal states unrepresentable

```rust
// Idiomatic: the compiler enforces the choice.
enum SortOrder {
    Ascending,
    Descending,
}

fn sort(items: &mut [Item], order: SortOrder) {
    // ...
}

// Avoid: `true` meaning "descending" is a comment, not a type.
fn sort(items: &mut [Item], reverse: bool) {
    // ...
}
```

Use `bool` only when the meaning is self-evident. Otherwise use an enum, or
document the flag inline at the call site.

### 6. Use newtypes when types must not be confused

```rust
// Idiomatic: Celsius and Fahrenheit cannot be mixed up.
struct Celsius(f64);
struct Fahrenheit(f64);
```

A type alias (`type Celsius = f64;`) creates no new type -- it only renames one.
Prefer a newtype when the type has notable semantics, deserves its own API,
may change its representation later, or is easy to mix up with a sibling.

Prefer named fields over tuple structs for anything with more than one field;
`.0`/`.1` stop being readable immediately.

### 7. A public API is a long-term contract

Mark publicly exposed enums `#[non_exhaustive]` so adding a variant later is
not a breaking change, and so downstream `match` statements must keep a
wildcard arm. The same applies to public structs with public fields.

```rust
// Idiomatic: callers must handle future variants.
#[non_exhaustive]
pub enum Shape {
    Circle,
    Square,
    Triangle,
}
```

Exception: enums describing an existing ontology (`Color`), two-state enums
that could be `bool`, or a team committed to fixing breakages in one sweep.

### 8. Write code that automation can rewrite

Google runs Large-Scale Changes (LSCs) across entire codebases. Consistency is
what makes those refactorings possible.

- One module per `use` statement (`imports_granularity = Module`)
- No glob imports
- Types referenced unqualified (`Regex`, not `regex::Regex`)
- Top-level functions called as `module::function()`

## Code Organization and Imports

- **Name source files and leaf modules after the primary item**: `Foo` lives in
  `foo.rs` / `mod foo`.
- **Leaf modules hold the implementation.** A non-leaf module should contain
  only `mod` declarations and `re-exports`, not definitions.
- **No glob imports.** Allowed only in narrow cases: `use super::*` inside an
  inline module, `use enum::*` in that enum's own methods, and
  `pub use submodule::*` in a non-leaf module. Do not define preludes.
- **One module per `use` statement.** No `::` inside the `{ .. }` block:

  ```rust
  // Idiomatic
  use foo::Foo;
  use foo::bar::{Bar, Baz};

  // Avoid
  use foo::{Foo, bar::Bar};
  ```

- **Import traits locally**, inside the function body, unless the trait's
  methods are used throughout the file.
- **Qualify top-level function calls with the module name**: `mem::transmute(y)`.
  Unqualified lowercase names are assumed local, so `foo()` should mean "from
  this module".
- **Types and traits are used unqualified**: `use regex::Regex;` then `Regex`.
  Qualify only to resolve an ambiguity (`io::Error`), or when a large group of
  types shares one module (such as `rustc_hir`).

### Formatting

Use rustfmt (`cargo fmt`, or `git cl format` in Chromium). Google-specific
settings: `max_width = 100`, lowercase hex literals, formatted macro matchers.

`#[rustfmt::skip]` is allowed only for manual alignment of related lines or
for generated code -- never for personal style preference.

## Ownership and Borrowing

- Prefer unique ownership and borrowing over `Rc`/`Arc`.
- Clone only for genuine deep copies. Cloning an `Rc`/`Arc` pointer is a
  refcount bump, not a deep copy, and is an expected way to share.
- Do not reach inside a poisoned mutex, however tempting the use case looks.

## Function Inputs and Outputs

- **Return iterators** (`impl Iterator` or a concrete iterator) rather than
  `Vec<T>` in library code. In application code, returning `Vec<T>` is fine
  when it simplifies the code and flexibility/performance gains are not
  clearly needed.
- **Accept iterators or `impl IntoIterator`** instead of slices in library code
  when the function only needs to iterate. Application code may accept `&[T]`.
- **Accept `impl Into<T>`** in library APIs when call-site ergonomics dominate;
  balance it against code bloat. Application code should almost never use
  `impl Into<T>` parameters.
- **Pair an important `From` impl with an explicit constructor**: `new()`,
  `new_with_foo()`, or `from_foo()`.

### Accessor naming

| Method | Meaning |
|---|---|
| `foo()` | Getter returning `T` by value |
| `foo_mut()` | Getter returning `&mut T` |
| `take_foo()` | Clears the value (to `None` or a default) and returns the old value |
| `set_foo()` | Setter taking `T` by value |
| `with_foo()` / `with_mut_foo()` | Closure accessor: `object.with_foo(\|foo\| frob(foo))` |
| `replace_foo()` | Setter that returns the old value |

Closure accessors are the right choice when the field sits behind interior
mutability (`Mutex`, `RefCell`), or when a setter would require an expensive
clone.

## Types

- Newtype over type alias for semantically distinct, API-worthy, or
  confusable types.
- Named fields over tuples (except newtype tuple structs and very local
  contexts).
- Derive what you can: prefer `#[derive(...)]` over a hand-written impl.

## Traits

- Implement the standard-library trait when one matches the method's purpose
  and behavior -- `impl FromStr` rather than a custom `fn from_str`.
- Define a trait only to enable generic programming, to accept/return
  `impl Trait` or `dyn Trait`, or to define an extension trait. Do not define
  traits to organize code.
- **Prefer generics over `dyn Trait`** in library parameters, except where code
  size matters.
- **Extension traits** add methods to a type from another crate. Name them with
  an `~Ext` suffix (`ForeignTypeExt`), and let the team that owns the original
  type own the extension trait.
- Low-level library code should anticipate trait impls users will need;
  application code adds them as needed.

Per-trait guidance:

| Trait | Guidance |
|---|---|
| `Copy` | Implement when it is reasonably clear the type will stay `Copy` |
| `Clone` | Most types should implement it, unless they represent an external resource |
| `Default` | Implement when the type has a `new()` or a default state |
| `PartialEq` | Prefer over `Eq` when `==` is the only need |
| `PartialOrd` | Prefer over `Ord` when `<`/`>` is the only need |
| `Hash` + `Eq` | Implement for types likely used as map keys or cached |
| `Ord` | Implement when the type has a clear total ordering |

Options structs (all-public fields used as a bag of options) should implement
`Default` so callers can use struct-update syntax.

## Concurrency

- Never reach into a poisoned mutex.
- `catch_unwind` is prohibited in first-party Rust code. It only works under
  `panic=unwind`, and Chrome, Android, and Fuchsia all require `panic=abort`.
  (Defense-in-depth use is acceptable only where `panic=unwind` is in play and
  the result is never relied upon.)
- Platform-specific rules, marked as such: Chrome does not use `async`/`.await`
  or `std` thread spawning; Fuchsia uses `fuchsia_sync::Mutex`.

## Naming

- Follow the standard library's method naming. Use `as_`/`to_`/`into_` prefixes
  for conversions with the matching `self` convention.
- Lifetimes get descriptive names. Single-letter lifetimes are fine only for a
  simple input-to-output relation or a local higher-ranked bound; more than
  two such local lifetimes calls for real names.
- Generic parameters get a short name hinting at the kind of thing they
  represent, ideally derived from the primary trait bound. `T`/`U` are fine in
  unbound APIs like `Vec<T>`.
- Constructors: `new()`, `new_with_foo()`, or `try_new()` when it returns a
  `Result`. Conversions: `from_foo()` paired with a `From` impl.
- Avoid abbreviations and initialisms that someone outside the project is
  unlikely to know. Do not abbreviate by deleting letters inside a word.

## Documentation

- Document public APIs. Add examples where they earn their place, and always
  document panic conditions.
- Document invariants for `unsafe` functions and traits.
- Do not restate the code. `/// Removes an element.` on `pub fn remove_element`
  adds nothing -- omit it instead.
- `///` documents the item below it; `//!` documents the module or crate and
  belongs at the top of the file. Use `//` for implementation comments, TODOs,
  and commented-out code.
- Comments should explain *why*, not *what*. Use Markdown in doc comments, and
  prefer hand-written doc comments over macro-generated ones.

```rust
/// Finds the first `FooItem` with the given `name`, or `None` if not present.
// TODO(crbug.com/12345) - `name` should be `&str`, not `String`.
pub fn get_named(items: &[FooItem], name: String) -> Option<&FooItem> {
    // ...
}
```

## Unsafe and Unstable Features

- Do not write `unsafe` unless there is no safe way to do the same thing.
- Encapsulate `unsafe` in a safe abstraction, isolated from business logic --
  ideally in its own crate with few dependencies.
- Every `unsafe` block needs a `SAFETY:` comment explaining why the code is
  correct, plus a technical justification: why there is no equivalent safe
  implementation, and benchmarks if the reason is performance.
- Do not use unstable features. Platform exceptions exist (Android Embedded
  may require them; Chrome may blanket-approve a short list with a clear path
  to stabilization).

## Public API Stability

- `#[non_exhaustive]` on publicly exposed enums and on public structs with
  public fields (see Core Principles).
- `#[must_use]` on functions whose result cannot be ignored -- pure functions,
  and any function returning an error or critical information. If the return
  type is already `#[must_use]` (as `Result` is), the function needs no
  annotation.
- `#[must_use]` on types meant to be returned by such functions: error types,
  or lazily evaluated computations.
- Implement `len()` together with `is_empty()`.
- Treat `#[doc(hidden)]` items as private. Do not access them unless you own
  the code.
- Mark a public function `const` only if you expect it to stay `const`;
  removing `const` later is a breaking change.
- Do not run code before `main()` (no `ctor`-style constructors).
- Avoid operator overloading for non-mathematical purposes.

## Implementation Details

- **Do not overuse type inference.** Add explicit types where a reader cannot
  infer them -- the result of `.into()`, `.parse()`, or a long iterator chain.
  Annotate the variable declaration, not a turbofish; use `_` if the compiler
  forces a turbofish.
- **Prefer pattern matching over check-then-unwrap.** `if let Some(v) = opt`
  proves to the compiler that a panic is impossible; `if opt.is_some() { opt.unwrap() }`
  proves nothing.
- **Prefer `expect` over `unwrap`.** `expect` documents why the panic cannot
  happen; `unwrap` leaves the reader guessing.
- **Do not omit patterns when matching `#[non_exhaustive]` enums.** List the
  variants you care about; put the rest in the wildcard arm, or use `if let` /
  `let ... else {}` when only one variant matters.
- **Give assertions context.** Use the format-string argument of `assert!` to
  say why the assertion should hold and what its failure means -- especially
  when you would otherwise add a comment, or when users will see the failure.
- **Keep iterator chains readable.** Do not build long chains with conditionals
  and side effects, do not construct a chain in a `for` loop header (bind it to
  a variable first), and prefer a `for` loop over `.for_each()`. Short chains
  like `.iter().any(...)` are better than the equivalent loop.
- **Prefer `format!`/`write!`** for concatenating more than two strings and
  for substituting into a literal.

```rust
// Avoid: check-then-unwrap.
if option.is_some() {
    use_value(option.unwrap());
}

// Idiomatic: the match arm proves the panic cannot happen.
if let Some(value) = option {
    use_value(value);
}
```

```rust
// Idiomatic: the assertion explains itself in the failure log.
assert!(
    values.is_sorted(),
    "`values` is populated from a `PriorityQueue`, so we expect it to be sorted"
);
```

## Anti-Patterns Agents Commonly Generate

Watch for these specifically -- they are the usual review findings:

- `.unwrap()` everywhere instead of `expect` with a reason, or `Result`
  propagation with `?`
- `&String`, `&Vec<T>`, or `&Option<T>` parameters
- `Rc`/`Arc` reflexively for any shared data
- `.clone()` used to silence a borrow-checker error
- `bool` parameters whose meaning is only in a comment
- Glob imports (`use foo::*`)
- `use foo::{Bar, baz::Baz}` mixing modules in one statement
- `catch_unwind` for error recovery
- `unwrap()` after `is_some()`/`is_ok()`
- Long iterator chains with side effects, or chains built inside `for` headers
- Public enums and public-field structs without `#[non_exhaustive]`
- `type` aliases where a newtype was needed to prevent mixing units

## Clippy Lint Map

Run `cargo clippy --all-targets --all-features -- -D warnings` and treat these
lints as the machine-checkable form of the rules above.

| Rule | Lint |
|---|---|
| `&Vec<T>` / `&String` parameter | `ptr_arg` |
| `&Box<T>` parameter | `borrowed_box` |
| Custom method that duplicates a std trait | `should_implement_trait` |
| `new()` without `Default` | `new_without_default` |
| `len()` without `is_empty()` | `len_without_is_empty` |
| Public enum missing `#[non_exhaustive]` | `exhaustive_enums` |
| Wrong `as_`/`to_`/`into_` self convention | `wrong_self_convention` |
| Missing match arm on `#[non_exhaustive]` enum | `non_exhaustive_omitted_patterns` (rustc) |

Use `#[expect(lint)]` over `#[allow(lint)]`, with a justification comment.
(This comes from the Apollo handbook, not the Google guide -- see
[Sources and Maintenance](#sources-and-maintenance).)

## When to use me

- The user asks for idiomatic Rust, or asks why Rust code is written a certain way
- The user is writing, reviewing, or refactoring `.rs` files or `Cargo.toml`
- The user mentions Rust, cargo, rustc, clippy, or rustfmt
- An API is being designed and signatures, traits, or error types are in question
- Borrowing vs. cloning, iterator vs. `Vec`, or generics vs. `dyn Trait` need a call
- Code under review contains one of the anti-patterns above

## Limitations

- This skill encodes Google's conventions, not a universal Rust standard. Where
  they conflict with the official Rust style guide, the official guide wins
  unless the Google guide says otherwise.
- Platform-specific rules (Chrome, Fuchsia, Chromium build layout) are marked
  inline and are not general advice.
- It does not pin toolchain versions, dependency choices, or a crate layout for
  your repository; those follow your project's own conventions.
- It does not replace the compiler, `rustc` lints, or clippy.

## Sources and Maintenance

**Original resource.** This skill is derived from the Google Rust Style Guide:
<https://google.github.io/styleguide/rustguide.html>
(upstream source: `google/styleguide`, file `rustguide.md`).

The guide's stated goals, which explain why a rule exists when the rule alone
looks arbitrary:

- Prioritize readability and maintainability over writeability.
- Favor better automation -- consistency makes Large-Scale Changes possible.
- Stay consistent with the wider Rust ecosystem where possible.
- Every rule must pull its weight.
- Rules should settle minor disagreements instead of reopening them.

The guide also defers to the official Rust style guide and the Rust API
guidelines wherever they do not conflict, and splits API-design rules into
binding rules for library code and recommendations for application code.

**Related Rust guides to check when extending or correcting this skill:**

- Official Rust Style Guide -- <https://doc.rust-lang.org/nightly/style-guide/>
- Rust Style Guide editions (style changes per Rust version) --
  <https://doc.rust-lang.org/style-guide/editions.html>
- Rust API Guidelines -- <https://rust-lang.github.io/api-guidelines/>
- Clippy lint index -- <https://rust-lang.github.io/rust-clippy/master/index.html>
- rustfmt configuration -- <https://rust-lang.github.io/rustfmt/>
- Comprehensive Rust (naming conventions, API design) --
  <https://google.github.io/comprehensive-rust/>

**Sibling skills.**

- `spf13/go-skills` -> `go` -- the structural template for this file (shape,
  activation triggers, anti-pattern sections, toolchain guidance).
  <https://github.com/spf13/go-skills>
- `apollographql/skills` -> `rust-best-practices` -- installed separately by
  `Install-AiSkills`. It covers the Apollo Rust Best Practices handbook
  (idioms, clippy, error handling, testing, type state) with per-chapter
  reference files; this skill covers Google's API-design and ownership rules.
  The names are deliberately distinct so the installer does not overwrite
  either one. <https://github.com/apollographql/skills>

**How to update this skill.**

1. Re-read the original guide and diff it against the sections above; the
   guide's own table of contents is the checklist.
2. Keep the "Library vs. Application Split" framing -- many rules change
   meaning without it.
3. Update the Clippy lint map when lints are renamed or added, and verify
   lint names against the Clippy index.
4. Refresh the `Checked against` stamp below.
5. Preserve the naming rule of the source: `use` one module per statement, no
   glob imports, types unqualified. The skill should model the style it
   describes.

Checked against: 2026-10-22 (Google Rust Style Guide as published on that date).
