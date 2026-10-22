# Comments and Inclusive Language

Scope: Comments (Comment Style, File Comments, Legal Notice and Author Line, Struct and Class Comments, Class Comments, Function Comments, Function Declarations, Function Definitions, Variable Comments, Class Data Members, Global Variables, Implementation Comments, Explanatory Comments, Function Argument Comments, Don'ts, Punctuation Spelling and Grammar, TODO Comments) and Inclusive Language.

## Comments
<!-- tier: portable -->
Treat comments as vital to readability, but prefer self-documenting code: name types and variables
sensibly instead of explaining obscure names. Write for the next contributor.
## Comment Style
<!-- tier: portable -->
Use either `//` or `/* */` syntax, as long as you are consistent. `//` is much more common, so
prefer it for everything and reserve block comments for rare cases.
## File Comments
### Start each file with license boilerplate
<!-- tier: portable -->
Start each file with license boilerplate.

### Describe the collection of abstractions in a header
<!-- tier: portable -->
When a source file (such as a `.h` file) declares multiple user-facing abstractions, include a
comment describing the collection, detailed enough for future authors to know what does not fit.
### Put the file comment on the file that owns the abstractions
<!-- tier: portable -->
Do not repeat the file comment in `frobber.cc` or `frobber_test.cc` when `frobber.h` carries it.
Do include one in `registered_objects.cc` when it holds classes with no associated header file.
## Legal Notice and Author Line
<!-- tier: portable -->
Include license boilerplate in every file, using the boilerplate for the project's license
(Apache 2.0, BSD, LGPL, GPL, and so on). When you make significant changes to a file with an
author line, consider deleting it. New files carry no author line.
## Struct and Class Comments
<!-- tier: portable -->
Give every non-obvious class or struct declaration an accompanying comment describing what it is
for and how it should be used.

```cpp
// Iterates over the contents of a GargantuanTable.
// Example:
//    std::unique_ptr<GargantuanTableIterator> iter = table->NewIterator();
//    for (iter->Seek("foo"); !iter->done(); iter->Next()) {
//      process(iter->key(), iter->value());
//    }
class GargantuanTableIterator {
  ...
};
```
## Class Comments
<!-- tier: portable -->
Give the reader enough information to know how and when to use the class, plus any considerations
needed to use it correctly. Document the synchronization assumptions the class makes, if any.
### Split interface and implementation comments
<!-- tier: portable -->
A class comment is often a good place for a small usage example. When sufficiently separated
(e.g., `.h` and `.cc` files), put use comments with the interface and operation comments with
the implementation.
## Function Comments
<!-- tier: portable -->
Declaration comments describe use of the function (when it is non-obvious); comments at the
definition of a function describe operation.
## Function Declarations
<!-- tier: portable -->
Comment almost every function declaration immediately before it, describing what the function does
and how to use it. Omit only for simple, obvious functions. Private methods and `.cc` file
functions are not exempt.
### Subject and scope of the comment
<!-- tier: portable -->
Write an implied subject of "This function" and start with the verb phrase: "Opens the file", not
"Open the file". Leave how the task is performed to the definition.
### Required facts to mention
<!-- tier: portable -->
Mention, in the comment at the function declaration:

- What the inputs and outputs are. Put argument names in `backticks` so code-indexing tools can
  present the documentation better.
- For class member functions: whether the object remembers reference or pointer arguments beyond the
  call. This is common for pointer/reference arguments to constructors.
- For each pointer argument: whether it may be null, and for each nullable one, how a null input
  is handled.
- For each output or input/output argument: what happens to the state it is in (e.g., appended to
  or overwritten?).
- Any performance implications of using the function.

```cpp
// Returns an iterator for this table, positioned at the first entry
// lexically greater than or equal to `start_word`. If there is no
// such entry, returns a null pointer. The client must not use the
// iterator after the underlying GargantuanTable has been destroyed.
//
// This method is equivalent to:
//    std::unique_ptr<Iterator> iter = table->NewIterator();
//    iter->Seek(start_word);
//    return iter;
std::unique_ptr<Iterator> GetIterator(absl::string_view start_word) const;
```
### `absl::string_view` in the guide example
<!-- tier: google-internal -->
The example above uses `absl::string_view`, a Google-internal type. Use the project's standard
string view type outside Google code; the comment rules themselves are unchanged.
### Document overrides, constructors, and destructors on their own terms
<!-- tier: portable -->
When documenting overrides, focus on the specifics of the override rather than repeating the
overridden function's comment; many need no comment at all. The reader already knows what
constructors and destructors are for, so document what constructors do with their arguments.
## Function Definitions
<!-- tier: portable -->
Explain anything tricky about how the function does its job at the definition: coding tricks, an
overview of the steps, or why you chose this implementation over a viable alternative.
## Variable Comments
<!-- tier: portable -->
Name variables descriptively enough to show what they are used for. In certain cases, more
comments are required.
## Class Data Members
<!-- tier: portable -->
Make the purpose of each class data member (instance variable, member variable) clear. Comment
invariants (special values, relationships between members, lifetime requirements) not expressed by
the type and name; if type and name suffice (`int num_events_;`), no comment is needed.

```cpp
private:
  // Used to bounds-check table accesses. -1 means
  // that we don't yet know how many entries the table has.
  int num_total_entries_;
```
## Global Variables
<!-- tier: portable -->
Comment every global variable, describing what it is, what it is used for, and (if unclear) why it
needs to be global.

```cpp
// The total number of test cases that we run through in this regression test.
const int kNumTestCases = 6;
```
## Implementation Comments
<!-- tier: portable -->
Comment the tricky, non-obvious, interesting, or important parts of your implementation.
## Explanatory Comments
<!-- tier: portable -->
Put a comment before tricky or complicated code blocks.
## Function Argument Comments
<!-- tier: portable -->
When the meaning of a function argument is nonobvious, consider one of these remedies:

- Use a named constant when the argument is a literal constant used in multiple calls in a way
  that tacitly assumes they are the same, making the constraint explicit.
- Replace a `bool` argument with an `enum` argument, so the values are self-describing.
- For several configuration options, define a single class or struct to hold all the options and
  pass an instance of it. Options are then referenced by name at the call site, the argument count
  shrinks, and adding an option does not require changing call sites.
- Replace large or complex nested expressions with named variables.
- As a last resort, comment argument meanings at the call site.

```cpp
// What are these arguments?
const DecimalNumber product = CalculateProduct(values, 7, false, nullptr);

// Versus:
ProductOptions options;
options.set_precision_decimals(7);
options.set_use_cache(ProductOptions::kDontUseCache);
const DecimalNumber product =
    CalculateProduct(values, options, /*completion_callback=*/nullptr);
```
## Don'ts
<!-- tier: portable -->
Do not literally describe what code does, unless the behavior is nonobvious to a reader who
understands C++ well. Provide higher-level comments describing why, or make the code
self-describing.

```cpp
// Find the element in the vector.  <-- Bad: obvious!
if (std::find(v.begin(), v.end(), element) != v.end()) {
  Process(element);
}

// Process "element" unless it was already processed.
if (std::find(v.begin(), v.end(), element) != v.end()) {
  Process(element);
}

// Self-describing code needs no comment; the comment above would be obvious:
if (!IsAlreadyProcessed(element)) {
  Process(element);
}
```
## Punctuation, Spelling, and Grammar
<!-- tier: portable -->
Pay attention to punctuation, spelling, and grammar. Write comments as readable as narrative text,
with proper capitalization and punctuation. Complete sentences are often more readable than
fragments. Shorter comments can be less formal; keep the style consistent.
## TODO Comments
### Use TODO comments for temporary or imperfect code
<!-- tier: portable -->
Use TODO comments for code that is temporary, a short-term solution, or good-enough but not
perfect.
### Include TODO plus an owner or issue identifier
<!-- tier: portable -->
Write `TODO` in all caps, followed by the bug ID, name, e-mail address, or other identifier of
the person or issue with the best context about the problem. The purpose is a consistent TODO that
can be searched to find details on request. A TODO is not a commitment that the person referenced
will fix the problem, so a named TODO is almost always your own.

```cpp
// TODO(bug 12345): remove the "Last visitors" feature.
// TODO(example.com/my-design-doc): Manually fix up this code the next time it's touched.
// TODO(kl@gmail.com): Use a "*" here for concatenation operator.
// TODO(Zeke): change this to use relations.
```
### Make deferred-work TODOs specific
<!-- tier: portable -->
For a TODO of the form "At a future date do something", include a very specific date
("Fix by November 2005") or a very specific event ("Remove this code when all clients can handle
XML responses.").
## Inclusive Language
### Use inclusive language
<!-- tier: portable -->
Use inclusive language in all code, including naming and comments. Avoid terms other programmers
might find disrespectful or offensive, even when the term also has an ostensibly neutral meaning.
Prohibited terms: `master`, `slave`, `blacklist`, `whitelist`, `redline`.
### Use gender-neutral language
<!-- tier: portable -->
Use gender-neutral language unless referring to a specific person, in which case use that person's
pronouns. Use `they`/`them`/`their` for people of unspecified gender, even when singular, and
`it`/`its` for software and other non-persons.

---
Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Comments, Inclusive Language)
