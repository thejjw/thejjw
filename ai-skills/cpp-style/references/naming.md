# Naming

Scope: Naming -- Choosing Names, File Names, Type Names, Concept Names, Variable
Names, Constant Names, Function Names, Namespace Names, Enumerator Names, Template
Parameter Names, Macro Names, Aliases, Exceptions to Naming Rules.

## Choosing Names
<!-- tier: portable -->
- Apply the rules even when you disagree; consistency beats personal preference.
- Treat a name as a signal: its style says what kind of entity it is, without a lookup.
- Read "word" as a unit you would write in English without internal spaces: all lowercase
  with underscores between words (`snake_case`), or mixed case with capitalized words.
- Ambiguity: the guide calls mixed-case-with-capitalized-words both "camelCase" and
  "PascalCase", though those differ in the first letter's case. Follow the guide's usage:
  PascalCase for types/functions, snake_case for variables/namespaces.
- Name things so their purpose or intent is understandable to a new reader, even on another
  team; never sacrifice clarity to save horizontal space.
- Make a name descriptive even when used far from the code that makes it available, but never
  repeat information already in the immediate context.
- Scale descriptiveness to the name's scope: a free function in a header should name the
  library; a local variable should not explain its function.
- Minimize abbreviations unknown outside your project, especially acronyms and initialisms.
- Never abbreviate by deleting letters inside a word (`cstmr_id` is bad).
- Capitalize an abbreviation as a single word: prefer `StartRpc()` over `StartRPC()`.
- Accept an abbreviation listed in Wikipedia; always allow universal ones like `i` (loop
  index) and `T` (template parameter).

### Vocabulary Names
<!-- tier: portable -->
- A few vocabulary names are reused so widely they are always in context; such names may be
  short or abbreviated, with full meaning in long-form docs, not in comments on the definition.
- Expect to define new vocabulary names rarely; when you do, make sure they work well widely.

### Google-Internal Vocabulary Notes
<!-- tier: google-internal -->
- Get additional design review before introducing a new vocabulary name.
- The guide's example vocabulary name is `absl::Status`, documented in a devguide page.

### Naming Examples
<!-- tier: portable -->
```cpp
// Good:
class MyClass {
 public:
  int CountFooErrors(const std::vector<Foo>& foos) {
    int n = 0;  // Clear meaning given limited scope and context
    for (const auto& foo : foos) { ... ++n; }
    return n;
  }
  absl::Status DoSomethingImportant() {
    // No need to explain non-OK on failure: the `absl::Status` return type implies it.
    std::string fqdn = ...;  // Well-known abbreviation for Fully Qualified Domain Name
    return absl::OkStatus();
  }
 private:
  const int kMaxAllowedConnections = ...;  // Clear meaning within context
};

// Bad:
class MyClass {
 public:
  int CountFooErrors(const std::vector<Foo>& foos) {
    int total_number_of_foo_errors = 0;  // Overly verbose given limited scope and context
    for (int foo_index = 0; foo_index < foos.size(); ++foo_index) {  // Use idiomatic `i`
      ... ++total_number_of_foo_errors;
    }
    return total_number_of_foo_errors;
  }
  // A return type with a generic name is unclear without widespread education.
  Result DoSomethingImportant() {
    int cstmr_id = ...;  // Deletes internal letters
  }
 private:
  const int kNum = ...;  // Unclear meaning within broad scope
};
```

### Google-Internal Types in Examples
<!-- tier: google-internal -->
- `absl::Status`, `absl::OkStatus()`, and `absl::string_view` are Google-internal types; use the
  equivalent types of your own project elsewhere.

## File Names
<!-- tier: portable -->
- Keep filenames all lowercase; allow underscores (`_`) or dashes (`-`) as separators.
- Follow the convention your project uses; with no consistent local pattern, prefer `_`.
- Use `.cc` for C++ files and `.h` for header files.
- End files textually included at specific points in `.inc`; see the guide's self-contained
  headers section.
- Make filenames very specific: prefer `http_server_logs.h` over `logs.h`.
- Pair implementation and header files for one type: `foo_bar.h` and `foo_bar.cc` for `FooBar`.
```cpp
my_useful_class.cc
my-useful-class.cc
myusefulclass.cc
myusefulclass_test.cc // _unittest and _regtest are deprecated.
```

### Avoid System Header Names
<!-- tier: platform-specific -->
- Never use a filename that already exists in the platform's system include directory (the
  guide cites `/usr/include`, a POSIX path); avoid names like `db.h`.

### Deprecated Test File Suffixes
<!-- tier: google-internal -->
- The `_unittest` and `_regtest` filename suffixes are deprecated.

## Type Names
<!-- tier: portable -->
- Start type names with a capital letter and capitalize each new word; no underscores:
  `MyExcitingClass`, `MyExcitingEnum`.
- Apply the same convention to all types: classes, structs, aliases, enums, and type template
  parameters.
```cpp
// classes and structs
class UrlTable { ...
class UrlTableTester { ...
struct UrlTableProperties { ...
// typedefs
typedef hash_map<UrlTableProperties*, std::string> PropertiesMap;
// using aliases
using PropertiesMap = hash_map<UrlTableProperties*, std::string>;
// enums
enum class UrlTableError { ...
```

## Concept Names
<!-- tier: portable -->
- Follow the same rules as type names.

## Variable Names
<!-- tier: portable -->
- Name variables (including function parameters) and data members in `snake_case`: all
  lowercase with underscores between words.
- Add a trailing underscore to data members of classes, but not structs: `a_local_variable`,
  `a_struct_data_member`, `a_class_data_member_`.

### Common Variable Names
<!-- tier: portable -->
```cpp
std::string table_name;  // OK - snake_case.

std::string tableName;   // Bad - mixed case.
```

### Class Data Members
<!-- tier: portable -->
- Name class data members, static and non-static, like ordinary nonmember variables, plus a
  trailing underscore.
- Exception: static constant class members follow the constant naming rules.
```cpp
class TableInfo {
 public:
  ...
  static const int kTableVersion = 3;  // OK - constant naming.
  ...
 private:
  std::string table_name_;             // OK - underscore at end.
  static Pool<TableInfo>* absl_nullable pool_;       // OK.
};
```

### Struct Data Members
<!-- tier: portable -->
- Name struct data members, static and non-static, like ordinary nonmember variables.
- Never add the trailing underscore that class data members have.
```cpp
struct UrlTableProperties {
  std::string name;
  int num_entries;
  static Pool<UrlTableProperties>* absl_nullable pool;
};
```

- See the guide's "Structs vs. Classes" section on when to use a struct rather than a class.

## Constant Names
<!-- tier: portable -->
- Name variables declared `constexpr` or `const` whose value is fixed for the program's
  duration with a leading `k` followed by mixed case.
- Use underscores as separators when capitalization cannot separate words.
- Apply the `k` prefix to all such variables with static storage duration, including static
  constant class members and template variables whose value differs per instantiation.
- Treat the convention as optional for other storage classes, such as automatic variables;
  the usual variable naming rules apply there.
```cpp
const int kDaysInAWeek = 7;
const int kAndroid8_0_0 = 24;  // Android 8.0.0

template <int kMaxAttempts>
class ExponentialBackoff final {
  static constexpr absl::string_view kLogTag = "exponential backoff";
  ...
}

// Good: either of these is acceptable.
void ComputeFoo(absl::string_view suffix) {
  const absl::string_view kPrefix = "prefix";
  const absl::string_view prefix = "prefix";
  ...
}

// Bad: different invocations of ComputeFoo give kCombined different values.
void ComputeFoo(absl::string_view suffix) {
  const std::string kCombined = absl::StrCat(kPrefix, suffix);
  ...
}
```

- Ambiguity: the guide calls the `kCombined` example bad, but the stated reason is that the
  value varies per invocation, not the spelling. It still shows a `k` prefix does not fit a
  local whose value is not fixed.

## Function Names
<!-- tier: portable -->
- Name functions in `PascalCase`: start with a capital letter and capitalize each new word.
- Apply the same PascalCase rule to class- and namespace-scope constants exposed as part of
  an API and intended to look like functions; that they are objects is an unimportant detail.
- Accessors and mutators (get and set functions) may be named like variables, in
  `snake_case`; they often mirror member variables, but this is not required.
```cpp
AddTableEntry()
DeleteUrl()
OpenFileOrDie()

int count()                 // accessor
void set_count(int count)   // mutator
```

## Namespace Names
<!-- tier: portable -->
- Name namespaces in `snake_case`: all lowercase with underscores between words.
- Make top-level namespaces globally unique and recognizable.
- Give each top-level namespace to a single project or team, named after that project or
  team, with its code under directories of the same name.
- Avoid well-known top-level namespace names, especially `std` and `absl`: in C++ nested
  namespaces do not protect from collisions with other namespaces (TotW #130).

### Qualification in Headers
<!-- tier: google-internal -->
- Unqualified alias declarations are generally banned, so names must be fully qualified when
  used in a header outside the namespace.

## Enumerator Names
<!-- tier: portable -->
- Name enumerators, scoped and unscoped alike, like constants, not macros: use `kEnumName`,
  not `ENUM_NAME`.
- New code must use constant-style naming. Macro-style spelling was the style until January
  2009 and caused collisions between enum values and macros.
```cpp
enum class UrlTableError {  // Good.
  kOk = 0,
  kOutOfMemory,
  kMalformedInput,
};

enum class AlternateUrlTableError {  // Bad.
  OK = 0,
  OUT_OF_MEMORY = 1,
  MALFORMED_INPUT = 2,
};
```

## Template Parameter Names
<!-- tier: portable -->
- Name template parameters by category: type template parameters follow the type naming
  rules, non-type ones follow the variable or constant rules.
- Single-letter names are acceptable for template parameters: `T` is a universal
  abbreviation.
```cpp
template <typename T, int kMaxAttempts>  // type parameter, non-type constant parameter
class ExponentialBackoff final { ... };
```

## Macro Names
<!-- tier: portable -->
- Avoid macros; in general they should not be used.
- When a macro is absolutely necessary, name it in all capitals and underscores, plus a
  project-specific prefix.
```cpp
#define MYPROJECT_ROUND(x) ...
```

## Aliases
<!-- tier: portable -->
- Name an alias with the same principles you would apply to any other new name.
- Apply those principles where the alias is defined, not where the original name appears.

## Exceptions to Naming Rules
<!-- tier: portable -->
- When naming something analogous to existing C or C++ entities (or a Rust entity via
  interop), follow the existing naming convention scheme.
```cpp
bigopen()          // function name, follows form of open()
uint               // typedef
bigpos             // struct or class, follows form of pos
sparse_hash_map    // STL-like entity; follows STL naming conventions
LONGLONG_MAX       // a constant, as in INT_MAX
```

---

Source: Google C++ Style Guide -- https://google.github.io/styleguide/cppguide.html (sections: Naming, Choosing Names, File Names, Type Names, Concept Names, Variable Names, Constant Names, Function Names, Namespace Names, Enumerator Names, Template Parameter Names, Macro Names, Aliases, Exceptions to Naming Rules)
