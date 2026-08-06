# Test safety

- Tests must not modify persistent user or machine state, including `PATH`, registry values, profiles, credentials, installed packages, or application configuration.
- Mock functions that write persistent state or invoke installers and package managers.
- Use `TestDrive:` or another disposable location for test fixtures.
- For `PATH` tests, snapshot the persistent User `PATH` and assert that it is unchanged afterward.
- Load only the function definitions needed by a test; do not dot-source the complete user profile.
