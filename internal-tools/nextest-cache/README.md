# Nextest cache wrapper

The wrapper passes only explicitly selected environment variables to test
processes, and includes the same variables in the cache key. `PATH` and the
platform's dynamic-library search path are selected by default.

Use repeated `--env NAME` options to add package-specific variables. Put more
specific script rules before less specific rules because the first matching
run wrapper wins.

```toml
experimental = ["wrapper-scripts"]

[scripts.wrapper.cache-foo]
command = [
  "/absolute/path/to/nextest-cache",
  "--env", "DATABASE_URL",
  "--env", "RUST_LOG",
  "--",
]
target-runner = "within-wrapper"

[scripts.wrapper.cache-bar]
command = ["/absolute/path/to/nextest-cache", "--"]
target-runner = "within-wrapper"

[[profile.default.scripts]]
filter = "package(foo)"
run-wrapper = "cache-foo"

[[profile.default.scripts]]
filter = "package(bar)"
run-wrapper = "cache-bar"
```

Variables that are not selected are removed before the child command is
started, so they cannot change test behavior without also changing the cache
key. Names beginning with `NEXTEST` are reserved for the wrapper and cannot be
selected.
