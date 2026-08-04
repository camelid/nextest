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

Cache hits are shown as `(cached)` on nextest's test status lines.

## I/O effect tracking

On Linux systems with `strace` installed, the wrapper records an effect ledger
for the test process and its descendants. Use `--io-policy POLICY` before `--`
to select a policy:

- `off` preserves the original cache behavior.
- `conservative` caches only tests without external file reads, external
  writes, network I/O, or subprocess execution.
- `content-addressed` hashes external regular files that the test reads and
  validates them before every cache hit. It still rejects external writes,
  network I/O, and subprocess execution. This is the default on Linux.

The default is `off` on other platforms. For example:

```toml
command = [
  "/absolute/path/to/nextest-cache",
  "--io-policy", "conservative",
  "--",
]
```

Files created exclusively under the system temporary directory and removed
before the test exits are treated as private temporary I/O. Loader, procfs,
sysfs, locale, and time-zone reads are treated as ambient platform inputs.
Tracing failures run the test normally and bypass the cache.
