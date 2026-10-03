# Tooling: what is in, and what is tabled

The first three items of `docs/plan-tools.md` were built on 2026-10-03 as proofs of concept: clippy and rustfmt in CI, three stricter clippy lints in the shipped crates, and weekly mutation testing. This file says what each does now and what was left for later.

## Clippy and rustfmt in CI

**In:** a `lint` job in `.github/workflows/ci.yml`, running `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo fmt --all --check` in a Fedora 44 container, with the clippy and rustfmt Fedora ships (1.98.1 when added, the same as the development machine). It runs on every push, like the tests.

**Tabled:**

- **A pinned clippy version.** Fedora updates its Rust package, and a new clippy can bring new warnings, which would turn the job red on a commit that changed nothing. The owner chose Fedora's toolchain to match what is packaged; if surprise failures become a nuisance, pin it as the `rust-version` job pins 1.98.
- **Linting the shell scripts.** `install.sh` and the podman scripts are security-relevant too; `shellcheck` in the same job would cover them.

## Stricter clippy lints in the shipped crates

**In:** `undocumented_unsafe_blocks`, `indexing_slicing` and `cast_possible_truncation`, switched on at the root of each shipped crate (core, sys, helper, pam and cli; the helper's binary too), so CI fails on them. Test code may still index (`clippy.toml`), and the test-only crates are left alone. What they flagged, and how each was settled, is in the commit that added them; in short, five spots were rewritten to avoid the panic or the cast, and three casts that can't truncate got a named constant or function with an `allow` saying why. A check that the lint bites: with one `SAFETY` comment removed, clippy refuses the PAM module.

**Tabled**, counted on the shipped crates when the first three went in:

- **`arithmetic_side_effects`:** 17 places where arithmetic could overflow. Most are bounded by construction (counts capped elsewhere, times checked to be in order), but each wants a look, and `saturating_`, `checked_` or a comment.
- **`unwrap_used` and `expect_used`:** 6 places. A panic in the PAM module is caught at its edge, and the helper aborts on one, so none can unlock anything, but each should be deliberate.
- **`clippy::pedantic`:** about 150 warnings, mostly `must_use` attributes (45), missing `# Errors` sections in docs (27) and backticks in docs (19). Worth a pass with a list of exceptions; noisy as a blanket rule. One of them is a deliberate design choice and should become an `allow` with a reason: `Settings`' hand-written `Debug` leaves fields out on purpose, to keep the hash and the pepper out of logs.
- **The same lints for the test-only crates,** which run as root in the container: less important, since they never ship.

## Mutation testing

**In:** `.github/workflows/mutants.yml`, every Monday and on demand, runs cargo-mutants 27.1 on properpin-core and properpin-sys in Fedora 44, as an unprivileged user. Each mutant is tested against the core, sys and helper tests, since the helper's tests drive much of core. It only reports: missed mutants and timeouts keep the job green, and their list goes into the job summary and an artifact. `just properpin mutants` runs the same locally, on half the CPUs. cargo-mutants is installed on the development machine with `cargo install`, with the owner's agreement.

**The first run** (local, the same settings as CI): its results, and the tests written for the survivors that mattered, are described below once analysed.

**Tabled:**

- **The helper, the PAM module and the CLI** aren't mutated yet. The helper's tests are fast and would fit; the PAM module's and the CLI's tests build and run binaries, so each mutant costs more, and the PAM module's real tests are the container scenarios, which cargo-mutants can't run.
- **Failing on missed mutants.** Report only for now, as the owner chose. Once the list is down to accepted survivors, those can be excluded (`.cargo/mutants.toml`, or `#[mutants::skip]` with a reason) and the job made to fail on any new one.
- **Running only on changed code** (`cargo mutants --in-diff`) on pull requests, cheap enough for every push.
- **The container scenarios as a test command,** so mutants in the helper and the PAM module face the real PAM stack. Possible through `--test-tool` or a custom script, but slow: minutes per mutant.

## Next from `docs/plan-tools.md`

Fuzzing the parsers and `decode_hash` with cargo-fuzz, and Kani proofs for `decode_hash`, the hex and XOR functions and the budget, are the next steps, unchanged.
