# Tools that check Rust code automatically

A survey made on 2026-10-03 of linters, analysers and verifiers that could check properpin's code beyond what it uses today, with a recommended order. Nothing here is set up yet. Everything would run in CI or in a podman container, so nothing gets installed on the development machine; trying a tool locally (each is one cargo crate) is to be agreed with the owner first.

## What properpin already has

- **Locally, through `just lint`:** clippy with warnings as errors, and rustfmt.
- **In CI:** `cargo deny` and `cargo audit`, which check dependencies against known security advisories; `cargo deny`'s licence, ban and source checks only warn.
- **In the code:** `unsafe_code = "deny"` everywhere except the FFI modules.

One gap: **clippy and rustfmt don't run in CI,** so nothing stops a commit that fails lint.

## Linters beyond plain clippy

- **Clippy's restriction lints.** They are off by default and meant to be picked one by one; enabling the whole group is discouraged, since some contradict each other. The ones that matter for security code:
  - `undocumented_unsafe_blocks`: every `unsafe` block must carry a `// SAFETY:` comment. Ours already do, so this only enforces it.
  - `indexing_slicing`: flags `a[i]` and `&a[x..y]`, which panic when out of range. It would flag `decode_hash`, for example.
  - `arithmetic_side_effects`: flags arithmetic that can overflow.
  - `cast_possible_truncation`: flags casts that can silently lose bits, such as `bits as u8` in the decoder.
  - `unwrap_used` and `expect_used`: flag calls that panic. A panic in the PAM module is caught, and in the helper it aborts, but each one should be deliberate.
- **`clippy::pedantic`:** a stricter style group, noisier, best turned on with a list of exceptions.
- **Semgrep:** custom pattern rules across the code, such as "never log a variable named pin or password", which clippy can't express.

## Tools that run the code to find bugs

- **cargo-mutants (mutation testing):** breaks the code on purpose, one change at a time, and reports every change no test notices. Already a row in `docs/plan.md`, and the best single sign of how far the tests can be trusted.
- **cargo-fuzz:** feeds random input to a function, millions of times. Good targets: the settings parser (`kv.rs`), the state, budget and hex parsers, and `decode_hash`. It needs the nightly toolchain, which is fine in CI.
- **Miri:** an interpreter that catches undefined behaviour in `unsafe` code. It is of limited use here: it can't run calls into foreign C libraries such as libxcrypt and libpam, and that is where properpin's `unsafe` code is; the rest has no `unsafe` code at all.
- **cargo-careful:** runs the tests against a standard library with extra internal checks turned on. Cheap, and it works around FFI. Nightly only.

## Proving properties

- **Kani:** a model checker from AWS that proves a property for every possible input, not just the tested ones. AWS runs it in CI for Firecracker and s2n-quic. It suits small, critical functions: "`decode_hash` never panics and gives back exactly what libxcrypt encoded", "`xor` applied twice gives the input back", or the budget's invariants. Heavier to learn, but those functions are small.

## Supply chain, beyond what properpin has

- **cargo-vet:** records that a person reviewed each dependency.
- **cargo-geiger:** counts the `unsafe` code in the dependencies.
- **cargo-machete:** finds dependencies no longer used; fast, since it doesn't compile anything. cargo-udeps is the more accurate, slower, nightly-only alternative.
- **`cargo deny`'s licence, ban and source checks as errors** instead of warnings, already a row in `docs/plan.md`.

## The recommended order

- **First, clippy and rustfmt in CI.** Trivial, and it closes a real gap.
- **Then a handful of restriction lints** in the workspace `Cargo.toml`: `undocumented_unsafe_blocks`, `indexing_slicing` and `cast_possible_truncation`, at least for properpin-sys and the helper. Expect a short round of fixes or justified exceptions.
- **Then cargo-mutants in CI,** as `docs/plan.md` already plans.
- **Then cargo-fuzz targets** for the parsers and `decode_hash`, in CI.
- **Later, Kani proofs** for `decode_hash`, the hex and XOR functions, and perhaps the budget.

## Sources

- Awesome Rust Checker, a curated list: https://github.com/BurtonQin/Awesome-Rust-Checker
- Rust static code analysis guide: https://hyrax.dev/learn/rust-static-code-analysis
- Your Clippy config should be stricter: https://emschwartz.me/your-clippy-config-should-be-stricter/
- cargo-mutants: https://dev.co/testing/open-source/cargo-mutants
- Unused dependencies, cargo-machete and cargo-udeps: https://rustprojectprimer.com/checks/unused.html
- Miri: https://github.com/rust-lang/miri/
- What's new in Miri (2025): https://www.ralfj.de/blog/2025/12/22/miri.html
- Kani: https://github.com/model-checking/kani
- Kani paper: https://arxiv.org/html/2607.01504
- Rust security best practices 2026: https://corgea.com/learn/rust-security-best-practices
