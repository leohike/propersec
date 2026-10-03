# The --dev options and AT_SECURE

A short explainer, written on 2026-10-03, of what guards properpin-helper's `--dev-*` options and why that guard matters. The code is in `products/pin/crates/helper`: `main.rs` (`Options`, `run`) and `secure.rs` (`elevated`).

## The --dev options

The helper normally uses fixed places: hashes in `/etc/properpin`, counts in `/run/properpin`, the password checker `/usr/sbin/unix_chkpwd`, and syslog. The `--dev-*` options replace them:

| Option | Replaces |
|---|---|
| `--dev-etc DIR` | where hash files are read from |
| `--dev-run DIR` | where counts are kept |
| `--dev-owner UID` | who must own those files |
| `--dev-chkpwd PATH` | which password checker is run |
| `--dev-log FILE` | where log lines go |

They exist so `cargo test` and `just properpin demo` can run the real helper binary against a temporary sandbox, without root and without installing anything.

**They are also the most dangerous thing in the helper.** If the installed helper accepted them, any user could run `properpin-helper arm --dev-chkpwd ~/fake-says-yes --dev-run ~/myrun`: a fake checker that always says yes arms the PIN without the password, and counts in a directory the user controls can be reset at will. So they must be refused whenever the helper runs with properpin's rights.

## AT_SECURE

When a program starts, the kernel hands it a small list of facts, the auxiliary vector. One of them, `AT_SECURE`, is 1 when the program was started with more rights than whoever started it: a setuid or setgid bit changed its identity, or file capabilities raised it. Otherwise it is 0.

The rest of the system already relies on it:

- the dynamic loader ignores `LD_PRELOAD` and `LD_LIBRARY_PATH`, so nobody can inject a library into `sudo`;
- glibc ignores other dangerous environment variables;
- the process is made non-dumpable, so its caller can't attach a debugger or read its memory.

The helper reads it with `getauxval(AT_SECURE)` in `secure.rs`, `elevated()`:

| AT_SECURE | What is running | --dev options |
|---|---|---|
| 1 | the installed setuid or setgid helper | refused, exit 2, logged |
| 0 | a plain copy run by tests, with no more rights than its caller | allowed, and harmless: it can only touch what the caller could anyway |

The container scenario "--dev options are refused under setgid" fails when this check is disabled, which was verified once by breaking it on purpose.

## The second guard

Since the setgid helper (`docs/spec-setgid-helper.md`, built 2026-10-03), that check has an independent partner: the `--dev` options are allowed only when the real and effective user ids are equal and the real and effective group ids are equal.

- Run by tests: both pairs match, so the options are allowed.
- Installed setgid: the real group is the caller's, the effective group is `properpin`, so they differ and the options are refused.

The two guards read the same fact from different places: `AT_SECURE` is the kernel's flag set at program start, the id comparison is what the process is right now. A bug has to break both to expose the options. The comparison lives in a pure function, `dev_options_allowed(at_secure, uid, euid, gid, egid)`, so a unit test covers every combination instantly, with no root and no container. Both halves were checked by breaking them on purpose: with the `AT_SECURE` half removed, the unit test fails while the container scenario still passes on the id comparison alone.
