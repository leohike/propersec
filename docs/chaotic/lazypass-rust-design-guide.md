---
id: 2610012315AMJ6w9J7eW
datetime: 2026 Oct 1, 23:15
ctime: "2026-10-01 23:15:35"
---



For: a software engineer new to Rust, with one day of PAM knowledge.
Goal: build `pam_lazypass.so` (PIN with a time window, 3 strikes then full password, duress PIN) and test it properly without building a lab.

---

## 1. Words you'll keep running into

**PAM and Linux**

- **PAM**: the Linux system that decides "is this person allowed in?". Apps like the lock screen, sudo or ssh don't check passwords themselves; they ask PAM.
- **libpam**: the C library that implements PAM. Apps call it, and it loads and runs modules.
- **PAM module**: a plugin (`.so` file) that libpam loads. `pam_unix.so` checks your normal Linux password; yours will be `pam_lazypass.so`.
- **Service file / stack**: a config file in `/etc/pam.d/`, one per app. The lock screen uses `/etc/pam.d/kde`. It lists modules top to bottom, and libpam runs them in that order. That ordered list is "the stack".
- **Control flag**: the word on each stack line that says what a module's answer means. Examples:
  - `required`: must pass, keep going either way
  - `sufficient`: pass means done
  - `optional`: mostly ignored
  - `[success=done default=ignore]`: the explicit long form
- **Conversation**: how a module asks the user something (like "Password:") through the app. The lock screen answers with whatever was typed.
- **PAM_AUTHTOK**: the slot where the typed password is stored, so the next module in the stack can reuse it instead of asking again.
- **PAM_IGNORE**: a module saying "not my business, ask the next one". This is your safe answer when the PIN isn't allowed.
- **unix_chkpwd**: a small helper program pam_unix uses to check passwords when the app isn't root. The lock screen isn't root, so this path is the one that matters.

**Rust and loading libraries**

- **`.so` (shared object)**: a Linux shared library, the same idea as a `.dll` on Windows.
- **dlopen / dlclose**: C functions that load and unload a `.so` while a program is running. libpam does this to your module on every unlock attempt.
- **FFI (Foreign Function Interface)**: calling between languages, here C (libpam) and Rust (your module). The compiler can't check this boundary, so it's where crashes come from.
- **`unsafe`**: Rust code where you promise the compiler you're handling raw pointers correctly. It's needed at the FFI edge; keep it small.
- **Panic**: Rust's version of an uncaught exception. If it escapes into C, the whole process dies, and here that's the lock screen.
- **`catch_unwind`**: Rust's "try/catch for panics". Wrap every function libpam calls in it.

**Rust project vocabulary**

- **Crate**: a Rust library or program, the unit you compile and publish. crates.io is Rust's npm/PyPI.
- **cdylib**: a crate compiled as a C-compatible `.so`. Your PAM module is one.
- **Workspace**: several crates in one repo that are built together.

**Testing**

- **Mock / fake**: a stand-in for a real dependency in tests, like a fake clock or a fake password checker.
- **Property-based testing**: instead of writing specific test inputs, you state a rule ("a PIN never works after 3 strikes"). The library tries hundreds of random inputs and, when something fails, shrinks it to the smallest failing example.
- **proptest**: the main Rust library for property-based testing. Same idea as Hypothesis in Python.
- **pamtester**: a command-line tool that runs a PAM stack the way an app would. Something like `pamtester kde alice authenticate`.
- **Container (podman)**: a lightweight isolated Linux userland. Your bootc OS image is also a container image, so you can run it with podman.
- **VM**: a full virtual machine with its own kernel, SELinux and boot.

---

## 2. How the lock screen actually uses your module

```
you type "1234" on the lock screen
        │
kscreenlocker_greet  (runs as YOU, not root)
        │  pam_start("kde") → pam_authenticate → pam_end
        ▼
libpam reads /etc/pam.d/kde, runs the stack top to bottom:
   1. pam_lazypass.so mode=pin     ← is "1234" a valid PIN right now?
   2. password-auth (pam_unix)     ← is it the real password?
   3. pam_lazypass.so mode=record  ← password worked → open PIN window
        │
   result → unlocked, or "wrong password"
```

Things that follow from this:

- **Only `auth` lines matter.** The lock screen only runs the authentication part of the stack. So the "remember that a full password just worked" step also has to be an `auth` line, placed after pam_unix (step 3).
- **It runs as you, not root.** Your module can only read and write files your user can. Any state file (strike count, last unlock time) has to be user-writable, which also means your user could edit it. That's fine for your threat model, since the attacker is at the keyboard without a shell. Just be aware of it.
- **Duress actions also run as your user.** No root powers unless you build a separate privileged helper.
- **Other stacks run in parallel.** If fingerprint or smartcard is set up, `kde-fingerprint` and `kde-smartcard` run at the same time. Never put your module in those.
- **Plasma 6.8 adds switchable authenticators** (experimental, opt-in). Switching cancels a running authenticator, so your module must cope with being interrupted halfway.
- **Login is a separate service.** Fedora 44 uses Plasma Login Manager instead of SDDM for the login screen. Logging in is a different service from the lock screen, so lazypass only affects the lock screen unless you add it there too.

---

## 3. How to structure the Rust code

Split it into two crates in one workspace.

**`lazypass-core`: the brain**

- Normal Rust, with no PAM, no `unsafe`, no files.
- One main function, roughly:
  ```rust
  fn decide(state: State, attempt: Attempt, now: Time, cfg: &Config) -> (Outcome, State)
  ```
- `State`: strike count, last full-password unlock time.
- `Attempt`: PIN, duress PIN, full password OK, full password wrong.
- `Outcome`: allow, deny, ignore (let pam_unix decide), duress.
- This is where all the rules live, and it's trivially testable.

**`pam_lazypass`: the plug (cdylib)**

- 100–200 lines of glue. It:
  - exports the C functions libpam looks for (`pam_sm_authenticate`, `pam_sm_setcred`)
  - gets the typed secret from libpam
  - reads the state file, calls `core::decide`, writes the state file
  - turns the outcome into a PAM return code
  - logs via `pam_syslog`
- All the dangerous stuff lives here (`unsafe`, panics, load/unload), so it's small and easy to review.

**Two more things to pass in rather than hard-code:**

- **A clock.** Pass `now` in instead of reading the system clock inside the logic. Then tests can say "pretend 20 minutes passed" instantly.
- **Storage behind an interface (a trait, in Rust terms).** Real code uses a file; tests use an in-memory fake.

---

## 4. Rules for the module (best practices)

**Never crash, never hang**

- Wrap every exported function in `catch_unwind`. On panic, return `PAM_IGNORE` so pam_unix still works and you're not locked out.
- Set `panic = "unwind"` in the build config (not `abort`), otherwise `catch_unwind` can't catch anything.
- Don't block: no network, and file locks with a timeout. There's no longer a separate process that gets killed after 2 seconds, as there was with `pam_exec`.
- Avoid threads, `println!`, and thread-local variables with cleanup code. These are the usual causes of crashes when libpam unloads the `.so`.

**Fail safe**

- If the state file is missing, corrupted or unreadable, require the full password. Never fall back to "PIN allowed".
- If the clock goes backwards (suspend, NTP), never extend the PIN window.
- Only a successful full password resets strikes and opens the window.

**State file hygiene**

- Write atomically: write to a temp file, then `rename` it over the old one, so a crash never leaves a half-written file.
- Use `flock` with a timeout. Two attempts at once (parallel stacks) shouldn't lose or double-count a strike.
- Count strikes before checking the PIN, or at least in a way where interrupting halfway can't erase a strike.

**Duress**

- From the outside, a duress unlock should look like a normal unlock: same return code, same messages, similar timing.
- The duress action must be quick or run in the background, and must never be able to break the unlock itself.

**Stack config**

- Keep a known-good copy of `/etc/pam.d/kde` and a one-command restore (you have `just lazypass restore-pam`).
- Watch control-flag syntax. One real Fedora lock-screen project locked users out with an invalid `[...] substack` line; libpam treated `substack` as a module name.

**Porting from Python**

- Python's `len("é")` is 1 (characters). Rust's `"é".len()` is 2 (bytes). Use `.chars().count()` for PIN length rules.
- Compare secrets in constant time (e.g. the `subtle` crate). It's minor locally, but it's a free habit.
- Don't store PINs in plain text. Store a hash with a slow algorithm like argon2. Keep in mind this adds noticeable time per check.

---

## 5. Testing, in layers

Think of it as a ladder: each rung is closer to the real lock screen and more work. Most of your bugs get caught on the first three.

**Layer 1: pure logic tests** (every change, seconds to run)

- Tests `lazypass-core` only. No PAM at all, nothing to fake.
- Start with normal unit tests, one per rule:
  - "3 wrong PINs → PIN rejected even if correct"
  - "PIN works 5 min after password"
  - "PIN fails 20 min after password"
  - "duress PIN triggers duress outcome"
  - "corrupted state → full password required"
- Then add property tests with `proptest`. It generates random sequences of events (wrong PIN, wait 4 min, password ok, duress, wait 20 min, PIN…) and checks rules that must always hold:
  - a PIN never succeeds after 3 strikes
  - a PIN never succeeds outside the window
  - only the full password resets strikes
  - time going backwards never helps
- This finds the bugs you wouldn't think to write a test for.
- Effort: 1–2 evenings.

**Layer 2: real `.so` + real libpam, no root** (every change, seconds)

- Builds the actual module and has real libpam load it, using a test stack file in a temp folder.
- How: libpam has `pam_start_confdir`, which is "pam_start, but read config from this folder instead of `/etc/pam.d`". No root needed.
- Replace pam_unix with simple stand-ins so you control the outcome: `pam_permit.so` (always yes), `pam_deny.so` (always no), or `pam_matrix.so` from pam_wrapper (a fake user/password list).
- What it catches:
  - module loads, the exported names are right
  - reads the typed secret correctly
  - stack order and control flags behave as you think
  - only one prompt per attempt
- Also add here:
  - **Load/unload loop:** start → authenticate → end, 1000 times, from several threads. Catches crash-on-unload bugs.
  - **Forced panic:** a test-only option that makes the module panic, then check it returns `PAM_IGNORE` instead of crashing.
  - **Parallel attempts:** two processes at once against the same state file; strikes must add up.
  - **valgrind:** run the harness under valgrind to catch memory errors at the C/Rust boundary.
- Effort: 1–2 evenings. You already do this in Python (`test_pam.py`), so port the idea.

**Layer 3: your real OS image in a container** (before deploying, about a minute)

- `podman run` your actual bootc image (Aurora + lazypass). Create a test user with a real password.
- Run `pamtester` **as that test user, not root**. This is the important part, because the lock screen isn't root. As root, pam_unix behaves differently and you'd test the wrong thing.
- What it catches:
  - the real Fedora PAM config
  - real pam_unix and unix_chkpwd
  - file permissions on your state file
  - whether your image build actually installs the module and config correctly
- Script scenarios like "3 wrong PINs → full password needed" with a small script that feeds inputs.
- Effort: about 1 evening.

**Layer 4: VM** (optional, nightly or before releases)

- `bcvk` boots your bootc image as a throwaway VM with one command, no root. Then run the Layer 3 scripts over SSH.
- Adds what containers can't check: SELinux actually enforcing, real boot, systemd.
- After each run, check for SELinux denials (`ausearch -m avc`).
- GitHub Actions' free Linux runners can now run VMs with hardware acceleration (KVM), so this can run in CI. Expect slow and occasionally flaky runs.
- Effort: 1–2 evenings. Mainly worth it when you change packaging or SELinux-related stuff.

**Layer 5: the real lock screen, by hand** (each release or Plasma upgrade, ~15 min)

- Keep an SSH session open from another device (your escape hatch). `loginctl unlock-sessions` unlocks a stuck screen.
- Run `journalctl -f` to watch your logs.
- Checklist:
  - PIN in window → unlocks
  - PIN after window → rejected, password works
  - 3 wrong PINs → PIN dead, password works, PIN works again afterwards
  - duress PIN → looks normal, duress action happened
  - suspend while locked, resume, try PIN
  - fingerprint enabled at the same time (if you use it)
  - Plasma 6.8 authenticator switching mid-prompt (if enabled)
- Shortcut: `kscreenlocker_greet --testing` shows the real lock screen UI as a normal window using real PAM, without locking your session.

**Where to stop**

- Layers 1–3 catch nearly everything about your module.
- After that you're mostly testing KDE, not your code.
- Fully automating the real lock screen (virtual KWin + fake keyboard input + UI automation) works, KDE does it, but it's a project of its own. Skip it.

---

## 6. Ideas worth borrowing

- **Two `auth` lines for one module:** `mode=pin` before pam_unix, `mode=record` (`optional`) after it. That's the cleanest way to get the "window opens after password" behaviour inside an auth-only stack.
- **Return `PAM_IGNORE` instead of failing when the PIN isn't allowed.** pam_unix then gets the typed text and checks it as the real password, so the user doesn't need two input fields.
- **Put the typed text in `PAM_AUTHTOK`** and use `try_first_pass` on pam_unix, so the user is never asked twice.
- **Debug mode via a module argument** (`debug`) that logs decisions (never secrets) to syslog.
- **A `lazypass status` CLI** that prints current strikes and window state. Handy for manual testing and for a sanity check in Layer 3 scripts.
- **Golden stack files:** keep your intended `/etc/pam.d/kde` in the repo and test that exact file in Layers 2–3, so the tested config and the deployed one never drift apart.

---

## 7. Existing projects to look at

**Rust libraries for writing PAM modules** (pick one; they handle the FFI glue)

- **pam-rs** (https://github.com/lvkv/pam-rs)
  - A library for writing PAM modules in Rust.
  - Steal: its integration tests run `pamtester` inside `bwrap` (a sandbox that swaps in a test `/etc/pam.d` without root). See `.github/workflows/rust.yml`.
- **nonstick** (https://docs.rs/nonstick)
  - A newer library with a cleaner Rust-style API, designed so PAM pieces can be swapped for fakes in tests.
- **pamsm** (https://crates.io/crates/pamsm)
  - Another small module-writing library. Worth comparing APIs before choosing.
- **pam-client** (https://docs.rs/pam-client)
  - For the *app* side (calling PAM). Useful for writing your Layer 2 test harness.
  - Steal: `conv_mock`, a scripted fake conversation ("when asked, answer 1234").

**PAM testing tools**

- **pam_wrapper / pypamtest** (https://cwrap.org/pam_wrapper.html)
  - The standard toolkit for testing PAM without root. Packaged in Fedora.
  - Steal: `pam_matrix` (fake password list) and `pam_set_items` (pre-fill `PAM_AUTHTOK` to simulate an earlier module).
- **pamtester** (https://github.com/pld-linux/pamtester)
  - The command-line driver for Layers 3–4.
- **kanidm pam_tester** (https://github.com/kanidm/pam_tester)
  - An alternative driver, written in Rust.

**Projects whose tests are worth reading**

- **fprintd** (https://gitlab.freedesktop.org/libfprint/fprintd)
  - Look at `tests/pam/test_pam_fprintd.py`.
  - Best real-world example of testing a lock-screen-relevant PAM module: pam_wrapper plus a fake system service (python-dbusmock).
- **sssd test framework** (https://tests.sssd.io/en/latest/guides/testing-pam.html)
  - Its faillock tests (3 wrong attempts → locked → reset) are almost exactly your strike scenario.
- **Linux-PAM itself** (https://github.com/linux-pam/linux-pam)
  - Source of `pam_faillock` and `pam_unix`. Read `pam_faillock` for strike counting and lockout state files.
- **pam-u2f** (https://github.com/Yubico/pam-u2f)
  - A mature third-party module that's widely used with KDE's lock screen. Good reference for code structure and how a module handles the user context.

**Duress implementations**

- **nuvious/pam-duress** (https://github.com/nuvious/pam-duress)
  - Duress password that runs scripts and then still logs you in. Steal: the stack layout and its "looks normal" approach.
- **rafket/pam_duress** (https://github.com/rafket/pam_duress)
  - An older C version of the same idea.

**KDE lock screen internals**

- **kscreenlocker** (https://invent.kde.org/plasma/kscreenlocker)
  - The lock screen itself. Look at:
    - `greeter/pamauthenticator.cpp`: exactly how it calls PAM
    - `autotests/`: how KDE tests it
    - MR !163: parallel stacks
    - MR !318: Plasma 6.8 authenticator switching

**OS image / VM testing**

- **bcvk** (https://github.com/bootc-dev/bcvk)
  - Boot a bootc image as a VM with one command. For Layer 4.

**Cautionary tales**

- **rust-lang/rust#91979** (https://github.com/rust-lang/rust/issues/91979)
  - A Rust `.so` crashing when unloaded after thread-local storage was used. This is why the load/unload loop test exists.
- **dromeropa/tinkero PR #47** (https://github.com/dromeropa/tinkero/pull/47)
  - Lock-screen lockout caused by an invalid stack line. This is why stack files get tested, not just module code.

---

## 8. Suggested order of work

1. **Write `lazypass-core` with plain unit tests.** Port the rules from your Python version. This is also a gentle way into Rust: no `unsafe`, no FFI.
2. **Add proptest rules** to Layer 1.
3. **Pick a PAM library** (pam-rs or nonstick), write the thin `pam_lazypass` plug, and get Layer 2 green: real libpam, temp config, load/unload loop, panic test.
4. **Write the Layer 3 podman script.** Reuse the scenarios from your Python `test_pam.py` and run them against the Rust module as a non-root user. When the Rust module passes everything the Python one did, it's a drop-in replacement.
5. **Run the Layer 5 manual checklist on the real machine**, with SSH open.
6. **Add Layer 4 (bcvk)** only if SELinux or packaging starts causing trouble, or if you publish.

**Before trusting your setup, check these three things on your machine:**

- `cat /etc/pam.d/kde` and see what Fedora/Aurora actually ships.
- `ps -eZ | grep kscreenlocker_greet` and see which SELinux label the lock screen runs under.
- Whether vendor PAM files live in `/usr/lib/pam.d` or `/usr/etc/pam.d` on your image.
