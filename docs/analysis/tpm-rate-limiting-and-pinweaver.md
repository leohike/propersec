# TPM rate limiting, and PinWeaver

How a TPM 2.0 limits guessing, whether one TPM can protect several secrets, why it can't make each secret wait longer after every failure, and how Google's PinWeaver does exactly that in ChromeOS's own security chip. Written on 2026-10-18 as a follow-up to `docs/analysis/tpm-for-the-lock-screen.md`, which covers the TPM's PIN Fail slots, its counters and the access problem on Linux in detail; this report doesn't repeat that and refers to it by name.

## The short answer

One TPM can protect many secrets from guessing, in two separate ways:

- **The global lockout,** often called the dictionary-attack (DA) protection: one failure counter for the whole TPM. Every secret that isn't marked as exempt shares it. It lets a burst of failures through, then forgets one failure every so many seconds, so after the burst an attacker gets one guess per period. The rate is steady, not growing. A correct password doesn't lower the counter. A failure against one secret locks out all the others.
- **A counter per secret,** in PIN Fail slots: as many as the TPM's small NV memory holds, each with its own limit. Each is a hard stop with no timer. A correct value resets it, and once locked, someone with permission must write to it to unlock it.

TPM 2.0 has no way to make one particular secret wait longer after each failure. Its rule language can compare the clock or a stored number only with a fixed value written into the rule when the secret is created. It can't remember when the last failure happened.

Chips that do have per-secret growing delays build them into their own firmware. PinWeaver is Google's version, and it is open source under a 3-clause BSD licence, in `chromiumos/platform/pinweaver`. It is only strong when it runs inside Google's security chip, Cr50 or Ti50. Cr50 is a TPM-like chip whose firmware Google writes, and PinWeaver is an extra command added to it. An ordinary PC's TPM can't run it. The repository also has a backend that uses an ordinary TPM only as storage. There, the delays are enforced by whatever runs PinWeaver's code, and the TPM's job is to stop that code's state being rolled back. The Linux implementation of that backend in the repository uses fixed placeholder keys, so it is reference or test code, not a deployment.

ChromeOS's real PIN schedule (in `platform2`, `cryptohome/auth_blocks/pin_weaver_auth_block.cc`) waits 30 seconds after the 4th failure, and grows to 12 hours per attempt from the 20th. A successful password login resets the PIN's count. That is screenlock-pin's pause, its forgiveness by the password, and its failure budget, held in hardware.

## Method and evidence

- **TPM behaviour** was tested on swtpm 0.10.2 (libtpms) with tpm2-tools 5.7 and tpm2-tss 4.1.3 from Fedora 44, in scratch directories, over TCP. The machine's own TPM wasn't touched. swtpm runs the TCG's reference code; hardware chips run their makers' firmware, which should behave the same but wasn't checked. The PIN Fail and counter experiments are in `docs/analysis/tpm-for-the-lock-screen.md`, in the section What the simulator showed.
- **PinWeaver** was read in a clone of https://chromium.googlesource.com/chromiumos/platform/pinweaver at commit `c77497fedf74823a17d19caf8a0b886c26cc253c` (2026-06-29, "pinweaver: add EAL function for clearing keys"; 163 commits since the initial one on 2021-04-13). Citations are `path:line` in that clone.
- **ChromeOS's use of it** was read from two files of https://chromium.googlesource.com/chromiumos/platform2 on its `main` branch, fetched on 2026-10-18: `cryptohome/auth_blocks/pin_weaver_auth_block.cc` and `cryptohome/auth_session/auth_session.cc`. Line numbers are from those copies and will drift.
- **Web sources** are listed at the end. Anything marked "from memory" was not looked up for this report.

## Rate limiting inside a TPM 2.0

### The global lockout: one counter for every secret

The TPM keeps one failure counter, `failedTries`. Every authorization failure against an object or NV slot that isn't marked `NO_DA` adds one. Three numbers set its behaviour. tpm2-tools shows them as properties, and `TPM2_DictionaryAttackParameters` changes them, which needs the lockout password:

| Setting | tpm2-tools property | Meaning |
|---|---|---|
| `maxTries` | `TPM2_PT_MAX_AUTH_FAIL` | How many failures are allowed before the TPM locks |
| `recoveryTime` | `TPM2_PT_LOCKOUT_INTERVAL` | Every this many seconds, one failure is forgotten |
| `lockoutRecovery` | `TPM2_PT_LOCKOUT_RECOVERY` | How long the lockout password itself stays blocked after a wrong try at it |

`TPM2_DictionaryAttackLockReset` sets the counter back to zero. It needs the lockout password, which is empty on almost every Linux machine, as the section Can TPM access be narrowed in the lock-screen report explains.

Defaults differ by chip. swtpm ships with 3 tries, 1000 seconds and 1000 seconds. Microsoft's blog says Windows sets 32 tries for TPM 2.0 and forgets each failure after 2 hours.

On swtpm, set to 3 tries and one failure forgotten every 4 seconds, with two unrelated secrets A and B (two ordinary NV slots with different passwords):

| Time | What happened | Counter |
|---|---|---|
| 0 s | wrong A | 1 |
| 0 s | right A: accepted, and the counter didn't go down | 1 |
| 0 s | wrong A | 2 |
| 0 s | wrong B: B's failure went into the same counter | 3 |
| 0 s | right B: refused; B was locked out by guesses at A | |
| 5 s | right B: accepted, because one failure had been forgotten | 2 |
| 5 s onwards | one wrong guess at A got through every 4 seconds, and the next was refused | 3 |

So the global lockout protects any number of secrets with one shared budget. That has consequences:

- **Unrelated secrets are coupled.** Guessing at one secret locks out every other, so a TPM+PIN disk unlock can be blocked by someone guessing at an SSH key's PIN.
- **The rate is steady.** After the burst there is one guess per `recoveryTime`, forever. Over a year at Windows' 2 hours, that's about 4,400 guesses.
- **Success doesn't help.** Only time, or the lockout password, lowers the counter.
- **The clock:** as far as I know, on many chips the forgetting only advances while the TPM is powered.
- **Pulling the power** doesn't let an attacker skip the count. A TPM shut down without warning counts that against the counter at the next start (from memory of the specification, not tested).

### A counter per secret: PIN Fail slots

A PIN Fail NV slot (`TPM_NT_PIN_FAIL`) holds its own `pinCount` and `pinLimit`, and must be marked `NO_DA`, so it neither feeds nor obeys the global counter. You can have as many as the TPM's NV memory allows: dozens on a typical chip, not thousands. Tested on swtpm (lock-screen report, section What the simulator showed):

- A wrong value adds one to that slot's count only.
- A correct value sets the count back to zero. So it limits consecutive failures, like a smart card's PIN retry counter.
- At the limit, even the right value is refused (`0x12F`, "authValue or authPolicy is not available").
- It never unlocks by waiting. Someone allowed to write the slot has to reset it.
- The global lockout doesn't block it.

TPM 2.0 also has PIN Pass slots (`TPM_NT_PIN_PASS`), which count successful uses up to a limit, a "use at most N times" rule. They don't limit guessing.

### A hard cap that can't be lowered

A monotonic counter (an NV slot of the counter kind) can only be bumped up by one. Deleting and re-creating it doesn't lower it: on swtpm it went on from 5 to 6. A secret whose rule says "this counter is below N" can't even be tried once the counter reaches N. The lock-screen report tests this in the section A TPM budget that counts every failure. It gives a hard cap per secret that no software can lower, but software has to bump the counter, because the TPM counts failures by itself only in PIN Fail slots, and those reset on success.

### Why there are no growing delays per secret

TPM 2.0 policies (rules that must hold before the TPM allows an action) can look at time and at stored numbers:

- `TPM2_PolicyCounterTimer` compares the TPM's clock or its boot counters with a value.
- `TPM2_PolicyNV` compares the contents of an NV slot with a value.

In both, the value is part of the rule. It is hashed into the policy when the secret is created, so it is a constant. A rule can say "not before this clock value" or "only while this counter is below 8". It can't say "one hour after the last failure", because nothing compares a stored timestamp with the clock. A rule can be made changeable (`TPM2_PolicyAuthorize`, `TPM2_PolicyAuthorizeNV`), but then whoever may sign or write the new rule decides the delay, and that is software again. The TPM's clock is also a weak base for delays. As far as I know, it doesn't run while the TPM is unpowered, and it isn't tied to real-world time.

So with a TPM 2.0, per-secret growing delays are enforced by software, and the TPM can only make that software's state hard to roll back.

## Chips that do per-secret delays

Each of these is a security chip whose own firmware holds the rules:

- **PinWeaver** in ChromeOS's Cr50 and Ti50 chips, described below.
- **Apple's Secure Enclave** enforces growing delays after wrong device passcodes (from memory of Apple's Platform Security guide).
- **Android's Weaver and Gatekeeper** interfaces keep throttling for lock-screen credentials in secure hardware where a device has it, for example the Titan M chip in Pixel phones (from memory).

They all exist because standard TPM 2.0 commands can't express per-credential delay schedules.

## PinWeaver

### What it is, and who owns it

PinWeaver is a protocol and reference implementation for "low-entropy credentials": secrets like PINs, too weak to be stored as a hash. A chip keeps the credentials and decides when each one may be tried. Its code lives at https://chromium.googlesource.com/chromiumos/platform/pinweaver. The `OWNERS` file says "The GSC firmware teams own the code in this repo", and `DIR_METADATA` files it under "ChromeOS > Platform > System > Hardware Security > HwSec GSC". GSC is the Google Security Chip.

**Licence:** `LICENSE` is a 3-clause BSD licence, "Copyright 2021 The Chromium OS Authors". The source files say "Use of this source code is governed by a BSD-style license". It can be reused in screenlock-pin, which is MIT OR Apache-2.0, as long as the copyright notice and licence text are kept.

**Where it runs:**

- **Cr50** (the older chip, H1). PinWeaver runs inside the chip's firmware as a vendor-specific TPM command: `DECLARE_VENDOR_COMMAND(VENDOR_CC_PINWEAVER, pw_vendor_specific_command)` at `eal/cr50/pinweaver_eal.c:439`. The README links the Cr50 firmware to the `cr50_stab` branch of https://chromium.googlesource.com/chromiumos/platform/ec, which I believe is public, but I didn't open it.
- **Ti50** (the newer chip, on a platform called Dauntless). The Ti50 backend used to be in this repository and was removed in commit `ad067fb` (2023-05-11, Matt Vertescher, "ti50: Remove `eal/ti50`"). Its message says "The directory will now live in Ti50", and the commit depends on a `chrome-internal` change, which suggests the Ti50 tree isn't public. Commit `1bb6d78` (2023-07-20) exports the common files for a Ti50 Bazel build of `//platform/ti50/common/libs/pinweaver-sys`. So the common PinWeaver code is shared with Ti50, but I found no public source for Ti50's own firmware.
- **Ordinary TPMs,** only as storage, through the `eal/tpm_storage` backend described below.

### The files

From `README.md` and the tree at commit `c77497f`:

| File | Lines | What it is |
|---|---|---|
| `pinweaver.h` | 202 | The embedded API: the Merkle tree (`struct merkle_tree_t`, lines 40-56), the encrypted part of a leaf (`struct leaf_sensitive_data_t`, lines 81-85), `pw_handle_request` |
| `pinweaver.c` | 2,202 | The implementation: every request handler, the delay check, the log |
| `pinweaver_types.h` | 658 | Types shared with the clients that call PinWeaver: the leaf's public part, the delay schedule, the message types, error codes |
| `pinweaver_eal.h` | 173 | The Environment Abstraction Layer (EAL): what each platform must provide, such as storage, random numbers, AES, SHA-256, HMAC and `pinweaver_eal_seconds_since_boot()` |
| `eal/cr50/pinweaver_eal.c`, `eal/cr50/pinweaver_eal_types.h` | 439, 28 | The EAL for the Cr50 chip |
| `eal/tpm_storage/tpm_storage.c` | 1,487 | The EAL's storage methods on top of an ordinary TPM |
| `eal/tpm_storage/tpm_storage_internal.h`, `pinweaver_eal_tpm.h`, `tpm_storage.h`, `tpm_storage_stubs.c` | 194, 108, 16, 65 | Its internals, TPM handles, and empty stubs |
| `eal/tpm_storage/pinweaver_eal_linux.c` | 480 | The EAL's other methods "for Linux case", which a real platform replaces |
| `eal/tpm_storage/mini_trunks/` | `tss.c` alone is 8,262 | A small TPM software stack, cut down from ChromeOS's trunks and ported from C++ to C (commits `8203ca1` onwards, 2021-04-21) |
| `fuzzer/`, `eal/tpm_storage/fuzzer/`, `eal/tpm_storage/mini_trunks/fuzzer/`, `eal/tpm_storage/test/` | | Fuzzers and unit tests |
| `BUILD`, `BUILD.gn` | | Bazel (for Ti50) and GN build files |

In all, the C and header files come to 18,665 lines, almost half of it the cut-down TPM stack.

### How it stores many credentials in a small chip

The credentials form a Merkle tree, a tree of hashes. Each leaf is one credential, and the chip keeps only:

- the tree's **root hash**, which changes whenever any leaf changes;
- an **HMAC key and a wrap key** (`hmac_key`, `wrap_key` in `struct merkle_tree_t`), which sign and encrypt the leaves;
- a short **log** of the last operations (`PW_LOG_ENTRY_COUNT 2`, `pinweaver.h:37`).

The leaves themselves are stored by the operating system on its normal disk. Each leaf has three parts:

- **A public part** (`struct leaf_public_data_t`, `pinweaver_types.h:204-218`): its label (its position in the tree), its delay schedule, the time of its last attempt (`last_access_ts`), its failure count (`attempt_count`), up to two sets of PCR values it is bound to, an expiry time, and its type (normal or biometrics).
- **An encrypted part** (`struct leaf_sensitive_data_t`, `pinweaver.h:81-85`): three 32-byte secrets.
  - `low_entropy_secret`: the PIN, as the client derived it.
  - `high_entropy_secret`: a strong secret, released only when the PIN is right.
  - `reset_secret`: what the client presents to reset the failure count without the PIN.
- **An HMAC over both,** so the chip notices any change.

When the operating system asks the chip to check a PIN, it sends the leaf and the hashes along its path to the root. The chip checks the HMAC, recomputes the root, and compares it with the one it holds. An old copy of a leaf, for example from before some failures, gives a different root and is refused. That is how one small chip can rate-limit any number of credentials without storing them.

The log covers a crash. If the chip updated its root but the operating system lost the new leaf, `PW_GET_LOG` and `PW_LOG_REPLAY` let the operating system bring the leaf up to date instead of being locked out.

### The delay schedule

`pinweaver_types.h`:

```c
// pinweaver_types.h:105-108, 124-137, 153
struct PW_PACKED attempt_count_t {
	uint32_t v;
};
...
struct PW_PACKED time_diff_t {
	uint32_t v;
};
#define PW_BLOCK_ATTEMPTS UINT32_MAX
...
struct PW_PACKED delay_schedule_entry_t {
	struct attempt_count_t attempt_count;
	struct time_diff_t time_diff;
};
...
#define PW_SCHED_COUNT 16
```

Each leaf carries up to 16 pairs of "after this many failures, wait this many seconds". A wait of `PW_BLOCK_ATTEMPTS` means blocked for good. The client chooses the schedule when it inserts the leaf. `validate_delay_schedule` (`pinweaver.c:460-482`) refuses a schedule unless both columns strictly increase and any unused entries at the end are zero.

`test_rate_limit` (`pinweaver.c:665-724`) decides whether an attempt may go ahead:

- It refuses with `PW_ERR_EXPIRED` if the leaf has an expiry time that has passed, or if the chip has restarted since the expiry was set.
- It finds the last schedule entry whose failure count has been reached, and takes its wait.
- A wait of `PW_BLOCK_ATTEMPTS` refuses for good.
- Otherwise the wait runs from the last attempt if the chip hasn't restarted since, and from the restart if it has. This is the code:

```c
// pinweaver.c:714-717
if (leaf_data->pub.last_access_ts.boot_count == current_time.boot_count)
	ready_time = delay.v + leaf_data->pub.last_access_ts.timer_value;
else
	ready_time = delay.v;
```

- If the wait hasn't passed, it refuses with `PW_ERR_RATE_LIMIT_REACHED` and says how many seconds remain.

Time comes from the platform's `pinweaver_eal_seconds_since_boot()`. On Cr50 that is the chip's own time since its cold boot (`eal/cr50/pinweaver_eal.c:172-175`). Its restart counter goes up whenever PinWeaver starts less than 10 seconds after the chip did (`RESTART_TIMER_THRESHOLD`, `eal/cr50/pinweaver_eal_types.h:17`; the logic is in `eal/cr50/pinweaver_eal.c:211-245`). So a restart can't make an earlier wait look finished: after a restart, the whole wait is counted again from the restart.

### Trying a PIN, and resetting

`pw_handle_try_auth` (`pinweaver.c:1201-1342`) takes these steps:

- It checks the leaf against the tree, then any PCR binding, then `test_rate_limit`. A refused attempt changes nothing.
- It stamps `last_access_ts`, and prepares the failure count plus one before comparing anything.
- It compares the PIN in constant time (`pinweaver_eal_safe_memcmp`). On a match the count becomes 0 for a normal leaf; a biometrics leaf always counts up. On a mismatch it becomes the prepared count plus one.
- It writes the new leaf's root to the log before it commits the new root. Until the log is written, the paths for a right and a wrong PIN take the same time. The comment (`pinweaver.c:1216-1217`) says this removes "a timing side channel that would allow an attacker to prevent the log write", for example by cutting the power the moment a wrong PIN shows.
- It returns `high_entropy_secret` and `reset_secret` only on success. On failure it returns zeros.

`pw_handle_reset_auth` (`pinweaver.c:1345-1422`) compares a `reset_secret` in constant time and sets `attempt_count` back to 0. With `strong_reset` it also restarts the expiry period. Whoever holds the reset secret can unblock a PIN, but can't learn it.

The other message types are `PW_RESET_TREE`, `PW_INSERT_LEAF`, `PW_REMOVE_LEAF`, `PW_GET_LOG`, `PW_LOG_REPLAY` and `PW_SYS_INFO`, plus three for fingerprint unlock: `PW_GENERATE_BA_PK`, `PW_START_BIO_AUTH` and `PW_BLOCK_GENERATE_BA_PK` (`pinweaver_types.h:269-287`).

### The backend for ordinary TPMs

The commit that created the backends, `511fc2c` (2021-04-14, Andrey Pronin), describes "two implementations: cr50 and generic Linux with TPM storage". In the second one, `pinweaver.c` doesn't run in the TPM. It runs wherever the platform puts it, and the TPM only stores the tree's state:

- **NV slots:** the tree descriptor, a "persist" entry and up to five log entries (`MAX_LOG_ENTRIES 5`, `tpm_storage_internal.h:57`). Their handles start at `TREE_DESCRIPTOR_HANDLE`, which is `NV_INDEX_FIRST + 0x00800000 + 7`, that is `0x01800007` (`eal/tpm_storage/pinweaver_eal_tpm.h:20-22`). The slots are defined with `TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_NO_DA` (`eal/tpm_storage/tpm_storage.c:220`), and their contents are encrypted with AES-256-CTR before they are written.
- **Sessions are salted.** The salt is encrypted to an ECC key at persistent handle `SALTING_KEY_HANDLE`, `PERSISTENT_FIRST + 4`, that is `0x81000004`. Before use, the key's type, curve and attributes are checked (`REQUIRED_SALTING_KEY_ATTR`: fixedTPM, fixedParent, decrypt, sensitiveDataOrigin; `tpm_storage_internal.h:63-64`). Its hash is compared with one provisioned earlier (`verify_salting_key_public` and `generate_session_salt`, `tpm_storage.c:374-472`). This is the "salted sessions, with the TPM's key checked against the one recorded at set" that screenlock-pin's notes ask for.
- **The Linux EAL is not a deployment.** `eal/tpm_storage/pinweaver_eal_linux.c` fills the three device keys with fixed bytes 0x01, 0x00 and 0xFF (`pinweaver_eal_get_device_key`, lines 198-212). It keeps the committed TPM key hash in `/tmp/pw_tpm_key_hash` (line 22), and it takes time from `sysinfo()`'s uptime (lines 189-196). The README says a platform using the TPM-storage option "needs to implement all EAL methods implemented in `pinweaver_eal_linux.c` (or use it as-is, if Linux compatible)". The commit history mentions a "pinweaver_client selftest". I found no record of which production platform, if any, uses the TPM-storage backend.

So when an ordinary TPM is only the storage, the delays are only as strong as the place `pinweaver.c` runs. On a platform with an isolated environment, such as a secure co-processor or a trusted execution environment, that can be strong. As root on a normal Linux PC, it's software. What the TPM adds is that the state can't be rolled back, and that the stored data is encrypted and authenticated.

A side note on handles: pinpam keeps its version tags at `0x01800000` plus the uid, and PinWeaver's TPM backend uses `0x01800007` onwards, so the two would collide for uids 7 to 13 (the tree descriptor, the persist entry and five log entries). That shows the point in the lock-screen report that nobody hands out TPM handles.

### How ChromeOS uses it

The client is cryptohome, in `platform2`.

- **The schedules,** in `cryptohome/auth_blocks/pin_weaver_auth_block.cc` (lines 72-143 of the copy read):

  | Failures reached | Wait for a PIN (`PinDelaySchedule`) | Wait for a password (`PasswordDelaySchedule`) |
  |---|---|---|
  | 4 | 30 s | |
  | 6 | 1 min | |
  | 9 | 10 min | 30 s |
  | 11 | | 1 min |
  | 12 | 30 min | |
  | 14 | 1 h | 10 min |
  | 16 | 2 h | |
  | 17 | | 30 min |
  | 18 | 5 h | |
  | 19 | | 1 h |
  | 20 | 12 h | |
  | 21 | | 2 h |
  | 23 | | 5 h |
  | 25 | | 12 h |

  The password schedule carries the comment "TODO(b/172221456): finalize the policy". The older schedule, `LockoutDelaySchedule`, is `{kLockoutAttemptLimit = 5, kInfiniteDelay}`: five failures, then blocked for good. PINs still on an older schedule are flagged for re-creation when they are next used ("PIN factor is using obsolete delay schedule", around lines 495-510).
- **The password resets the PIN.** After a successful login with a factor that isn't itself a PinWeaver credential, `AuthSession` calls `ResetLECredentials()` ("Reset LE Credential counter if the current AutFactor is not an LECredential", `cryptohome/auth_session/auth_session.cc`, around lines 912-916). That function (around line 4226) resets every PinWeaver-backed factor whose count isn't zero, using the reset secret, which the password login has unwrapped.
- **The PIN releases key material.** On success, the `high_entropy_secret` is turned into the key for the user's encrypted home (`vkk_seed` and `vkk_key`, `pin_weaver_auth_block.cc`, around lines 511-513). So a ChromeOS PIN can open the home directory, not just the lock screen, and that is safe only because the chip limits guessing.

Two things stand out. The current PIN schedule has no hard cap: after 20 failures it allows one guess every 12 hours, without end, about 730 a year. And the reset after a password login is the same design as screenlock-pin's housekeeping, enforced by the chip instead of by a setgid program checking the password through `unix_chkpwd`.

## What it means for screenlock-pin

- **The design matches.** screenlock-pin's pause after 3 failures in a row, its forgiveness when the password is typed, and its budget over days and in total are close to what ChromeOS does with PinWeaver: growing waits, and a reset by the password. The difference is where it is enforced. ChromeOS uses its own chip; screenlock-pin uses a setgid program and a group that has no members.
- **screenlock-pin is stricter in one way.** Its total of 60 failures per PIN is a hard cap. ChromeOS's current PIN schedule has none, so a patient attacker gets two guesses a day for as long as they like. Against a 6-digit PIN that is about 1 in 1,400 a year (730 of a million).
- **PinWeaver can't run in a PC's TPM.** On a normal Linux PC, the TPM-storage backend would mean running `pinweaver.c` as a helper with TPM access, as root or setgid `tss`. Its delays would then be as strong as that helper, the same as screenlock-pin's PIN checker today. The TPM would add rollback protection and encrypted state, and bring with it every cost the lock-screen report lists, the access problem first.
- **Worth borrowing, under the BSD licence:**
  - the delay schedule as data, a list of "after N, wait T" pairs checked to be increasing (`validate_delay_schedule`, `test_rate_limit`);
  - the order in `pw_handle_try_auth`: compute the failure before comparing, compare in constant time, and write the log before committing;
  - measuring a wait from a restart when the clock restarted, never assuming time has passed;
  - the reset secret, a separate secret that unblocks without revealing the PIN, as an idea for how a password could unpause the PIN without the PIN checker checking the password itself. That idea brings back part of the pepper's cost, a secret tied to the password, which screenlock-pin dropped on 2026-10-16.
- **A correction** to what I said in conversation on 2026-10-18: I said that with an ordinary TPM, PinWeaver's delays "are enforced by software on the main CPU". More precisely, they are enforced by wherever the platform runs `pinweaver.c`. The repository's Linux implementation of that environment is reference and test code with fixed keys, and I found no production platform that uses it.

## Sources

- PinWeaver repository: https://chromium.googlesource.com/chromiumos/platform/pinweaver, read at commit `c77497fedf74823a17d19caf8a0b886c26cc253c`
- PinWeaver README (stabilize-16197.B): https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/refs/heads/stabilize-16197.B/README.md
- PinWeaver tree at stabilize-15610.B, with the Ti50 build commit: https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/refs/heads/stabilize-15610.B
- The Cr50 firmware, as linked from the README: https://chromium.googlesource.com/chromiumos/platform/ec/+/refs/heads/cr50_stab
- trunks, the TPM stack mini_trunks was cut from: https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/trunks/
- cryptohome's PinWeaver auth block: https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/cryptohome/auth_blocks/pin_weaver_auth_block.cc
- cryptohome's auth session: https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/cryptohome/auth_session/auth_session.cc
- Microsoft on TPM lockout, with Windows' 32 tries and 2 hours: https://learn.microsoft.com/en-us/archive/blogs/dubaisec/tpm-lockout
- Microsoft on how the TPM mitigates dictionary attacks: https://technet.microsoft.com/en-us/jj889440
- OpenTitan, the open silicon root of trust inspired by Google's Titan chips: https://opensecura.googlesource.com/3p/lowrisc/opentitan/+/refs/heads/master/doc/introduction.md
- OSFC 2024, "Open source all the way down: developing firmware in parallel with open silicon": https://www.osfc.io/2024/talks/open-source-all-the-way-down-developing-firmware-in-parallel-with-open-silicon
- From memory, not opened for this report: Apple's Platform Security guide on Secure Enclave passcode delays, and Android's Weaver and Gatekeeper interfaces.
- The swtpm experiments, the PinWeaver clone and the fetched cryptohome files are in this session's scratch directory, not in the repository.
