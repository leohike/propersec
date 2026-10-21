# A TPM for the lock-screen PIN

What it would take to back screenlock-pin's lock-screen PIN with the computer's TPM, how much of pinpam's TPM design a PIN for the lock screen alone could drop, and how much complexity the TPM brings in just by being used. Written on 2026-10-18. One of screenlock-pin's premises is that a TPM for the lock screen alone is both overkill and too complicated. This report checks the second claim. It looks at the first only as far as needed to decide whether the effort would pay. A PIN for `sudo` is out of scope, except where it shows why the lock screen is the harder case.

## The short answer

The TPM part itself would be small. The TPM 2.0 standard has a storage slot made for PINs, the "PIN Fail" index. It keeps the PIN as its password and counts wrong tries. Once the count reaches a limit, it refuses even the right PIN, and a correct PIN sets the count back to zero. On the swtpm simulator it behaved exactly like screenlock-pin's pause: three wrong tries locked it, the right PIN before that reset the count, and a write like the one the housekeeping would make after a password unlock made it usable again. A lock-screen design needs one such slot per user and four operations: create, check, reset and delete. Most of what pinpam builds around the same slot can go: its write-once policy, its version tags and migrations, its two helper runs per attempt, its policy file and its master key. The TPM logic would be a few hundred lines, about the size of screenlock-pin's budget code.

What doesn't shrink with the scope is what the TPM brings with it:

- **A TPM software stack inside the setgid PIN checker.** That is either about 1.1 MB of C libraries from tpm2-tss plus OpenSSL, one of them loaded at run time where `install.sh check` can't see it, or TPM session code that screenlock-pin writes itself on top of a Rust crate that only builds and parses commands.
- **Access to `/dev/tpmrm0` for the PIN checker's group.** On Linux that access is all or nothing. On a stock machine, whose TPM administrator passwords are empty, it lets whoever holds it delete or replace anything in the TPM, including other software's disk-unlock data. An exploited PIN checker would go from being able to read PIN hashes to being able to damage everything every program keeps in the TPM.
- **Everything else around it:** state that disappears when the TPM is cleared, limits on writes, a new set of error codes, a second code path for machines without a TPM, and swtpm in every layer of testing.

For a lock-screen PIN, the gain is small. Mostly it is what the pepper gave until 2026-10-16: a copy of the files becomes useless. `docs/chaos/security-target.md` judged that not worth keeping. The rest is the pause held in hardware, which protects only against bugs in the smallest counter screenlock-pin has. The TPM doesn't stop the slow attack that the budget exists for, because it forgets all failures at every correct PIN. It doesn't survive an exploited PIN checker either, because the PIN checker would need TPM access. In fairness, the TPM gives what the pepper gave without the pepper's costs: no password after every boot, and changing the password doesn't break the PIN.

So "overkill" holds. "Too complicated" is half true. The PIN logic itself would get no harder. What grows is the privilege picture, which gets worse, and the plumbing, which gets bigger: roughly 1,300 to 1,900 lines with tests, plus a trust problem that no amount of code solves on a stock Linux machine. The lock screen is also the TPM's worst fit on Linux. Its PAM module runs as the user, so something the user can start has to be given TPM access. `sudo`'s module already runs as root and needs no such grant.

Two questions asked after the first version are answered further down. A TPM budget that counts every failure and never forgives can be built: a counter that only goes up, and a PIN index that the TPM won't check once the counter reaches its limit. Software still has to add each failure, and `set` moves the limit. TPM access can be narrowed to a small separate helper, and the administrator can set a lockout password. That makes a break less likely, but whoever breaks the helper still gets the TPM's owner powers. For other programs using the TPM, the loss is mostly in availability (wiping, refusing) rather than in secrets, with one exception: TPM keys protected by a PIN lose their hardware guess limit.

Two findings about pinpam came out along the way, both confirmed only on swtpm so far. First, pinpam's write-once policy stops anyone from resetting the counter by writing to it, but a correct PIN still resets it. Someone with repeated access therefore gets the limit minus one guesses after every unlock by the user, without end. That is the gap screenlock-pin's budget closes, and pinpam's code comments say the opposite. Second, pinpam talks to the TPM in sessions without a salt. Someone who records the bus of a discrete TPM chip while the PIN is used could then try PINs offline at the speed of a fast hash.

## Method and evidence

- **pinpam** was read in the clone at `/var/home/shared/projects/pinpam-tpm`, commit `1c22a94` of 2026-06-22 (version 0.0.5). All of `pinpam-core`, `pinpam-pam`, `pinutil`, `README.md` and `SECURITY.md` was read; `master_key.rs` and `flake.nix` were skimmed. Citations are `path:line` in that clone.
- **screenlock-pin** was read at commit `784ebc7`: `README-BIG.md`, `docs/analysis/summary.md`, and `complexity-as-layers.md`, `competition.md`, `security-target.md`, `threat-insider-hash-leak.md`, `review-of-dropping-the-pepper.md`, `plan.md` and `current-concerns.md` under `docs/chaos/`.
- **Experiments** ran on swtpm 0.10.2 (libtpms) with tpm2-tools 5.7 and tpm2-tss 4.1.3, all from Fedora 44, in a scratch directory and over TCP. The machine's own TPM was not touched. Its device node is `root:tss 0660`, and nothing was run as root. swtpm runs the TCG's reference code. Vendors' firmware is meant to behave the same way, but no hardware TPM was checked for this report, so "verified" below always means "verified on swtpm". The section Checking on real hardware below has a script for that.
- **Web sources:** the source of tss-esapi's `execute_with_nullauth_session` on docs.rs (identical in 7.6.0 and 7.7.0), notes on the `tpm2-protocol` crate, and the man page of systemd-tpm2-setup. Anything marked "inferred" was reasoned from code or documents, not tested. Anything marked "from memory" was not looked up for this report.

## Words used here

- **TPM:** a small security chip, or firmware, that holds keys and secrets and does some checks by itself. A *discrete* TPM is a separate chip on the mainboard, connected by a bus (LPC, SPI or I2C), and someone with the machine in their hands can attach a probe to that bus. A *firmware* TPM (Intel PTT, AMD fTPM) runs inside the processor and has no external bus.
- **NV index:** a small slot of the TPM's own non-volatile memory (memory that keeps its contents without power), at a fixed address called a handle, such as `0x01000000`. It survives reboots. It has a public part (its size, attributes, hash algorithm and policy) and an *authorization value*: a password the TPM checks before letting anyone use the slot.
- **Name:** the hash of an object's public part. Policies and checks refer to an object by its Name. The Name does not include the authorization value.
- **PIN Fail index** (`TPM_NT_PIN_FAIL`): an NV index whose 8 bytes are two numbers, `pinCount` and `pinLimit`. A wrong authorization value raises `pinCount` by one. Once `pinCount` reaches `pinLimit`, the TPM refuses the authorization value altogether.
- **Dictionary-attack (DA) lockout:** the TPM's single, global failure counter. Every object in the TPM shares it unless the object is marked `NO_DA`. Too many failures anywhere lock all the objects it protects for a while. A PIN Fail index must be marked `NO_DA`, so its failures don't count towards this lockout, and the lockout doesn't block it.
- **Owner and lockout hierarchies:** two of the TPM's administrative roles. The owner creates and deletes NV indexes. The lockout role resets the DA counter and can clear the whole TPM. Each role has a password of its own. It stays empty until someone sets it, and on Linux nobody usually does.
- **Policy:** a list of conditions that must hold before the TPM allows an action, such as "this command, and only while the slot is still unwritten".
- **Session:** the way a command carries its authorization. A *password session* sends the value in clear. An *HMAC session* sends a keyed hash computed from it instead. A *salted* session also mixes in a random value encrypted to a key inside the TPM, which someone listening on the bus can't recover.
- **Resource manager:** `/dev/tpmrm0`, the kernel's shared entry point to the TPM, which keeps different programs' sessions apart. It does not filter commands: anyone who can open it can send any command.
- **TSS:** the TPM software stack, meaning the library a program uses to build TPM commands. tpm2-tss is the C one, and tss-esapi is the Rust wrapper around it that pinpam uses. A **TCTI** is the small plug-in through which the stack reaches the TPM: the kernel device, a simulator or a daemon.

## How pinpam uses the TPM

Each user gets a PIN Fail index at `0x01000000` plus their uid (`pinpam-core/src/pinindex.rs:8-22`). Its authorization value is the PIN itself: digits only, 4 to 8 of them by default (`pinpam-core/src/pinpolicy.rs:29-39`, `78-104`). `setup_pin` defines the index with these attributes:

```rust
// pinpam-core/src/pinmanager.rs:432-438
let attributes = NvIndexAttributesBuilder::new()
    .with_nv_index_type(NvIndexType::PinFail)
    .with_auth_read(true)
    .with_owner_read(true)
    .with_policy_write(true)
    .with_no_da(true)
    .build()?;
```

In plain words: the PIN can read the slot, which is the check; the owner can read the counts, which is how the status is shown; and writing needs a policy. The policy has two conditions: the command is `NV_Write`, and the index has not been written yet (`pinmanager.rs:429-431`). So the slot can be written exactly once, to set `pinCount` to 0 and `pinLimit` to the configured number of attempts. After that nobody can write to it, root included. Only deleting the slot, which the owner can do, ends a lockout, and it deletes the PIN with it. This is pinpam's answer to the second threat in its `SECURITY.md`: root resetting the counter in order to find a PIN that the user also uses elsewhere.

A second index per user, at `0x01800000` plus the uid, holds a one-byte format version (`pinmanager.rs:238-344`). `verify_pin` uses it to migrate PINs saved before version 0.0.4, which had lost their leading zeros (`pinmanager.rs:143-173`, `pinpam-core/src/util.rs:5-12`).

The check is a read of the slot, with the PIN as its authorization (`pinmanager.rs:175-222`). On success the TPM returns the counts. After a wrong PIN, pinpam reads the counts again as the owner, to tell "wrong" from "wrong, and now locked".

The TPM is reached through `pinutil`. It is installed setgid to the `tss` group, or setuid root, together with a udev rule that gives that group `/dev/tpmrm0` (the Manual installation section of pinpam's README). The PAM module runs as whoever the service runs as. For each attempt it runs `pinutil -m status <user>` and then `pinutil -m test <user>` with the PIN on stdin, and reads JSON back (`pinpam-pam/src/lib.rs:92-195`, `599-706`). That is two runs of a privileged program per attempt. `pinutil` limits its own file writes and network use with Landlock (`pinutil/src/sandbox.rs`). It ignores a policy file that root doesn't own or that others can write (`pinpolicy.rs:236-264`). It lets any process with effective uid 0 test anyone's PIN, because `su` and `sudo` check other users' PINs (`util.rs:25-39`).

The PAM module supports `try_first_pass` and `use_first_pass` (`pinpam-pam/src/lib.rs:205-291`). Input that isn't all digits, or has the wrong length, never reaches the TPM. That has a side effect which matters below. In a single field where the user may type either secret, a password containing a letter never costs a TPM try.

The master key (`pinpam-core/src/master_key.rs` and the `pinpam-master-key-pam` crate) is a separate feature. It derives a per-user token from a key held in the TPM, so that KWallet or GNOME Keyring can open at a PIN login. At the lock screen the wallet is already open, so none of it applies here.

### What pinpam's counter really limits

When a PIN Fail index accepts the right authorization value, the TPM itself sets `pinCount` back to zero. pinpam's write-once policy only forbids writes, and this reset is not a write. On swtpm, an index built like pinpam's (same attributes, same policy, made with tpm2-tools) refused a second write ("a policy check failed") and refused a write by the owner. Even so:

| Round | Wrong guesses | Then the user's correct PIN | `pinCount` afterwards |
|---|---|---|---|
| Each of rounds one to five | 2 | accepted | 0 |

That made ten wrong guesses in five rounds against a limit of 3, and the index never locked. So pinpam limits consecutive failures only. Someone who can reach the keyboard again and again gets `pinLimit` minus one guesses after every correct PIN, without end. Where pinpam is in `sudo`'s stack, "someone" includes code running as the user. pinpam's code comments say the opposite: "A failed attempt permanently consumes a TPM lockout slot" (`pinpam-core/src/util.rs:25-27`), and "Each wrong attempt permanently consumes a TPM lockout slot" (`pinutil/src/main.rs:481`). Its README is right that a lockout lasts until root clears the PIN, but only consecutive failures can cause one. Its tests check only consecutive failures (`pinpam-core/tests/swtpm_pin.rs:62-90`).

This is exactly the gap that the section The failure budget in `README-BIG.md` describes for screenlock-pin's own consecutive count ("someone with repeated access could guess twice whenever you step away, forever") and closes in software. It should be confirmed on a hardware TPM before anyone tells pinpam's author. `docs/chaos/competition.md` already suggests talking to them.

### Sessions without a salt

Every pinpam command runs inside tss-esapi's `execute_with_nullauth_session` (for example `pinmanager.rs:111` and `183`). In tss-esapi 7.7.0 that function starts an HMAC session with no salt key and no bind object:

```rust
// tss-esapi 7.7.0, src/context.rs, read on docs.rs; the first three arguments are
// the salt key, the bind object and the nonce
let auth_session = match self.start_auth_session(
    None,
    None,
    None,
    SessionType::Hmac,
    SymmetricDefinition::AES_128_CFB,
    HashingAlgorithm::Sha256,
)? {
```

In a session like this, the PIN is the only secret behind the keyed hash, and everything else that goes into the hash crosses the bus. Someone who records the bus of a discrete TPM while the PIN is used can then test PIN guesses offline, at one cheap hash per guess, and the TPM never counts them. Published research on the buses of discrete TPMs has gone after BitLocker's disk keys (from memory), and the same kind of recording applies here. There are two ways to close this. One is a salted session; the salt key must be the TPM's real one, which means recording its public part at a trusted moment and checking it on every use. The other is to make the authorization value expensive to compute from the PIN, which is what the design below does. Firmware TPMs have no external bus to record.

## What the simulator showed

| Question | On swtpm | Why it matters |
|---|---|---|
| Can a PIN Fail index be defined without `NO_DA`? | No, refused | Its failures can never count towards the global lockout |
| Can it be used before its first write? | No, refused | `set` must write the counts right after defining it |
| A wrong PIN | Refused with `0x9A2`, "authorization failure without DA implications"; `pinCount` goes up by one | The TPM counts before it answers, so a caller killed at the wrong moment can't avoid the count |
| The right PIN | Accepted; `pinCount` back to 0 | It counts consecutive failures, like screenlock-pin's pause, not all failures |
| The right PIN once `pinCount` equals `pinLimit` | Refused with `0x12F`, "authValue or authPolicy is not available for selected entity" | This is the pause, in hardware |
| The owner writes 0 and 3 to a locked index | Accepted; the right PIN works again | This would be the housekeeping's unpause, if the index lets the owner write |
| An index made like pinpam's (written once, through a policy) | A second write and an owner write are both refused; the right PIN still resets the count | See the section What pinpam's counter really limits above |
| Does a correct PIN write to NV memory? | Not when `pinCount` is already 0 (the simulator's state file stayed the same); yes when it is 1 | Wear grows with failures, not with unlocks |
| The TPM in global DA lockout (caused through another, DA-protected index) | The PIN Fail index still accepted the right PIN; its own failures never raised the global counter | Lockouts caused by other TPM users don't break the PIN, and the PIN's failures don't lock them out |
| Authorization values ending in zero bytes | `31 32 00 00` and `31 32` were both accepted | Trailing zero bytes don't count. For values of a fixed 32 bytes that can't make two different values equal, but about one value in 256 ends in a zero byte, so a test should cover it |
| A monotonic counter (an NV index of the counter kind) bumped 5 times, then deleted and defined again | The new counter went on from 5 to 6; a plain write to it was refused | No one can lower a counter, not even by re-creating it |
| A PIN index readable only through a policy "counter below 8, and the PIN" | Accepted the right PIN while the counter was 6. A wrong PIN still raised its own `pinCount`. Once the counter reached 8, it refused before the PIN was even tried | The TPM itself can enforce a budget kept in a counter |
| Only the lockout password set | Clearing the TPM and resetting the global lockout were refused; deleting an owner index, creating a key under the owner and extending a PCR were still allowed | What setting that password takes away from whoever can open the device |
| The owner password set as well | Deleting an owner index was refused, and so was creating a key under the owner without that password | Blocks replacing indexes, but also breaks tools that create keys under the owner with an empty password |
| Authorization values longer than 32 bytes on a SHA-256 index | 33 to 50 bytes accepted, and every byte checked; tpm2-tools refused 64 | As I understand the specification, it limits the value to the hash's size, and implementations enforce that differently. Hashing to exactly 32 bytes avoids the question; screenlock-pin's PINs can be 64 characters, which is more bytes than that in UTF-8 |

## The smallest TPM design for screenlock-pin's lock screen

This takes screenlock-pin as it stands: the setgid PIN checker, the budget, the `check` line that runs before the stock password check (so everything typed reaches it), and the housekeeping after a correct password. The TPM is added as a layer beside the software, in the sense of `docs/chaos/complexity-as-layers.md`: the PIN unlocks only when every layer says yes.

Each user gets one PIN Fail index:

| Part | Value | Plain meaning |
|---|---|---|
| Handle | A fixed base plus the uid | Nobody hands these out. pinpam uses `0x01000000` and `0x01800000` plus the uid, so screenlock-pin would choose another base, check at `set` that the handle is free, and never touch an index whose public part isn't the one it made |
| Type and attributes | PIN Fail, `NO_DA`, `AUTHREAD`, `OWNERREAD`, `OWNERWRITE` | The PIN reads the index (the check); the owner reads the counts (`status`, `doctor`) and writes them (the unpause) |
| `pinLimit` | 3 | screenlock-pin's pause |
| Authorization value | 32 bytes derived from yescrypt of the PIN, with a salt of the user's own | See the section on yescrypt below |
| Contents | `pinCount` 0 and `pinLimit` 3, written right after the index is defined | |

What each part of screenlock-pin would do:

- **`sudo screenlock-pin set`** works as today. Then it deletes the user's old index, if any, defines the new one, writes its counts, and stores the salt and the handle in `/etc/screenlock-pin/users/<user>` instead of the hash. No hash of the PIN stays anywhere on disk. A hash kept as a fallback could be cracked offline, past the TPM, as the condition "No crackable copy" in `complexity-as-layers.md` says.
- **The check in the PIN checker** works as today up to the decision: it takes the lock, checks whether the software has paused or disabled the PIN, and counts the attempt in the budget first. Then it runs yescrypt on the input with the salt, and reads the index in an HMAC session with the result. Success means yes, unless the software's own rules say no. A wrong value means no, and the TPM has counted it too. "Not available" means paused in hardware. Anything else (no TPM, a TPM error, a TPM that is busy) refuses the PIN and leaves the password. Every refusal is logged with the layer that gave it. A user enrolled with the TPM never falls back to the software layer alone.
- **The housekeeping**, after `unix_chkpwd` has accepted the password, works as today. In addition, if `pinCount` isn't 0, it writes 0 and 3 as the owner.
- **`remove`** deletes the index, then removes the files as today. **`status`** and **`doctor`** read the counts as the owner, check that the index exists with the expected public part, and say which layer refuses. That check catches someone else's index at the handle. It can't catch a deliberate replacement; the section Device access is all or nothing below says why.

The password typed at the lock screen is why the index has to be writable. screenlock-pin checks everything typed as a PIN first. So every password unlock is a TPM failure until the housekeeping resets the count, and "typo, typo, password" locks the index on the password itself. pinpam avoids this by allowing only digits, which keeps most passwords away from the TPM. screenlock-pin allows any characters in a PIN, so it can't copy pinpam's write-once design.

### Why the authorization value comes from yescrypt

People often say a TPM makes the PIN's strength irrelevant. That is only true while nobody can see the authorization value or anything computed from it. There are three places where it might be seen: on the bus of a discrete TPM; inside the TPM itself, since published attacks have extracted the whole state of firmware TPMs (faulTPM against AMD's fTPM, 2023, from memory); and in the PIN checker's memory while it runs. If the value is yescrypt of the PIN and its salt, at today's cost, none of these gives an attacker more than today's hash file does: one yescrypt per guess.

That makes the design much simpler. The session needs no salt, so there is no TPM key to create or find, no fingerprint of that key to record at `set` and check every time, and no session-key derivation. A plain HMAC session is enough. It also lets the PIN checker check that the TPM's answer is genuine, because the answer is signed with a keyed hash whose key the attacker doesn't have. The price is one yescrypt per check, about 18 ms at cost 5, which screenlock-pin already pays today. A salted session would instead need a key in the TPM. systemd 255 and later can keep one at `0x81000001` and publish its public part in `/run/systemd/tpm2-srk-public-key.*`, but on this machine, with systemd 259, that file doesn't exist. screenlock-pin would therefore have to create a key on every check, which is slow on many chips (not measured here), or keep one of its own at a persistent handle: one more thing to own and check.

### What the design drops from pinpam

| pinpam's piece | For the lock screen | Why |
|---|---|---|
| The write-once policy, and with it policy sessions | Dropped | The password must be able to unpause. In screenlock-pin's threat model root wins anyway (`docs/chaos/security-target.md`) |
| A lockout that only root can lift | Dropped | The pause ends at the next password unlock; the long-term limits stay in the software budget |
| The version-tag index and the two migrations | Dropped | The format version goes in the user file on disk, and there are no existing installs to migrate |
| Two privileged runs per attempt, with JSON | Dropped | The PIN checker runs once and answers with an exit code, as it does today |
| Digits only, 4 to 8 of them | Dropped | The value is hashed to 32 bytes |
| `try_first_pass`, `use_first_pass`, its own prompts, other services | Dropped | One field, one service |
| A policy file naming `pinutil_path` and `tcti` | Dropped | The paths are on the PAM line. The TPM is always `/dev/tpmrm0`; tests reach swtpm only through `--dev` options, which work only without privilege |
| Root may test anyone's PIN | Dropped | The PIN checker answers only about its caller |
| Landlock | Optional | screenlock-pin's clean start already covers more, and Landlock can't limit which commands go to the TPM anyway |
| The master key and the keyring token | Dropped | The wallet is already open at the lock screen |
| One PIN Fail index per user, `NO_DA` | Kept | This is the TPM part |
| The owner reading the counts | Kept | For `status` and `doctor` |

### What it needs that pinpam doesn't have

- A count that can be written, reset only after the PIN checker has checked the password.
- An authorization value derived through yescrypt, so that the bus and a broken TPM give away no more than today's file.
- Agreement between the layers. The software's consecutive count and the TPM's count should match. When they don't (a write that failed, an attempt that was killed), the PIN is refused, and `doctor` names the TPM layer.
- No hash on disk, and no fallback to the software layer for a user enrolled with the TPM.
- A check at `set` that the handle is free, and a check on every use that the index's public part is the one `set` made.

## A TPM budget that counts every failure

The idea, added on 2026-10-18 after the first version of this report: if screenlock-pin used a TPM, it would most likely hold one more budget category, beside the software ones. That category would count every failure, typos and passwords typed at the lock screen included. Nothing would forgive a failure, and only `set` would start the count over.

The TPM can't count failures like that by itself. A PIN Fail index forgets all its failures at the first correct PIN, as the section What the simulator showed above found. The only failure counter in the TPM that a success doesn't reset is the global DA counter. Everything in the TPM shares it, the disk unlock with a TPM and PIN included, and it forgets failures over time. Feeding screenlock-pin's typos into it would lock the disk unlock out.

What the TPM can do, as tested on swtpm, is keep a number that only ever goes up and refuse to check the PIN once that number reaches a limit:

| Index | Kind | How it is used |
|---|---|---|
| The budget | A monotonic NV counter, one per user | It can only be bumped up by one. Deleting and re-creating it doesn't lower it: on swtpm it went on from 5 to 6, and as I understand the specification, a new counter starts at the highest value any counter on that TPM has ever had |
| The PIN | A PIN Fail index, readable only through a policy: "the budget counter is below N, and the authorization value is right" | `set` puts N into the policy: the counter's value at that moment plus the size of the budget. The index must not also be readable with the PIN alone (no `AUTHREAD`), or the PIN would get past the limit. Its own `pinLimit` can be set very high, so it never pauses in hardware and no housekeeping write is needed |

Software still decides when to add a failure. The order has to be "check, then count": the helper tries the PIN, and bumps the counter only if the TPM said no. Counting before the check, as screenlock-pin does in software, would count correct PINs too, because a counter can't be taken back down. "Check, then count" leaves a window: a helper killed between the TPM's answer and the bump adds nothing. The lock screen killing its worker doesn't open that window, because the helper is a separate process that finishes on its own, as the PIN checker does today. Only code running as the user can kill the helper itself, and only for that user's own PIN, and screenlock-pin's threat model already gives such code the session.

What it buys over the simple total limit in software, which `docs/chaos/complexity-as-layers.md` proposes: no software bug can lower the count, restoring old files can't either, and the TPM refuses past the limit even if screenlock-pin's own refusal code is wrong. What it doesn't buy: a helper that has been exploited simply skips the bump, and whoever can open the device can replace the PIN index, as the section Device access is all or nothing below explains. It is worth more than a software counter only if the TPM is also the only thing that can check the PIN, with no hash on disk.

What it costs:

- **Passwords count.** screenlock-pin's `check` line sees every input before the stock password check, so every password unlock spends one failure, and so does every typo, for the PIN's whole life. The limit has to be generous, "several hundred" as `complexity-as-layers.md` suggests. Users will still reach it now and then, and run `set` again.
- **A reset path still exists, at `set`.** But it doesn't reset anything. It re-creates the PIN index with a new limit, and only root runs it. The counter itself is never touched.
- **Every failure is a write** to the TPM's NV memory: a few a day.

It also helps with the access problem that the section Can TPM access be narrowed below discusses: since nothing on the lock-screen side ever resets the TPM's counts, the program holding TPM access needs no password check and no reset command, so it can be very small.

## What the TPM brings in, however small the design

### A TPM software stack inside the PIN checker

There are two choices, and neither is small.

**tss-esapi**, the Rust wrapper over the C library tpm2-tss, which pinpam uses. The PIN checker would link libtss2-esys (604 KB on Fedora 44), libtss2-sys (160 KB), libtss2-mu (298 KB) and libtss2-tctildr, and through them OpenSSL's libcrypto. The TCTI loader opens the device plug-in, libtss2-tcti-device, by name at run time. `install.sh check-build` judges what a binary loads by reading it with readelf and ldd, which can't see a library opened at run time, so the check would need a new rule for that. The build would need clang (for bindgen) and tpm2-tss-devel, which isn't installed on this machine. pinpam's `Cargo.lock` lists 234 crates; screenlock-pin's lists 83 (both counting crates used only by tests). Today the PIN checker links only libc and libxcrypt, and the Rust code it runs with the screenlock-pin group comes to under 4,000 lines, unit tests included: 866 in `crates/checker`, 1,608 in `crates/core` and 1,439 in `crates/sys`.

**Pure Rust**, with `tpm2-protocol`. It is written by the Linux kernel's TPM maintainer, licensed MIT or Apache-2.0, uses no standard library and has no dependencies; its first standalone release, 0.10.0, came out in August 2025. It builds and parses commands and leaves policy to the caller. Since it has no dependencies, it can't do any cryptography (inferred). So the keyed hash of every command and response, the nonce handling, and anything salted would be screenlock-pin's own code, built on RustCrypto crates: `sha2` and `hmac`, plus `p256` and `aes` only if sessions were salted. The unsalted HMAC session this design needs is roughly 150 lines, plus test vectors. Talking to the device is trivial: write a command to `/dev/tpmrm0`, then read the answer. This route adds no C and keeps the build check as it is. But screenlock-pin would then own security-critical protocol code that few people will ever review, built on a young crate.

### Device access is all or nothing

The PIN checker runs as the user, with the screenlock-pin group added. On this machine `/dev/tpmrm0` is `root:tss 0660`, set by tpm2-tss's `/usr/lib/udev/rules.d/60-tpm-udev.rules`. There are three ways to let the PIN checker in:

- A udev rule that gives the screenlock-pin group an ACL on the device (an ACL is an extra permission entry beyond owner, group and others). This is the simplest. As an untested sketch:

  ```
  # /etc/udev/rules.d/70-screenlock-pin-tpm.rules (a sketch, never tried)
  KERNEL=="tpmrm[0-9]*", SUBSYSTEM=="tpmrm", RUN+="/usr/bin/setfacl -m g:screenlock-pin:rw /dev/%k"
  ```

- Making the PIN checker setgid `tss` instead, and moving screenlock-pin's files to that group, which other TPM software uses too.
- A service running as root, listening on a socket, which does the TPM part and learns the caller's uid from the kernel. That is a new root process, which is exactly what screenlock-pin avoided by making the PIN checker setgid only.

The kernel doesn't filter TPM commands: whoever can open the resource manager can send any command. As far as I know, Windows sends programs' TPM commands through its TPM Base Services, which block some commands for ordinary programs, and ChromeOS goes through daemons. On Linux, the owner and lockout passwords are almost always empty. Running `tpm2_getcap properties-variable` as root shows this, in `ownerAuthSet` and `lockoutAuthSet`; this report didn't run it. Setting those passwords isn't screenlock-pin's call, since every other TPM user on the machine would then need them.

So whatever group can reach the TPM can delete or redefine any owner index, screenlock-pin's or anyone else's, reset the global lockout, and clear the TPM. Today an exploited PIN checker can read every PIN hash but can't change anyone else's files. With TPM access, it couldn't read a PIN any more, but it could wipe or change what other software keeps in the TPM, including the disk-unlock enrollments of systemd-cryptenroll. It could also replace another user's index with one whose PIN it knows. An index's Name doesn't include its authorization value, so nothing screenlock-pin could check would notice the swap.

Could a cleverer arrangement of TPM objects survive this? This part is reasoned, not tested. Anything the check relies on lives either in owner NV memory, which that group can replace, or behind the global DA counter, which the lockout role resets. So on a machine with empty administrator passwords, no arrangement of TPM objects protects the PIN from someone who can open the device; the TPM protects it from everyone else. pinpam has the same exposure through its setgid `tss` pinutil. It matters more there, because pinpam's PIN can also open `sudo`. Its README warns only that others could delete or reset PINs, not replace them.

### Can TPM access be narrowed

This question came up after the first version of this report. A screenlock-pin that holds TPM access makes every other program that uses the TPM depend on screenlock-pin's code too. Is that fixable with permissions that aren't too complex?

First, how much "less secure" means for other TPM users. On a stock machine only root opens the TPM today, and this machine's `tss` group has no members. The table assumes someone who has broken into the program holding TPM access, running as an ordinary local user. This is reasoned, not tested.

| What uses the TPM | What that attacker gains |
|---|---|
| Disk unlock with the TPM alone (systemd-cryptenroll) | They can't unseal the disk key, because its sealed blob is in the LUKS header, which only root can read. They can clear the TPM or delete what the unlock depends on, so the next boot asks for the recovery key or passphrase |
| Disk unlock with the TPM and a PIN | The same. They can also trigger the global lockout, so the TPM refuses the PIN at the next boot until the lockout wears off. Resetting the lockout only helps someone who also holds the blob, which takes root |
| Keys kept in the TPM with a PIN (tpm2-pkcs11, an SSH agent) | Where they can read a key's blob, they can reset the global lockout between guesses at its PIN, so the TPM's guess limit no longer protects it. On machines where users use such keys, the users are usually in the `tss` group already, so nothing changes there |
| Measured boot and attestation | They can extend PCRs (the registers that record what booted), so this boot fails attestation and anything sealed to those PCRs can't be unsealed until the next reboot. They can't make a PCR show a value it didn't reach |
| systemd's encrypted credentials | Like disk unlock: the blobs are files only root can read |

So the loss is mostly in availability: an attacker can make the TPM forget or refuse things. Secrets sealed in the TPM stay as safe as the files that hold their blobs. The exception is TPM keys protected by a PIN, whose hardware guess limit an attacker can reset. All of it needs a code-execution bug in the program that holds the access first, so the access makes such a bug worse; it doesn't open anything by itself.

The levers, from cheapest to dearest:

- **Groups, ACLs and SELinux** decide who may open `/dev/tpmrm0`. None of them limits what is sent once it is open. As far as I know, the Linux kernel has no filter for TPM commands.
- **A separate helper that holds the access,** in the style of `unix_chkpwd`. The PIN checker keeps everything it has now and gets no TPM access. A second program, say `screenlock-pin-tpm`, setgid `tss`, does only the TPM part: `check`, which tries a value against the caller's own PIN index and counts a failure; `status`; and `enroll` and `remove`, for root only. It takes the user from the kernel (the real uid), computes the handles from it, and never takes a handle, a command or a policy from its caller. It gets 32 bytes on stdin that the PIN checker derived with yescrypt and a salt that only the screenlock-pin group can read, so a user who runs it directly can't produce a right value and can only spend their own budget. With the budget from the section A TPM budget that counts every failure above, it needs no password check and no reset, so screenlock-pin's own part of it is a few hundred lines. The C stack or the session code still comes with it. Exploiting the PIN checker then gives what it gives today; exploiting the helper gives the TPM. This makes such a break less likely. It doesn't make it any less serious.
- **The lockout password,** set to a random value that only root keeps, or thrown away. On swtpm this stopped whoever could open the device from clearing the TPM and from resetting the global lockout, but not from deleting owner indexes, creating keys or extending PCRs. It is a change to the whole machine, so it is the administrator's call. screenlock-pin can recommend it, but must not do it itself, since screenlock-pin doesn't change the system's defaults to suit itself. If the password is thrown away, lockouts can only wear off with time, and the TPM can only be cleared from the firmware's setup screen.
- **The owner password** would also stop indexes being deleted or replaced. But on swtpm it also refused creating a key under the owner without that password, and some tools do that with an empty password every time they run. As far as I know, that includes clevis's TPM pin, and systemd when it has no persistent key. So it isn't an option.
- **A root service** with the same narrow interface as the helper. It narrows the access just as well, but the process holding the TPM then runs as root.

So the answer is yes, partly. A small separate helper and, where the administrator wants it, a lockout password together bring the exposure down to "a bug in a few hundred lines of screenlock-pin plus its TPM library gives a local user the TPM's owner powers". That is roughly the bargain Linux already makes with `unix_chkpwd` and `/etc/shadow`. It can't go to zero: with the owner password empty, any process that can open the device has every power that empty password gives. The only way to add no exposure at all is for the lock screen not to need the TPM.

### State that can disappear

- **Clearing the TPM** removes every index. That happens from the firmware's setup screen, from Windows, when the mainboard is replaced, and on some AMD machines when a firmware update offers or requires resetting the firmware TPM. Each PIN is then refused, the password still works, and `doctor` says to run `set`. screenlock-pin's design makes this harmless, since a refused PIN costs one password. With pinpam as the only way into a service, it would be a lockout.
- **A disk moved to another machine, or restored from a backup,** has user files pointing at indexes that don't exist there. That is the point of the TPM, but `doctor` must tell this apart from damage.
- **In a virtual machine,** the virtual TPM's state is a file on the host, so "nothing to crack" holds only as far as the host protects that file.

### NV memory, handles and wear

- **Writes:** NV memory is written by failures, by the correct PIN that follows a failure, and by the housekeeping's reset, so a few times a day. TPMs can endure only a limited number of writes, and some throttle them; a TPM may answer `TPM_RC_NV_RATE` when written too often. That answer must become a refusal, and a test should cover it.
- **Space:** a TPM holds only a limited number of indexes. One 8-byte index per user is fine for a family machine. On a machine with many users the space could run out, and `set` must say so plainly.
- **Handles:** with no registry, the handle base is a guess at what other software leaves alone. Checking at `set` that the handle is free catches collisions only at that moment.

### Machines without a usable TPM

Some machines have no TPM, or an old TPM 1.2. Some VMs have no virtual TPM, and the podman container has none. So the software path stays, which means two paths, both tested, for as long as screenlock-pin exists, plus a choice per user at `set`. Making the TPM mandatory would drop screenlock-pin from machines it works on today.

### Testing

- **swtpm per test.** pinpam's harness (`pinpam-core/tests/common/mod.rs`, 161 lines) starts one swtpm per test, on free TCP ports. screenlock-pin's PIN checker would reach it only through a `--dev` option, allowed only without privilege, like its existing ones.
- **The container test** would need swtpm inside the container. It could reach it over TCP through that same option, or as a real `/dev/tpmrm` device through the kernel's vTPM proxy (`tpm_vtpm_proxy`), which needs root and that module on the host. The CI's rootful podman could probably do the second (inferred).
- **Tests that must fail:** a wrong value doesn't read; the index locks at 3; a missing TPM, a busy TPM, someone else's index at the handle, and a cleared TPM all refuse the PIN while the password still works. Resetting the count without the right password is a rule of the PIN checker, not of the TPM, so it is tested there.
- **The kill tests:** a worker killed in the middle of a TPM command. The TPM finishes the command anyway, and the PIN checker isn't killed with the worker (it already finishes on its own today).
- **Hardware:** swtpm runs the reference code, while chips run their makers' firmware. The reset on success, the error codes and the timing need checking by hand on at least one discrete chip and one firmware TPM, since CI has no TPM.
- **Mutation testing** of the new layer on its own, as `complexity-as-layers.md` asks for each layer.

### Timing at the lock screen

Each check costs one yescrypt (about 18 ms) plus three or four TPM commands: start the session, read the index's public part, read the index, and close the session. Discrete TPMs take from milliseconds to tens of milliseconds per command; that wasn't measured here. The module already waits until 75 ms have passed, so the question is whether the slowest path stays acceptable on a slow chip. The TPM handles one command at a time, so simultaneous attempts queue behind each other and behind other TPM users, such as disk unlock at boot.

## How big it would be

These are estimates in lines of Rust, unless marked otherwise, for the design above.

| Piece | Pure Rust with `tpm2-protocol` | tss-esapi |
|---|---|---|
| Talking to `/dev/tpmrm0` | about 60 | a few lines, plus the C stack |
| The commands used (`StartAuthSession`, `NV_DefineSpace`, `NV_Write`, `NV_Read`, `NV_ReadPublic`, `NV_UndefineSpace`, `FlushContext`) | about 200 | about 100 |
| An unsalted HMAC session | about 150 | provided |
| TPM answers mapped to yes, no, paused and unavailable, with retries | about 80 | about 80 |
| PIN checker: the check, the housekeeping's reset, the status, agreement between layers | about 150 | about 150 |
| CLI: `set`, `remove`, `doctor` and `status`, and the user file's new format | about 150 | about 150 |
| `install.sh`: device access, `check`, `uninstall` | 60 to 100 lines of shell | the same |
| Shipped, in total | about 850 to 900 | about 550, plus about 1.1 MB of C libraries |
| Tests: the swtpm harness, unit tests, the PIN checker against swtpm, container scenarios | about 800 to 1,000 | about 700 to 900 |

For comparison, screenlock-pin's shipped crates come to 4,935 lines today, its tests and harnesses to 3,836, and `install.sh` to 584. pinpam's TPM PIN code (`pinmanager.rs`, `pinindex.rs`, `pindata.rs` and `tcti.rs`) is 651 lines, and this design would drop about a third of it: the policy session, the version tags and the migration.

So the TPM would add between an eighth and a fifth to screenlock-pin's code. It would also add much more to what the privileged program depends on, a new permission on a device, and a hardware test that CI can't run. The logic is the smallest of these.

## What it would buy

The table follows the attackers in `docs/chaos/security-target.md`, plus two that matter here.

| Attacker | screenlock-pin today | With the TPM design |
|---|---|---|
| Someone at the locked keyboard, guessing | 3 guesses, then the password; the budget allows 10 a day, 25 a week and 60 per PIN | The same. The pause is held by the TPM as well, so a bug in the software's consecutive count no longer gives extra guesses; the budget stays in software only |
| Someone watching the PIN being typed | A short secret, typed often | The same |
| Code running as the user | Can't read the hash, but can unlock the session directly | The same |
| Root on the running machine | Wins | Wins: it can reset the count and guess online, or read the PIN as it is typed |
| Someone who steals files (a backup, a disk image, a disk sent for repair) | Gets a hash that falls in seconds for a short PIN | Gets a salt and nothing to crack. **This is the TPM's real gain** |
| Anyone who can read RAM | Could recover the hash, but takes the disk key instead | The same |
| An exploited PIN checker, for example another local user's code | Reads every user's hash; can't change anyone's files | Can't read PINs, but can damage everything in the TPM and replace any user's PIN. **Worse, not better** |
| Someone recording a discrete TPM's bus (new) | Not applicable | Gets no more than today's hash file would give, thanks to yescrypt; with a fast-hash value or pinpam's sessions it would be worse than today |
| Reuse of the PIN on a phone or a card | A copied hash leads to it | Copies don't lead to it; watching still does |

The gain is the row that the pepper covered until 2026-10-16. `docs/chaos/security-target.md` explains why that row is worth little for a PIN that opens only the lock screen. To use the PIN, the attacker who read the files must also come back to the locked keyboard later, and anyone who could read those files as root could do far worse anyway. The fair comparison is with the pepper: the pepper's costs were mostly in how screenlock-pin is used (the password after every boot, a PIN broken by every password change), while the TPM's costs are mostly in engineering and trust.

## Why the lock screen is the TPM's worst fit on Linux

The lock screen's PAM module runs as the locked user. To use the TPM, it needs a privileged bridge, and that bridge has to be given TPM access, which the user can then start at will. `sudo`'s module runs as root, inside `sudo`, so it can talk to the TPM with no new permission at all. As `docs/chaos/complexity-as-layers.md` notes, it can check the PIN itself, the way `pam_unix` does there, so no PIN checker is involved. The TPM is therefore cheaper for `sudo`. That doesn't make it more valuable there: the TPM still forgets failures at every correct PIN, so a `sudo` PIN would still need a budget in software, kept by a module running as root, and against code running as the user, such a root-owned budget is already out of reach. That note's reason for putting the TPM with `sudo` was that only the TPM survives an exploited PIN checker. With the module checking the PIN as root there is no PIN checker to exploit. Where there is one, it holds TPM access and so doesn't survive either. The note's case for a TPM with `sudo` needs restating before that work starts.

## Alternatives not pursued

- **A FIDO2 security key with a PIN** (pam-u2f): the retry counter lives in the key, and nothing on the computer can reset it. It needs a key to carry. `docs/analysis/summary.md` covers it.
- **ChromeOS's PinWeaver** (from memory, not read for this report): a protocol in Google's own security chip that limits low-entropy credentials, with delays that grow after failures and a reset secret released by the password. That is screenlock-pin's budget, in hardware. As far as I know, Google built it because standard TPM 2.0 objects can't express it. It isn't available on ordinary PCs.

## Recommendation

- **Don't build TPM support for the lock screen.** Keep the premise, but change its reason. The TPM logic isn't complicated; it is a few hundred lines. The problem is that using a TPM from the lock screen on Linux means giving TPM access to something the user can start, and in that scope it buys only what the pepper bought. The README's plan to "add TPM support in a systemic way such that more complex code does not simply increase the attack surface" should say that, for the lock screen, the attack surface grows mainly through the device access, not through the code.
- **If it is built anyway,** prefer the budget from the section A TPM budget that counts every failure to the pause in hardware. It needs no reset after a password unlock, so the TPM access can sit in the small separate helper described in the section Can TPM access be narrowed. Keep the rest of the section The smallest TPM design for screenlock-pin's lock screen: pure Rust, an authorization value from yescrypt, unsalted HMAC sessions, no hash on disk, and the device-access trade-off stated in the README, together with a recommendation that the administrator set a lockout password.
- **Confirm the two pinpam findings on hardware,** then tell pinpam's author.
- **Correct `docs/chaos/complexity-as-layers.md`,** which this report didn't edit. Its TPM layer "counts every failure itself since the last password unlock", but on swtpm a correct PIN resets the count, so the TPM counts consecutive failures since the last correct PIN or reset. Its claim that only the TPM survives an exploited PIN checker doesn't hold where the PIN checker needs TPM access and the administrator passwords are empty. Its condition of salted sessions with a recorded key can be replaced by deriving the authorization value through yescrypt.

## Checking on real hardware

These commands only read; none of them changes what the TPM stores. Run them by hand, as root:

```
# commands to type, as root; they read the TPM and change nothing
tpm2_getcap properties-fixed         # the maker, the firmware version, the NV limits
tpm2_getcap properties-variable      # ownerAuthSet, lockoutAuthSet, inLockout, the DA settings
time tpm2_getrandom 16 > /dev/null   # the time one command takes
```

The script below does change the TPM, briefly. It creates a temporary PIN Fail index, tries a wrong PIN and the right one, prints the counts and the time of a check, and deletes the index when it exits. It refuses to run if the handle is already in use, and it never deletes an index it didn't create. It needs the owner password to be empty; if it isn't, the first `tpm2_nvdefine` fails, which also answers a question. It was tested only against swtpm.

```
# a script to run by hand, as root, on the real TPM; tested only against swtpm
set -e
h=0x01500016
if tpm2_getcap handles-nv-index | grep -qi "${h#0x0}"; then echo "$h is in use; pick another handle"; exit 1; fi
tpm2_nvdefine $h -C o -s 8 -a "ownerwrite|ownerread|authread|no_da|nt=pinfail" -p 1234 >/dev/null
trap 'tpm2_nvundefine $h -C o' EXIT
f=$(mktemp); printf '\0\0\0\0\0\0\0\3' > "$f"; tpm2_nvwrite $h -C o -i "$f"; rm -f "$f"
tpm2_nvread $h -C $h -P 9999 -s 8 >/dev/null 2>&1 || true
echo "after one wrong PIN:   $(tpm2_nvread $h -C o -s 8 | od -An -tx1)"
time tpm2_nvread $h -C $h -P 1234 -s 8 >/dev/null
echo "after the right PIN:   $(tpm2_nvread $h -C o -s 8 | od -An -tx1)"
```

On swtpm it printed `00 00 00 01 00 00 00 03` after the wrong PIN and `00 00 00 00 00 00 00 03` after the right one. If a hardware chip prints `00 00 00 01` the second time, a correct PIN doesn't reset its count, and both pinpam's comments and the design above would need revisiting. This script uses a password session, so it says nothing about the timing of an HMAC session. That would be one more command per check.

## Sources

- pinpam: the clone at `/var/home/shared/projects/pinpam-tpm`, commit `1c22a94`, and https://github.com/RazeLighter777/pinpam
- tss-esapi, `execute_with_nullauth_session`: https://docs.rs/tss-esapi/7.7.0/src/tss_esapi/context.rs.html
- tpm2-protocol: https://kernel.googlesource.com/pub/scm/linux/kernel/git/jarkko/tpm2-protocol/ and the release note at https://social.kernel.org/users/jarkko/media
- systemd-tpm2-setup and its SRK files: https://www.mankier.com/8/systemd-tpm2-setup.service
- Microsoft on the TPM's global dictionary-attack lockout: https://learn.microsoft.com/en-us/archive/blogs/dubaisec/tpm-lockout and https://technet.microsoft.com/en-us/jj889440
- From memory, not opened for this report: research on recording the bus of discrete TPMs to recover BitLocker keys (Pulse Security, 2019, and later work), and "faulTPM: Exposing AMD fTPMs' Deepest Secrets" (2023).
- The experiments' commands and the swtpm state are in this session's scratch directory, not in the repository; the tables above give their results.
