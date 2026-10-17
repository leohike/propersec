# Complexity as layers

A short note, written on 2026-10-16, on how added complexity in properpin could make it safer rather than riskier: by making each new piece an extra check that must also agree, never a replacement for an existing one. It came out of weighing a TPM against the simplicity of the current design (`docs/chaos/competition.md` has the comparison with pinpam that led here). Nothing here is built; it records a design direction for the plan's TPM row and for any future use of the PIN for `sudo`.

## The idea

A PIN unlocks only when every layer agrees, and any layer saying no sends the user to the password:

- **A simple total limit,** in software: every failure counts, typos included, against a generous limit of several hundred; the count only ever goes up, and only `set` resets it. A few dozen lines in a file of its own, sharing nothing with the budget but the lock.
- **The forgiving budget,** in software, as built: typos forgiven by a correct PIN or password within 45 or 90 seconds, suspicious failures limited per day, per week and per PIN. The good user experience lives here, and so does the most room for subtle mistakes.
- **The TPM,** in hardware: the PIN can be checked only by asking the TPM, which counts every failure itself since the last password unlock, and whose counter only the password can reset (the "option 4" design: a per-user PinFail index, with the secret sealed under a policy that requires authorising it with KDF(pepper‖PIN)).

A bug has to get through all of them to matter. That works in properpin because a wrong "no" is cheap: the password still works. In pinpam, where a wrong "no" is a lockout only root can lift, stacking layers would cost far more.

## What each layer survives

- **Logic bugs** in any one counter (a wrong comparison, a window off by one, forgiveness forgiving too much): the other layers still refuse. Rust prevents memory bugs, not logic bugs, so mutation testing should run on each layer separately.
- **Code running inside the pinchecker,** through an exploit: every software layer falls at once, since they all run in the process the attacker now controls. Only the TPM survives, and only if the PIN can be checked nowhere but in the TPM. This is what makes the TPM worth more than a third counter.
- **Without a TPM,** the two software layers still hold against logic bugs, as properpin does today.

## Conditions, or the layering is an illusion

- **Independence.** No shared parsing, state or code path between the layers beyond the lock, so one bug can't break two at once.
- **One small place decides.** The pinchecker's exit code, the PAM control flags and the check that the PIN is enabled: if any single place says "unlock" without asking every layer, all of them are bypassed. Keep it a few lines long, and test that removing any one layer still refuses, the way the product README's "broken on purpose" checks already work.
- **Count before checking,** in every layer, as the existing counting order requires; the TPM does it by itself.
- **No secret escapes.** The layers limit guessing, not the use of a known PIN, so a leak bypasses all of them. For the TPM code that means:
  - salted sessions, with the TPM's key checked against the one recorded at `set`;
  - only KDF(pepper‖PIN) sent, never the raw PIN;
  - authorisation values and session keys wiped, and no buffers in logs;
  - policies proved by tests on swtpm that must fail: unseal without the PIN, reset without the password, read with a wrong PIN.
- **No downgrade.** Once a user is enrolled with the TPM, a missing, busy or failing TPM refuses the PIN; it never falls back to the software checks alone.
- **No crackable copy.** On a machine enrolled with the TPM, the yescrypt hash must not stay on disk as a fallback: it can be cracked offline, past every layer. The fallback without a TPM is the password, not a software PIN hash.
- **Every refusal names its layer** in the log, so a wrong "no" can be traced.

## What no layer covers

A PIN captured as it is typed, by malware running as the user or by someone watching, and root on the running machine waiting for the next unlock. These are the limits of any PIN scheme, and the README should say so.

## When

The lock-screen PIN ships without a TPM. The simple total limit is cheap and could come first, on its own merits. The TPM layer belongs with the PIN for `sudo`: there a compromised pinchecker would otherwise be a way to root, which is exactly the case only the TPM survives. Implementation notes, if it is built: pure Rust is possible through `tpm2-protocol` (by the Linux kernel's TPM maintainer) with RustCrypto for the session cryptography, tested against swtpm in CI; for `sudo`, the PAM module runs as root inside `sudo` and can check the PIN itself, as pam_unix does there, so the pinchecker plays no part in that decision.
