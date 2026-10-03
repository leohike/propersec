# Pepper terminology

The names fixed on 2026-10-03 for the pepper design: a random secret mixed into the PIN hash, kept in clear text in RAM only, and on disk only encrypted with a key derived from the user's password.

## Why the complexity

Linux can store a hash of the password directly, because a password is meant to have enough entropy that even a stolen hash gives nothing away, and the hash is hard to steal anyway.

A PIN doesn't have that luxury: by definition it has much less entropy, so a hash of the PIN alone is a vulnerability. So we mix a random pepper into the PIN hash, and on disk keep that pepper only encrypted with a key derived from something that already exists and is assumed to have enough entropy: the password. The PIN piggybacks on the password's entropy, which gives better UX while giving up nearly nothing in security, at least for real people, as opposed to a perfect human willing to type a fully random password at every login.

PS: the pepper has to be encrypted on disk. Stored there in clear text, next to the hash, it would be a mere salt, which yescrypt already has built in, and a clear-text salt doesn't protect a low-entropy secret from brute force: it only stops precomputed tables and cracking many hashes at once.

## The names

- `hash_of_peppered_pin`, on disk
- `encrypted_pepper`, on disk
- `clear_text_pepper` - in ram only
- `pepper_decryption_key` - derived from user password only, never stored, briefly exists in ram
- `cleartext_salt_for_deriving_pepper_decryption_key`, stored on disk

```
pepper_decryption_key = hash(user password, cleartext_salt_for_deriving_pepper_decryption_key)
clear_text_pepper = decrypt(encrypted_pepper, pepper_decryption_key) # stored in ram while the PIN is armed

checking pin:
hash(clear_text_pepper, pin) == hash_of_peppered_pin
```

## As built

Built on 2026-10-03; what was left for later is in `docs/pepper-issues.md`.

```
clear_text_pepper     = 32 random bytes from /dev/urandom, made by `properpin set`
pepper_decryption_key = yescrypt(user password, cleartext_salt_for_deriving_pepper_decryption_key), its 43 characters decoded to 32 bytes
encrypted_pepper      = clear_text_pepper XOR pepper_decryption_key
clear_text_pepper     = encrypted_pepper XOR pepper_decryption_key
hash_of_peppered_pin  = yescrypt(hex(clear_text_pepper) + pin), with yescrypt's own salt inside
```

- **`hash` is yescrypt** through libxcrypt in both places, the library `/etc/shadow` uses. `pepper_decryption_key` is derived at `seal_cost` (default 8, about a tenth of a second), the PIN hashed at `hash_cost` (default 5).
- **`decrypt` is XOR**, a one-time pad, safe because `set` makes a fresh salt, and so a fresh `pepper_decryption_key`, every time. Nothing checks the result: a wrong password decrypts to a wrong pepper, never to "wrong password". So the files on disk give a password guesser nothing to test a guess against, short of guessing the PIN too.
- **The pepper comes first, as 64 hex digits.** Its fixed length keeps it apart from the PIN.
- **`cleartext_salt_for_deriving_pepper_decryption_key`** has this same name in the code and in the user file. It is a whole yescrypt setting, `$y$<cost>$<salt>`, so it carries the cost it was sealed with.
- **Where each lives:**
  - `hash_of_peppered_pin`, `cleartext_salt_for_deriving_pepper_decryption_key` and `encrypted_pepper` are in `/etc/properpin/users/<user>`, owned by root and readable by the helper's group only;
  - `clear_text_pepper` is in the per-boot state, `/run/properpin/<uid>.state`, owned by the user and readable only through the helper, while the PIN is armed;
  - `pepper_decryption_key` exists only inside `properpin set` and the helper's `arm`, wiped after use.
- **The flows:**
  - `sudo properpin set` asks for the PIN twice and the password, checks the password through `unix_chkpwd`, seals, and arms at once;
  - each password unlock checks the password the same way, then decrypts the pepper into the state;
  - any refusal wipes it from there: expired, 3 failures in a row, or disabled;
  - a password change makes the PIN stop matching until the next `set`.
