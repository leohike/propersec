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
- `freetext_salt_needed_for_deriving_pepper_decryption_key`, stored on disk

```
pepper_decryption_key = hash(user password, freetext_salt_needed_for_deriving_pepper_decryption_key)
pepper = decrypt(encrypted_pepper, pepper_decryption_key) # stored in ram for prolonged periods

checking pin:
hash(pin, pepper) == hash_of_peppered_pin
```
