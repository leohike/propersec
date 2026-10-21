# Physical versus remote attacks

A short note, written on 2026-10-16, on the two kinds of attacker an authentication prompt faces, the idealized tool that best stops each, and why each tool is weak against the other kind. It came out of deciding against a PIN for `sudo` in screenlock-pin (`docs/chaos/pin-for-sudo.md`), and explains why screenlock-pin's PIN belongs at the lock screen. "Idealized" means the tool as its design intends, without implementation flaws; how real tools fall short is covered further down.

## The two attackers

- **The physical attacker** is at the machine: a flatmate, a colleague, a thief, someone with a camera behind you. They can touch the device, watch you, take objects from your desk or bag, and, at worst, take hold of you while you sleep or by force. They are slow, they are one person at one place, and every guess costs them presence and risk.
- **The remote attacker** is code: malware running as you, a compromised program, someone in over SSH with a stolen key. They can type anything, read your screen and what you type wherever your uid can reach, fake any prompt, replay anything they captured, and guess at machine speed at three in the morning. They can't touch anything: no button, no finger, no object.

Each prompt mostly faces one of them. The lock screen exists because someone may be physically present while you are away; the remote attacker is already inside the session it guards. `sudo` on an unlocked session exists because code running as you shouldn't become root; a physical attacker at your unlocked, unattended session has already won most of what matters.

## Against the physical attacker: a PIN

The idealized tool is a knowledge factor with a strict guessing limit: a PIN, typed on a path only the device reads, behind a counter that sends you to a long password after a few failures.

- **It lives in your head.** Nobody can take it from your bag, from your desk or from your sleeping hand. Getting it takes your cooperation.
- **The guessing limit makes guessing hopeless.** A few tries, then the password: even four digits hold, and two random words hold against anyone.
- **Its one gap is being watched.** Even an idealized PIN is seen as it is typed, and the PIN is typed often. Nothing in the PIN itself helps against that; a longer PIN, typed with care, only makes it harder.

## Against the remote attacker: physical presence

The idealized tool is a physical action bound to the request: a touch on a device that shows what you are approving ("sudo: dnf install …, touch to allow"), or a fingerprint read and matched on that same device.

- **It is the one thing code can't produce.** Malware can type, read and replay, but it can't press a button or put a finger on a reader.
- **It can't be replayed.** Each touch approves one request; capturing it gives nothing for the next.
- **Binding to the request matters.** Without a display on the device, malware can time its own request to match yours and take the touch you meant for your own. The idealized tool shows what it approves.
- **A fingerprint does a little more than a touch.** It needs your finger, not just the object, so it also stops a walk-up at your unlocked desk; a key alone stops only code.

## Why each fails against the other

- **A PIN against the remote attacker.** Everything that makes it strong against a person is about the person: nobody can take it from you. Code doesn't need to take it. It captures it as you type, through a fake prompt, a keylogger or by reading the process that asks for it, whenever that process runs as your uid. Once captured, it works forever. Short of capture, code can guess without tiring, at any hour, timed around your own correct entries. A PIN resists code only when it is typed on a path code can't reach: on the device itself, or into a prompt that runs outside the user's uid.
- **Physical presence against the physical attacker.** Everything that makes it strong against code is that it needs something physical, and that is exactly what this attacker has. A key needs only possession: left plugged in or carried in the laptop bag, it unlocks for whoever holds it. A finger can be taken from someone asleep or held, and courts in several countries compel fingerprints more readily than passcodes. No cooperation is needed for either.
- **The pattern.** Each tool's strength is the other attacker's capability. A remote attacker can do anything except act physically; a physical attacker can act physically but can't read your mind. So the knowledge factor fits the physical threat, and the physical factor the remote one.

## Combining them

When a prompt faces both attackers, the factors combine, each covering what the other can't. FIDO2 does exactly this with user verification: a PIN plus a touch on the key. The PIN stops whoever holds the key, and the touch stops code that captured the PIN. Neither alone covers both.

## Where real tools fall short

- **Fingerprint readers** that match on the host, through fprintd, can be fooled more easily than the idealized reader, and a lifted print can be cast into a fake with effort.
- **Most FIDO keys have no display,** so a touch isn't bound to the request it approves.
- **kscreenlocker's greeter runs as the user,** so screenlock-pin's PIN is not on a path code can't reach. This doesn't matter at the lock screen, whose attacker is physical, and is one more reason the PIN doesn't belong at `sudo`.

## For screenlock-pin

| Prompt | Its attacker | The idealized tool |
|---|---|---|
| The locked screen | Physical: someone at the keyboard | A PIN with a strict guessing limit, which screenlock-pin is |
| `sudo` on an unlocked session | Remote: code running as you, or someone in over SSH | A touch or a fingerprint, bound to the request |
