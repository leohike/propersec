# Planted lock files: a known denial of service

A known weakness of the setgid helper layout, written on 2026-10-03 when that layout was built. It is accepted for now: the PIN fails closed and the password still works. This doc describes it and a fix to make later.

## What happens

`/run/properpin` is `root:properpin 1770`: the helper's group may create files there, and the sticky bit lets only a file's owner replace or delete it. Each user's `<uid>.lock` and `<uid>.state` are created by the helper running as that user, so they belong to that user.

Someone who has the `properpin` group can create `<alice uid>.lock` before alice's first attempt of the boot. From then on:

- alice's helper opens the lock file, sees bob owns it, and refuses: "owned by uid 1001, not 1000" goes to the log;
- it can't delete or replace the file, because the directory is sticky and the file isn't alice's;
- so alice's PIN is refused until the next reboot clears `/run`. Her password still unlocks.

A planted `<uid>.state` does nothing more: a state file that isn't the user's own reads as no state, which requires the password.

**The failure budget has the same weakness, and it lasts longer.** `/var/lib/properpin` follows the same rules on disk. A `<uid>.budget` planted in alice's name is refused the same way, and since it isn't cleared at reboot, her PIN stays refused until root runs `properpin set`, which deletes the budget whoever owns it. The fix below applies to both directories.

## Who can do it

Only someone who already has the `properpin` group. The group has no members and a locked password, so in practice that means someone who has exploited a bug in the helper. Such an attacker can already read every PIN hash. Blocking one user's PIN until reboot is minor next to that, and it is visible in the log.

Tested by the container scenario "counts planted in another user's name are refused" and the local tests `a_lock_file_planted_by_someone_else_is_refused` and `a_state_file_planted_by_someone_else_reads_as_none`.

## The fix to make later

Give each user a directory of their own that only root creates:

- `/run/properpin/` becomes `root:properpin 0750`, no longer writable by the group;
- `/run/properpin/<uid>/` is `<uid>:properpin 0700`, holding that user's `state` and `lock`;
- `properpin set` (as root) adds `d /run/properpin/<uid> 0700 <user> properpin -` to a generated `/etc/tmpfiles.d/properpin-users.conf` and creates the directory for the current boot; `properpin remove` takes the line out again.

Nobody but root can then create anything in another user's place: the group can't write to `/run/properpin`, and another user's helper can't write to alice's directory. The user herself still can't reach her directory, because she can't enter `/run/properpin`.

What it costs:

- `set` and `remove` write a second file under `/etc`, and `install.sh check` has to compare it with the user files;
- a user without that line has no state directory, so their PIN fails closed until `set` runs again;
- the directory check changes from one directory at `1770` to a parent at `0750` and a per-user directory at `0700` owned by the caller.

Alternatives considered and rejected:

- **Delete a foreign lock file:** the sticky bit stops alice's helper, by design.
- **Pick another name when the lock file is foreign:** whoever can plant one name can plant every name, since the group can list the directory.
- **Clean up with a timer running as root:** it closes the window only after the fact, and adds a root service.
