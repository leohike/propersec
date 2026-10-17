# Planted lock files: a denial of service, now closed

A weakness of the setgid helper layout, written up on 2026-10-03 when that layout was built and closed on 2026-10-17. Git history keeps the full write-up and the per-user directories it proposed as the fix.

## What it was

Each user's lock file, and later their budget, lived in a directory shared by all users, `root:properpin 1770`, and was created by the pinchecker at that user's first attempt. Someone with the `properpin` group, which in practice meant someone who had exploited a bug in the pinchecker, could create `<alice uid>.lock` before alice's first attempt. Her pinchecker then saw that bob owned it and refused her PIN, and the sticky bit kept it from deleting the file. Her password still worked. A planted budget did the same. A reboot cleared the lock file while it was in `/run/properpin`.

**Since 2026-10-16** the lock file sits next to the budget in `/var/lib/properpin`, since `/run/properpin` went with the pepper, so a reboot no longer cleared a planted one; `sudo properpin set` and `remove` deleted it along with the budget instead.

## How it was closed

**Since 2026-10-17** `sudo properpin set` creates both the lock file and the budget, as root, owned by the user, and the pinchecker only ever opens them: a missing one refuses the PIN, and nothing creates one but `set`. While a user's files are there, the sticky bit stops anyone else's run replacing them, so nobody can plant one in that user's name; planting needs the files gone first, which only root can do. `set` also replaces whatever stands where the lock file should be, and an attempt that was waiting on a lock file deleted meanwhile is refused rather than trusting a lock that keeps nobody out.

The budget's temporary files are the one thing the pinchecker still creates there, under random names, so nobody can plant the one the next write takes.

Tested by the container scenario "counts planted in another user's name are refused" and the local tests `a_missing_or_planted_lock_file_is_refused`, `set_replaces_anything_in_place_of_the_lock_file` and `remove_waits_for_the_lock_and_a_replaced_lock_file_is_refused`.
