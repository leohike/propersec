use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::O_NOFOLLOW;
use properpin_core::{Budget, Error, MAX_FILE_BYTES, Settings, Store, kv};

use crate::system;

/// How long an attempt waits for another one to finish with the budget. The lock screen must never
/// hang on properpin, so after this the attempt gives up and the password is checked instead.
const LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// One user's properpin files, and the rules for trusting each of them:
///
/// ```text
/// <etc>/config               global settings, optional            owner-only writable
/// <etc>/users/<user>         the user's settings and hash         owner:<pinchecker group> 0640
/// <budget_dir>/              every user's budget, on disk         owner:<pinchecker group> 1770
/// <budget_dir>/<uid>.budget  a Budget                             <uid>:<pinchecker group> 0600
/// <budget_dir>/<uid>.lock    serialises concurrent attempts       <uid>:<pinchecker group> 0600
/// ```
///
/// The settings and the hash must belong to `etc_owner`, so nobody else can change them: root once
/// installed, the test's own uid in tests. The budgets live in one directory for all users, which
/// only the pinchecker's group can enter, so a user can neither read nor reset their counts. The
/// directory is sticky, and each user's budget and lock files must belong to that user, so one
/// user's run of the pinchecker can't read or replace another's. Both are created by root, at
/// `properpin set` ([`UserFiles::start_budget`]), and given to the user; the pinchecker only opens
/// them, so nobody's run ever creates a file there that another user's could find in their name.
/// Whoever writes the budget, the user or root, gives it to the user. [`UserFiles::new`] gives the
/// `etc` side, which `properpin set` and `remove` need; [`UserFiles::with_budget`] adds the
/// budget.
#[derive(Debug, Clone)]
pub struct UserFiles {
    etc: PathBuf,
    etc_owner: u32,
    budget: Option<SharedDir>,
    user: String,
    uid: u32,
}

/// A directory every user's files share: owned by `owner`, with the pinchecker's `group`.
#[derive(Debug, Clone)]
struct SharedDir {
    path: PathBuf,
    owner: u32,
    group: u32,
}

impl UserFiles {
    pub fn new(etc: impl Into<PathBuf>, etc_owner: u32, user: &str, uid: u32) -> Result<Self, Error> {
        if user.is_empty() || user.contains('/') || user == "." || user == ".." {
            return Err(Error::System(format!("{user:?} is not a usable user name")));
        }
        Ok(Self { etc: etc.into(), etc_owner, budget: None, user: user.into(), uid })
    }

    /// The same files, plus the budget in `dir`, which must belong to `owner` and `group`.
    pub fn with_budget(self, dir: impl Into<PathBuf>, owner: u32, group: u32) -> Self {
        Self { budget: Some(SharedDir { path: dir.into(), owner, group }), ..self }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn etc_owner(&self) -> u32 {
        self.etc_owner
    }

    pub fn config(&self) -> PathBuf {
        self.etc.join("config")
    }

    pub fn user_file(&self) -> PathBuf {
        self.etc.join("users").join(&self.user)
    }

    pub fn lock_file(&self) -> Option<PathBuf> {
        Some(self.budget.as_ref()?.path.join(format!("{}.lock", self.uid)))
    }

    pub fn budget_file(&self) -> Option<PathBuf> {
        Some(self.budget.as_ref()?.path.join(format!("{}.budget", self.uid)))
    }

    // --- the owner's side: settings and hash

    /// The settings in `path`, if the owner owns it and nobody else can change it (see [`read_trusted`]).
    fn read_pairs(&self, path: &Path, private: bool) -> Result<kv::Pairs, Error> {
        let text = read_trusted(path, &[self.etc_owner], private)?.unwrap_or_default();
        kv::parse(&text, &path.display().to_string())
    }

    /// Atomically write a new PIN's settings (its hash) into the user's file:
    /// owned by the owner, readable by `group` (the pinchecker's), mode 0640. The user's other settings
    /// in the file are kept as they are.
    pub fn save_pin(&self, new: &[(&str, &str)], group: u32) -> Result<(), Error> {
        let path = self.user_file();
        let pairs = new.iter().fold(self.read_pairs(&path, true)?, |pairs, (key, value)| kv::with(pairs, key, value));
        let dir = path.parent().expect("the user file is inside users/");
        fs::DirBuilder::new().recursive(true).mode(0o755).create(dir).map_err(|error| system(dir.display(), error))?;
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&format!(".{}.", self.user)).tempfile_in(dir)?;
            fchown(file.as_file(), Some(self.etc_owner), Some(group))?;
            file.as_file().set_permissions(Permissions::from_mode(0o640))?;
            file.write_all(kv::format(&pairs).as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(&path)?;
            Ok(())
        };
        write().map_err(|error| system(path.display(), error))
    }

    /// Delete the user's file, hash and settings both. `false` when there was none.
    pub fn remove_pin(&self) -> Result<bool, Error> {
        let path = self.user_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        }
    }

    /// Give a new PIN its budget and lock file, as root: `properpin set`. The lock is taken first,
    /// so an attempt still running finishes before the budget is replaced. A lock file that isn't
    /// the user's own goes, so does whatever stands in its place, and a new one is created for the
    /// user: root can delete anything here, so whatever got there, a fresh `set` repairs it.
    pub fn start_budget(&self, budget: &Budget) -> Result<(), Error> {
        let dir = self.trusted_budget_dir()?;
        let group = self.budget.as_ref().expect("checked by trusted_budget_dir").group;
        let path = dir.join(format!("{}.lock", self.uid));
        let file = match self.open_lock(&path) {
            Ok(file) => file,
            Err(_) => {
                let create = || -> std::io::Result<File> {
                    match fs::remove_file(&path) {
                        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
                        _ => {}
                    }
                    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(O_NOFOLLOW).open(&path)?;
                    fchown(&file, Some(self.uid), Some(group))?;
                    Ok(file)
                };
                create().map_err(|error| system(path.display(), error))?
            }
        };
        let _lock = flock(file, &path)?;
        self.save_budget(budget)
    }

    /// Delete the budget and the lock file: `remove`, which leaves none behind. Root can delete
    /// both whoever owns them.
    pub fn remove_budget(&self) -> Result<bool, Error> {
        let dir = self.trusted_budget_dir()?;
        let remove = |path: PathBuf| match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        };
        remove(dir.join(format!("{}.lock", self.uid)))?;
        remove(dir.join(format!("{}.budget", self.uid)))
    }

    // --- the pinchecker's side: the budget

    fn trusted_budget_dir(&self) -> Result<&Path, Error> {
        let budget = self.budget.as_ref().ok_or_else(|| Error::System("no budget directory given".into()))?;
        trusted_dir(budget, "budget directory")
    }

    /// The user's lock file at `path`, which must exist, be a regular file and be the user's own.
    fn open_lock(&self, path: &Path) -> Result<File, Error> {
        // Read and write: opening a FIFO planted in its place for reading alone would block.
        let file =
            OpenOptions::new().read(true).write(true).custom_flags(O_NOFOLLOW).open(path).map_err(|error| system(path.display(), error))?;
        let info = file.metadata().map_err(|error| system(path.display(), error))?;
        let refuse = |why: String| Err(Error::System(format!("{}: {why}; sudo properpin set makes a new one", path.display())));
        if !info.is_file() {
            return refuse("not a regular file".into());
        }
        if info.uid() != self.uid {
            return refuse(format!("owned by uid {}, not {}", info.uid(), self.uid));
        }
        Ok(file)
    }
}

/// Refuse a shared directory that isn't exactly as installed: a directory, not a symlink, owned by
/// the owner and the pinchecker's group, mode 1770. Without the group's write bit the pinchecker can't
/// keep its files; without the sticky bit one user's run could delete or replace another's files;
/// any bit for others would let users in.
fn trusted_dir<'a>(dir: &'a SharedDir, what: &str) -> Result<&'a Path, Error> {
    let info = fs::symlink_metadata(&dir.path).map_err(|error| system(dir.path.display(), error))?;
    let refuse = |why: String| Err(Error::System(format!("{what} {}: {why}", dir.path.display())));
    if !info.is_dir() {
        return refuse("not a directory".into());
    }
    if info.uid() != dir.owner {
        return refuse(format!("owned by uid {}, not {}", info.uid(), dir.owner));
    }
    if info.gid() != dir.group {
        return refuse(format!("group {}, not {}", info.gid(), dir.group));
    }
    if info.mode() & 0o7777 != 0o1770 {
        return refuse(format!("mode {:04o}, not 1770", info.mode() & 0o7777));
    }
    Ok(&dir.path)
}

impl Store for UserFiles {
    type Lock = Flock<File>;

    fn settings(&self) -> Result<Settings, Error> {
        let mut settings = Settings::default();
        let (config, user_file) = (self.config(), self.user_file());
        settings.apply(&self.read_pairs(&config, false)?, &config.display().to_string(), false)?;
        settings.apply(&self.read_pairs(&user_file, true)?, &user_file.display().to_string(), true)?;
        Ok(settings)
    }

    /// Every write of the budget happens under this lock. The lock file must exist, created by
    /// `properpin set`, and be the user's own: one that is missing or isn't refuses the PIN, and a
    /// fresh `set` repairs it. Opened without `O_CREAT`, which `fs.protected_regular` would refuse
    /// root in this sticky, group-writable directory, even for a file that exists.
    fn lock(&self) -> Result<Flock<File>, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.lock", self.uid));
        let file = self.open_lock(&path)?;
        flock(file, &path)
    }

    /// The budget must be the user's own and private; one that isn't is an error, never an empty
    /// budget.
    fn load_budget(&self) -> Result<Budget, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.budget", self.uid));
        let refuse = |why: &str| Err(Error::System(format!("{}: {why}; sudo properpin set starts it over", path.display())));
        let (info, text) = match read_regular_file(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return refuse("missing"),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        if info.uid() != self.uid {
            return refuse(&format!("owned by uid {}, not {}", info.uid(), self.uid));
        }
        if info.mode() & 0o077 != 0 {
            return refuse("open to its group or others");
        }
        Budget::parse(&text).map_or_else(|| refuse("not a valid budget"), Ok)
    }

    /// Written for the user and the pinchecker's group whoever writes it: the pinchecker, as the user, or
    /// `properpin enable`, as root. Synced, file and directory, since it must survive a power cut.
    fn save_budget(&self, budget: &Budget) -> Result<(), Error> {
        let dir = self.trusted_budget_dir()?;
        let group = self.budget.as_ref().expect("checked by trusted_budget_dir").group;
        let path = dir.join(format!("{}.budget", self.uid));
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&format!(".{}.", self.uid)).tempfile_in(dir)?;
            fchown(file.as_file(), Some(self.uid), Some(group))?;
            file.as_file().set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(budget.format().as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(&path)?;
            File::open(dir)?.sync_all()
        };
        write().map_err(|error| system(path.display(), error))
    }
}

/// An exclusive lock on `file`, waiting at most [`LOCK_TIMEOUT`] for whoever holds it.
fn flock(mut file: File, path: &Path) -> Result<Flock<File>, Error> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(lock),
            Err((_, errno)) if Instant::now() >= deadline => return Err(system(path.display(), errno)),
            Err((returned, _)) => file = returned,
        }
        sleep(Duration::from_millis(10));
    }
}

/// The global settings alone, from the config at `path`, for the PAM module: it runs as the user,
/// who can't read their own file. Trusted when owned by root, or by `uid`, the user the module
/// runs as: the one setting the module uses changes only how long that user's own correct PIN
/// waits, and the tests' sandboxes belong to the user running them. Defaults when there is no
/// config.
pub fn global_settings(path: &Path, uid: u32) -> Result<Settings, Error> {
    let text = read_trusted(path, &[0, uid], false)?.unwrap_or_default();
    let source = path.display().to_string();
    let mut settings = Settings::default();
    settings.apply(&kv::parse(&text, &source)?, &source, false)?;
    Ok(settings)
}

/// The text of `path`, provided it can be trusted: a regular file, not a symlink, owned by one of
/// `owners`, that nobody else can change. `private` also refuses a file others can read. `None`
/// when there is no such file.
fn read_trusted(path: &Path, owners: &[u32], private: bool) -> Result<Option<String>, Error> {
    let (info, text) = match read_regular_file(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        result => result.map_err(|error| system(path.display(), error))?,
    };
    let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
    if !owners.contains(&info.uid()) {
        let owners: Vec<String> = owners.iter().map(u32::to_string).collect();
        return refuse(format!("owned by uid {}, not {}", info.uid(), owners.join(" or ")));
    }
    if info.mode() & 0o022 != 0 {
        return refuse("writable by its group or by others".into());
    }
    if private && info.mode() & 0o004 != 0 {
        return refuse("readable by others".into());
    }
    Ok(Some(text))
}

/// The metadata and text of `path`, which must be a regular file and not a symlink. Both come from
/// one open file, so the file checked is the file read.
fn read_regular_file(path: &Path) -> std::io::Result<(Metadata, String)> {
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)?;
    let info = file.metadata()?;
    if !info.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    file.take(MAX_FILE_BYTES as u64 + 1).read_to_string(&mut text)?;
    if text.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!("longer than {MAX_FILE_BYTES} bytes")));
    }
    Ok((info, text))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::{current_egid, current_uid};

    /// A scratch `etc` and `var` owned by whoever runs the tests.
    struct Scratch {
        _dir: tempfile::TempDir,
        files: UserFiles,
    }

    fn scratch() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let uid = current_uid();
        fs::create_dir(dir.path().join("var")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(dir.path().join("var"), Permissions::from_mode(0o1770)).unwrap();
        let files =
            UserFiles::new(dir.path().join("etc"), uid, "tester", uid).unwrap().with_budget(dir.path().join("var"), uid, current_egid());
        Scratch { _dir: dir, files }
    }

    fn write(path: &Path, text: &str, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn settings_layer_config_then_user_file() {
        let Scratch { files, .. } = &scratch();
        write(&files.config(), "max_failures = 5\nhash_cost = 6\n", 0o644);
        write(&files.user_file(), "hash = $y$j9T$abc$def\nmax_failures = 2\n", 0o640);
        let settings = files.settings().unwrap();
        assert_eq!((settings.max_failures, settings.hash_cost, settings.pin_hash.as_str()), (2, 6, "$y$j9T$abc$def"));
    }

    #[test]
    fn the_pam_module_reads_the_global_config_alone() {
        let Scratch { files, .. } = &scratch();
        let uid = current_uid();
        assert_eq!(global_settings(&files.config(), uid).unwrap(), Settings::default(), "no config, the defaults");
        write(&files.config(), "min_milliseconds_before_pin_unlock = 300\nmax_failures = 5\n", 0o644);
        write(&files.user_file(), "max_failures = 2\n", 0o640);
        let settings = global_settings(&files.config(), uid).unwrap();
        assert_eq!((settings.min_milliseconds_before_pin_unlock, settings.max_failures), (300, 5));
        let error = global_settings(&files.config(), uid + 1).unwrap_err().to_string();
        assert!(error.contains(&format!("owned by uid {uid}, not 0 or {}", uid + 1)), "{error}");
        write(&files.config(), "min_milliseconds_before_pin_unlock = 300\n", 0o664);
        assert!(global_settings(&files.config(), uid).unwrap_err().to_string().contains("writable by its group"));
        write(&files.config(), "hash = $y$j9T$abc$def\n", 0o644);
        assert!(matches!(global_settings(&files.config(), uid), Err(Error::OutsideUserFile { .. })));
    }

    #[test]
    fn untrusted_files_are_refused() {
        let Scratch { files, .. } = &scratch();
        for (mode, why) in [(0o660, "writable by its group"), (0o644, "readable by others")] {
            write(&files.user_file(), "hash = $y$x\n", mode);
            let error = files.settings().unwrap_err().to_string();
            assert!(error.contains(why), "{error}");
        }
        let other_owner = UserFiles::new(files.etc.clone(), files.etc_owner + 1, "tester", files.uid).unwrap();
        write(&files.user_file(), "hash = $y$x\n", 0o640);
        assert!(other_owner.settings().unwrap_err().to_string().contains("owned by uid"));
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let Scratch { files, .. } = &scratch();
        let real = files.etc.join("elsewhere");
        write(&real, "max_failures = 10\n", 0o644);
        symlink(&real, files.config()).unwrap();
        assert!(files.settings().is_err());
    }

    #[test]
    fn saving_a_hash_keeps_other_settings_and_sets_the_mode() {
        let Scratch { files, .. } = &scratch();
        write(&files.user_file(), "hash = $y$old\nmax_failures = 2\n", 0o640);
        files.save_pin(&[("hash", "$y$new")], nix::unistd::getgid().as_raw()).unwrap();
        assert_eq!(fs::read_to_string(files.user_file()).unwrap(), "hash = $y$new\nmax_failures = 2\n");
        assert_eq!(fs::metadata(files.user_file()).unwrap().mode() & 0o777, 0o640);
        assert!(files.remove_pin().unwrap());
        assert!(!files.remove_pin().unwrap());
    }

    #[test]
    fn a_budget_dir_with_any_other_mode_is_refused() {
        let Scratch { files, .. } = &scratch();
        let dir = files.budget_file().unwrap().parent().unwrap().to_path_buf();
        for mode in [0o700, 0o770, 0o1777, 0o1775, 0o3770] {
            fs::set_permissions(&dir, Permissions::from_mode(mode)).unwrap();
            let error = files.lock().unwrap_err().to_string();
            assert!(error.contains(&format!("mode {mode:04o}, not 1770")), "{error}");
            assert!(files.save_budget(&Budget::default()).is_err());
        }
        fs::set_permissions(&dir, Permissions::from_mode(0o1770)).unwrap();
        files.start_budget(&Budget::default()).unwrap();
        assert!(files.lock().is_ok());
    }

    #[test]
    fn a_budget_dir_with_another_owner_or_group_is_refused() {
        let Scratch { files, .. } = &scratch();
        let budget = files.budget.clone().unwrap();
        let theirs = files.clone().with_budget(&budget.path, budget.owner + 1, budget.group);
        assert!(theirs.lock().unwrap_err().to_string().contains("owned by uid"));
        let theirs = files.clone().with_budget(&budget.path, budget.owner, budget.group + 1);
        assert!(theirs.lock().unwrap_err().to_string().contains(&format!("group {}, not {}", budget.group, budget.group + 1)));
    }

    #[test]
    fn a_symlinked_budget_dir_is_refused() {
        let Scratch { files, _dir } = &scratch();
        let budget = files.budget.clone().unwrap();
        let link = _dir.path().join("link");
        symlink(&budget.path, &link).unwrap();
        let linked = files.clone().with_budget(link, budget.owner, budget.group);
        assert!(linked.lock().unwrap_err().to_string().contains("not a directory"));
    }

    /// The pinchecker never creates the lock file, so a missing one is refused. A test can't make
    /// files owned by someone else, so it plays the other side: the files are built for another
    /// uid, and the file the test creates stands in for a planted one.
    #[test]
    fn a_missing_or_planted_lock_file_is_refused() {
        let Scratch { files, .. } = &scratch();
        let budget = files.budget.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_budget(
            &budget.path,
            budget.owner,
            budget.group,
        );
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains("No such file"), "{error}");
        assert!(!victim.lock_file().unwrap().exists(), "and nothing was created");
        write(&victim.lock_file().unwrap(), "", 0o600);
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains(&format!("owned by uid {}, not {}", files.uid, files.uid + 1)), "{error}");
        assert!(error.contains("sudo properpin set makes a new one"), "{error}");
    }

    /// Whatever stands where the lock file should be, set replaces it with a lock file of the user's.
    #[test]
    fn set_replaces_anything_in_place_of_the_lock_file() {
        let Scratch { files, _dir } = &scratch();
        let lock = files.lock_file().unwrap();
        symlink(_dir.path().join("elsewhere"), &lock).unwrap();
        assert!(files.lock().is_err());
        files.start_budget(&Budget::default()).unwrap();
        assert!(fs::symlink_metadata(&lock).unwrap().is_file());
        assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o7777, 0o600);
        assert!(files.lock().is_ok());
    }

    #[test]
    fn without_a_budget_dir_there_is_no_lock_and_no_budget() {
        let Scratch { files, .. } = &scratch();
        let etc_only = UserFiles::new(files.etc.clone(), files.etc_owner, "tester", files.uid).unwrap();
        assert!(etc_only.lock().is_err());
        assert!(etc_only.load_budget().is_err());
    }

    #[test]
    fn the_budget_starts_at_set_and_round_trips() {
        let Scratch { files, .. } = &scratch();
        assert!(files.load_budget().unwrap_err().to_string().contains("missing; sudo properpin set starts it over"));
        files.start_budget(&Budget::default()).unwrap();
        assert_eq!(files.load_budget().unwrap(), Budget::default());
        let budget = Budget { consecutive: 2, pending: vec![1], concerning: vec![2], total: 3, disabled: None };
        files.save_budget(&budget).unwrap();
        assert_eq!(files.load_budget().unwrap(), budget);
        assert_eq!(fs::metadata(files.budget_file().unwrap()).unwrap().mode() & 0o7777, 0o600);
        let lock = files.lock().unwrap();
        assert!(files.remove_budget().unwrap());
        assert!(!files.lock_file().unwrap().exists(), "the lock file goes with the budget");
        drop(lock);
        assert!(!files.remove_budget().unwrap());
        assert!(files.load_budget().is_err());
    }

    #[test]
    fn a_budget_that_cannot_be_trusted_is_an_error_not_an_empty_budget() {
        let Scratch { files, .. } = &scratch();
        let path = files.budget_file().unwrap();
        write(&path, "garbage\n", 0o600);
        assert!(files.load_budget().unwrap_err().to_string().contains("sudo properpin set starts it over"));
        write(&path, &Budget::default().format(), 0o640);
        assert!(files.load_budget().unwrap_err().to_string().contains("open to its group or others"));
        // Planted in another user's name: the test's own file stands in for the planted one.
        write(&path, &Budget::default().format(), 0o600);
        let budget = files.budget.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_budget(
            &budget.path,
            budget.owner,
            budget.group,
        );
        fs::rename(&path, victim.budget_file().unwrap()).unwrap();
        assert!(victim.load_budget().unwrap_err().to_string().contains(&format!("owned by uid {}, not {}", files.uid, files.uid + 1)));
    }

    #[test]
    fn a_budget_past_the_size_limit_is_an_error_not_a_shorter_budget() {
        let Scratch { files, .. } = &scratch();
        let path = files.budget_file().unwrap();
        let budget = Budget::default().format();
        // Padded with a comment to exactly MAX_FILE_BYTES it is read; one byte more, and it is refused.
        let padded = |length: usize| format!("{budget}#{}\n", "x".repeat(length - budget.len() - 2));
        write(&path, &padded(MAX_FILE_BYTES), 0o600);
        assert_eq!(files.load_budget().unwrap(), Budget::default());
        write(&path, &padded(MAX_FILE_BYTES + 1), 0o600);
        assert!(files.load_budget().unwrap_err().to_string().contains(&format!("longer than {MAX_FILE_BYTES} bytes")));
    }

    #[test]
    fn every_use_of_the_budget_directory_checks_it() {
        let Scratch { files, .. } = &scratch();
        let dir = files.budget.clone().unwrap().path;
        fs::set_permissions(&dir, Permissions::from_mode(0o777)).unwrap();
        assert!(files.load_budget().unwrap_err().to_string().contains("budget directory"));
        assert!(files.save_budget(&Budget::default()).is_err());
        assert!(files.remove_budget().is_err());
    }

    #[test]
    fn a_held_lock_times_out_instead_of_hanging() {
        let Scratch { files, .. } = &scratch();
        files.start_budget(&Budget::default()).unwrap();
        let _held = files.lock().unwrap();
        let started = Instant::now();
        assert!(files.lock().is_err());
        assert!(started.elapsed() < LOCK_TIMEOUT * 2);
        assert!(files.start_budget(&Budget::default()).is_err(), "set waits for an attempt still running, too");
    }
}
