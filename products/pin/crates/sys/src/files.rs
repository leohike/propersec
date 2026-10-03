use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use nix::fcntl::{Flock, FlockArg};
use nix::libc::O_NOFOLLOW;
use nix::sys::statfs::{TMPFS_MAGIC, statfs};
use properpin_core::{Budget, Error, MAX_FILE_BYTES, PinState, Settings, Store, kv};
use zeroize::Zeroizing;

use crate::system;

/// How long an attempt waits for another one to finish with the state. The lock screen must never
/// hang on properpin, so after this the attempt gives up and the password is checked instead.
const LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// One user's properpin files, and the rules for trusting each of them:
///
/// ```text
/// <etc>/config               global settings, optional            owner-only writable
/// <etc>/users/<user>         the user's settings, hash and        owner:<helper group> 0640
///                            encrypted pepper
/// <run_dir>/                 every user's state                   owner:<helper group> 1770
/// <run_dir>/<uid>.state      a PinState, with the clear pepper    <uid>:<helper group> 0600
/// <run_dir>/<uid>.lock       serialises concurrent attempts       <uid>:<helper group> 0600
/// <budget_dir>/              every user's budget, on disk         owner:<helper group> 1770
/// <budget_dir>/<uid>.budget  a Budget                             <uid>:<helper group> 0600
/// ```
///
/// The settings and the hash must belong to `etc_owner`, so nobody else can change them: root once
/// installed, the test's own uid in tests. The state lives in one directory for all users, which
/// only the helper's group can enter, so a user can neither read nor reset their counts. The
/// directory is sticky, and each user's state and lock files must belong to that user, so one
/// user's run of the helper can't read, replace or plant another's. The budget follows the same
/// rules in a directory on disk, so it survives a reboot; the run directory's lock covers it.
/// `properpin enable` needs the `etc` side and the budget; [`UserFiles::with_runtime`] adds the
/// state, which the helper keeps, `properpin set` arms, and `properpin remove` deletes. Whoever
/// writes the state or creates the lock file, the user or root, gives it to the user.
#[derive(Debug, Clone)]
pub struct UserFiles {
    etc: PathBuf,
    etc_owner: u32,
    runtime: Option<SharedDir>,
    budget: Option<SharedDir>,
    user: String,
    uid: u32,
}

/// A directory every user's files share: owned by `owner`, with the helper's `group`.
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
        Ok(Self { etc: etc.into(), etc_owner, runtime: None, budget: None, user: user.into(), uid })
    }

    /// The same files, plus the per-boot state in `dir`, which must belong to `owner` and `group`.
    pub fn with_runtime(self, dir: impl Into<PathBuf>, owner: u32, group: u32) -> Self {
        Self { runtime: Some(SharedDir { path: dir.into(), owner, group }), ..self }
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

    pub fn state_file(&self) -> Option<PathBuf> {
        Some(self.runtime.as_ref()?.path.join(format!("{}.state", self.uid)))
    }

    pub fn lock_file(&self) -> Option<PathBuf> {
        Some(self.runtime.as_ref()?.path.join(format!("{}.lock", self.uid)))
    }

    pub fn budget_file(&self) -> Option<PathBuf> {
        Some(self.budget.as_ref()?.path.join(format!("{}.budget", self.uid)))
    }

    // --- the owner's side: settings and hash

    /// The text of `path`, provided it can be trusted: a regular file, not a symlink, owned by the
    /// owner, that nobody else can change. `private` also refuses a file others can read.
    /// `None` when there is no such file.
    fn read_trusted(&self, path: &Path, private: bool) -> Result<Option<String>, Error> {
        let (info, text) = match read_regular_file(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        let refuse = |why: String| Err(Error::System(format!("{}: {why}", path.display())));
        if info.uid() != self.etc_owner {
            return refuse(format!("owned by uid {}, not {}", info.uid(), self.etc_owner));
        }
        if info.mode() & 0o022 != 0 {
            return refuse("writable by its group or by others".into());
        }
        if private && info.mode() & 0o004 != 0 {
            return refuse("readable by others".into());
        }
        Ok(Some(text))
    }

    fn read_pairs(&self, path: &Path, private: bool) -> Result<kv::Pairs, Error> {
        let text = self.read_trusted(path, private)?.unwrap_or_default();
        kv::parse(&text, &path.display().to_string())
    }

    /// Atomically write a new PIN's settings (its hash and encrypted pepper) into the user's file:
    /// owned by the owner, readable by `group` (the helper's), mode 0640. The user's other settings
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

    /// Start the budget over: `set` gives a new PIN a fresh one, and `remove` leaves none behind.
    /// Root can delete it whoever owns it, which also clears a budget planted in the user's name.
    pub fn remove_budget(&self) -> Result<bool, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.budget", self.uid));
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        }
    }

    /// Delete the state, and the pepper in it: `remove` leaves nothing armed behind.
    pub fn remove_state(&self) -> Result<bool, Error> {
        let path = self.trusted_run_dir()?.join(format!("{}.state", self.uid));
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(system(path.display(), error)),
        }
    }

    /// Whether the run directory is on tmpfs, so the pepper in the state stays in memory, unless
    /// swapped out. `None` when it can't be told.
    pub fn runtime_on_tmpfs(&self) -> Option<bool> {
        statfs(&self.runtime.as_ref()?.path).ok().map(|info| info.filesystem_type() == TMPFS_MAGIC)
    }

    // --- the helper's side: per-boot state, and the budget

    fn trusted_run_dir(&self) -> Result<&Path, Error> {
        let runtime = self.runtime.as_ref().ok_or_else(|| Error::System("no runtime directory: only the helper keeps state".into()))?;
        trusted_dir(runtime, "run directory")
    }

    fn trusted_budget_dir(&self) -> Result<&Path, Error> {
        let budget = self.budget.as_ref().ok_or_else(|| Error::System("no budget directory given".into()))?;
        trusted_dir(budget, "budget directory")
    }
}

/// Refuse a shared directory that isn't exactly as installed: a directory, not a symlink, owned by
/// the owner and the helper's group, mode 1770. Without the group's write bit the helper can't
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

    /// Every write of the state happens under this lock, so checking here that the lock file is the
    /// user's own refuses a lock or state file planted in their name by someone else's run.
    ///
    /// An existing file is opened without `O_CREAT`: with `fs.protected_regular` set, root may not
    /// `O_CREAT`-open a file of the user's in this sticky, group-writable directory, even one that
    /// exists. A new one is created exclusively and given to the user, so root creating it (in
    /// `properpin set`) doesn't leave a lock file the user's runs refuse.
    fn lock(&self) -> Result<Flock<File>, Error> {
        let dir = self.trusted_run_dir()?;
        let group = self.runtime.as_ref().expect("checked by trusted_run_dir").group;
        let path = dir.join(format!("{}.lock", self.uid));
        let options = |create: bool| {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(create).mode(0o600).custom_flags(O_NOFOLLOW);
            options
        };
        let open = match options(false).open(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                options(true).open(&path).and_then(|file| match fchown(&file, Some(self.uid), Some(group)) {
                    Ok(()) => Ok(file),
                    Err(error) => {
                        let _ = fs::remove_file(&path); // a lock file of the wrong owner would refuse every run
                        Err(error)
                    }
                })
            }
            result => result,
        };
        let mut file = open.map_err(|error| system(path.display(), error))?;
        let info = file.metadata().map_err(|error| system(path.display(), error))?;
        if !info.is_file() {
            return Err(Error::System(format!("{}: not a regular file", path.display())));
        }
        if info.uid() != self.uid {
            return Err(Error::System(format!("{}: owned by uid {}, not {}", path.display(), info.uid(), self.uid)));
        }
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

    /// A state file that isn't the user's own reads as no state, which requires the password.
    fn load_state(&self) -> Option<PinState> {
        let (info, text) = read_regular_file(&self.state_file()?).ok()?;
        let text = Zeroizing::new(text); // it may hold the pepper
        if info.uid() != self.uid || info.mode() & 0o077 != 0 {
            return None;
        }
        PinState::parse(&text)
    }

    /// Written for the user and the helper's group whoever writes it: the helper, as the user, or
    /// `properpin set`, as root. Owner-only, since it may hold the pepper.
    fn save_state(&self, state: &PinState) -> Result<(), Error> {
        let dir = self.trusted_run_dir()?;
        let group = self.runtime.as_ref().expect("checked by trusted_run_dir").group;
        let path = dir.join(format!("{}.state", self.uid));
        let write = || -> std::io::Result<()> {
            let mut file = tempfile::Builder::new().prefix(&format!(".{}.", self.uid)).tempfile_in(dir)?;
            fchown(file.as_file(), Some(self.uid), Some(group))?;
            file.as_file().set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(state.format().as_bytes())?;
            file.persist(&path)?;
            Ok(())
        };
        write().map_err(|error| system(path.display(), error))
    }

    /// The budget must be the user's own and private, like the state; unlike the state, a budget
    /// that isn't is an error, never an empty budget.
    fn load_budget(&self) -> Result<Budget, Error> {
        let path = self.trusted_budget_dir()?.join(format!("{}.budget", self.uid));
        let (info, text) = match read_regular_file(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Budget::default()),
            result => result.map_err(|error| system(path.display(), error))?,
        };
        let refuse = |why: &str| Err(Error::System(format!("{}: {why}; sudo properpin set starts it over", path.display())));
        if info.uid() != self.uid {
            return refuse(&format!("owned by uid {}, not {}", info.uid(), self.uid));
        }
        if info.mode() & 0o077 != 0 {
            return refuse("open to its group or others");
        }
        Budget::parse(&text).map_or_else(|| refuse("not a valid budget"), Ok)
    }

    /// Written for the user and the helper's group whoever writes it: the helper, as the user, or
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

    /// A scratch `etc`, `run` and `var` owned by whoever runs the tests.
    struct Scratch {
        _dir: tempfile::TempDir,
        files: UserFiles,
    }

    fn scratch() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        let uid = current_uid();
        for shared in ["run", "var"] {
            fs::create_dir(dir.path().join(shared)).unwrap();
            // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
            fs::set_permissions(dir.path().join(shared), Permissions::from_mode(0o1770)).unwrap();
        }
        let files = UserFiles::new(dir.path().join("etc"), uid, "tester", uid)
            .unwrap()
            .with_runtime(dir.path().join("run"), uid, current_egid())
            .with_budget(dir.path().join("var"), uid, current_egid());
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
        write(&files.config(), "max_failures = 5\nexpiry_hours = 2\n", 0o644);
        write(&files.user_file(), "hash = $y$j9T$abc$def\nmax_failures = 2\n", 0o640);
        let settings = files.settings().unwrap();
        assert_eq!((settings.max_failures, settings.expiry_hours, settings.pin_hash.as_str()), (2, 2.0, "$y$j9T$abc$def"));
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
        files
            .save_pin(
                &[("hash", "$y$new"), ("cleartext_salt_for_deriving_pepper_decryption_key", "$y$salt")],
                nix::unistd::getgid().as_raw(),
            )
            .unwrap();
        assert_eq!(
            fs::read_to_string(files.user_file()).unwrap(),
            "hash = $y$new\nmax_failures = 2\ncleartext_salt_for_deriving_pepper_decryption_key = $y$salt\n"
        );
        assert_eq!(fs::metadata(files.user_file()).unwrap().mode() & 0o777, 0o640);
        assert!(files.remove_pin().unwrap());
        assert!(!files.remove_pin().unwrap());
    }

    #[test]
    fn state_round_trips_under_the_lock() {
        let Scratch { files, .. } = &scratch();
        assert_eq!(files.load_state(), None);
        let pepper = properpin_core::Pepper::new(Zeroizing::new([9; properpin_core::PEPPER_BYTES]));
        let state = PinState::armed("b", 7, pepper);
        let _lock = files.lock().unwrap();
        files.save_state(&state).unwrap();
        assert_eq!(files.load_state(), Some(state));
        assert_eq!(fs::metadata(files.state_file().unwrap()).unwrap().mode() & 0o7777, 0o600);
        assert!(files.remove_state().unwrap());
        assert!(!files.remove_state().unwrap());
        assert_eq!(files.load_state(), None);
    }

    #[test]
    fn a_state_others_could_read_reads_as_none() {
        let Scratch { files, .. } = &scratch();
        files.save_state(&PinState { boot_id: "b".into(), armed_at: 7, failures: 0, pepper: None }).unwrap();
        fs::set_permissions(files.state_file().unwrap(), Permissions::from_mode(0o640)).unwrap();
        assert_eq!(files.load_state(), None);
    }

    #[test]
    fn tells_whether_the_run_directory_is_tmpfs() {
        let Scratch { files, .. } = &scratch();
        let on_tmpfs = files.runtime_on_tmpfs();
        assert!(on_tmpfs.is_some());
        let etc_only = UserFiles::new(files.etc.clone(), files.etc_owner, "tester", files.uid).unwrap();
        assert_eq!(etc_only.runtime_on_tmpfs(), None);
    }

    #[test]
    fn a_run_dir_with_any_other_mode_is_refused() {
        let Scratch { files, .. } = &scratch();
        let dir = files.state_file().unwrap().parent().unwrap().to_path_buf();
        for mode in [0o700, 0o770, 0o1777, 0o1775, 0o3770] {
            fs::set_permissions(&dir, Permissions::from_mode(mode)).unwrap();
            let error = files.lock().unwrap_err().to_string();
            assert!(error.contains(&format!("mode {mode:04o}, not 1770")), "{error}");
            assert!(files.save_state(&PinState { boot_id: "b".into(), armed_at: 7, failures: 0, pepper: None }).is_err());
        }
        fs::set_permissions(&dir, Permissions::from_mode(0o1770)).unwrap();
        assert!(files.lock().is_ok());
    }

    #[test]
    fn a_run_dir_with_another_owner_or_group_is_refused() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let theirs = files.clone().with_runtime(&runtime.path, runtime.owner + 1, runtime.group);
        assert!(theirs.lock().unwrap_err().to_string().contains("owned by uid"));
        let theirs = files.clone().with_runtime(&runtime.path, runtime.owner, runtime.group + 1);
        assert!(theirs.lock().unwrap_err().to_string().contains(&format!("group {}, not {}", runtime.group, runtime.group + 1)));
    }

    #[test]
    fn a_symlinked_run_dir_is_refused() {
        let Scratch { files, _dir } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let link = _dir.path().join("link");
        symlink(&runtime.path, &link).unwrap();
        let linked = files.clone().with_runtime(link, runtime.owner, runtime.group);
        assert!(linked.lock().unwrap_err().to_string().contains("not a directory"));
    }

    /// A test can't make files owned by someone else, so it plays the other side: the files are
    /// built for another uid, and the files the test creates stand in for planted ones.
    #[test]
    fn a_lock_file_planted_by_someone_else_is_refused() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_runtime(
            &runtime.path,
            runtime.owner,
            runtime.group,
        );
        // Creating it for the victim takes root, so a test's attempt fails and leaves nothing.
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains("Operation not permitted"), "{error}");
        assert!(!victim.lock_file().unwrap().exists());
        write(&victim.lock_file().unwrap(), "", 0o600);
        let error = victim.lock().unwrap_err().to_string();
        assert!(error.contains(&format!("owned by uid {}, not {}", files.uid, files.uid + 1)), "{error}");
    }

    #[test]
    fn a_state_file_planted_by_someone_else_reads_as_none() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let victim = UserFiles::new(files.etc.clone(), files.etc_owner, "victim", files.uid + 1).unwrap().with_runtime(
            &runtime.path,
            runtime.owner,
            runtime.group,
        );
        write(&victim.state_file().unwrap(), &PinState { boot_id: "b".into(), armed_at: 7, failures: 0, pepper: None }.format(), 0o600);
        assert_eq!(victim.load_state(), None);
    }

    #[test]
    fn without_a_runtime_there_is_no_state() {
        let Scratch { files, .. } = &scratch();
        let etc_only = UserFiles::new(files.etc.clone(), files.etc_owner, "tester", files.uid).unwrap();
        assert!(etc_only.lock().is_err());
        assert_eq!(etc_only.load_state(), None);
    }

    #[test]
    fn each_user_has_their_own_state() {
        let Scratch { files, .. } = &scratch();
        let runtime = files.runtime.clone().unwrap();
        let other = UserFiles::new(files.etc.clone(), files.etc_owner, "other", files.uid + 1).unwrap().with_runtime(
            runtime.path,
            runtime.owner,
            runtime.group,
        );
        let state = PinState { boot_id: "b".into(), armed_at: 7, failures: 1, pepper: None };
        files.save_state(&state).unwrap();
        assert_eq!(other.load_state(), None);
        assert_ne!(files.state_file(), other.state_file());
    }

    #[test]
    fn the_budget_round_trips_and_starts_empty() {
        let Scratch { files, .. } = &scratch();
        assert_eq!(files.load_budget().unwrap(), Budget::default());
        let budget = Budget { pending: vec![1], concerning: vec![2], total: 3, disabled: None };
        files.save_budget(&budget).unwrap();
        assert_eq!(files.load_budget().unwrap(), budget);
        assert_eq!(fs::metadata(files.budget_file().unwrap()).unwrap().mode() & 0o7777, 0o600);
        assert!(files.remove_budget().unwrap());
        assert!(!files.remove_budget().unwrap());
        assert_eq!(files.load_budget().unwrap(), Budget::default());
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
    fn the_budget_directory_is_checked_like_the_run_directory() {
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
        let _held = files.lock().unwrap();
        let started = Instant::now();
        assert!(files.lock().is_err());
        assert!(started.elapsed() < LOCK_TIMEOUT * 2);
    }
}
