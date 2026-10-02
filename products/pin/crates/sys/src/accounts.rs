use nix::unistd::{Gid, Group, Uid, User, geteuid, getuid};
use properpin_core::Error;

use crate::system;

/// A user account from the passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

impl Account {
    pub fn by_uid(uid: u32) -> Result<Self, Error> {
        let user = User::from_uid(Uid::from_raw(uid)).map_err(|error| system(format!("uid {uid}"), error))?;
        user.map(Self::from).ok_or_else(|| Error::System(format!("no user with uid {uid}")))
    }

    pub fn by_name(name: &str) -> Result<Self, Error> {
        let user = User::from_name(name).map_err(|error| system(format!("user {name:?}"), error))?;
        user.map(Self::from).ok_or_else(|| Error::System(format!("no user named {name:?}")))
    }
}

impl From<User> for Account {
    fn from(user: User) -> Self {
        Self { name: user.name, uid: user.uid.as_raw(), gid: user.gid.as_raw() }
    }
}

pub fn current_uid() -> u32 {
    getuid().as_raw()
}

pub fn current_euid() -> u32 {
    geteuid().as_raw()
}

/// The account's own group, which may read its hash file. A group anyone else belongs to is refused:
/// its members could read the hash and crack the PIN offline.
pub fn private_group(account: &Account) -> Result<u32, Error> {
    let gid = account.gid;
    let group = Group::from_gid(Gid::from_raw(gid)).map_err(|error| system(format!("gid {gid}"), error))?;
    let group = group.ok_or_else(|| Error::System(format!("no group with gid {gid}")))?;
    let others = other_users_with_primary_group(gid, &account.name);
    if group.name != account.name || !group.mem.is_empty() || !others.is_empty() {
        return Err(Error::System(format!(
            "{}'s primary group {:?} is not private to them, so it can't guard the hash",
            account.name, group.name
        )));
    }
    Ok(gid)
}

/// Every account except `except` whose primary group is `gid`. Walks the passwd database, which
/// nix has no safe wrapper for. Not thread-safe; only the CLI calls it.
#[allow(unsafe_code)]
fn other_users_with_primary_group(gid: u32, except: &str) -> Vec<String> {
    let mut names = Vec::new();
    // SAFETY: setpwent/getpwent/endpwent walk the passwd database. Each entry is read before the
    // next call, and its name is copied out. Nothing else in this process walks it concurrently.
    unsafe {
        nix::libc::setpwent();
        loop {
            let entry = nix::libc::getpwent();
            if entry.is_null() {
                break;
            }
            if (*entry).pw_gid == gid {
                let name = std::ffi::CStr::from_ptr((*entry).pw_name).to_string_lossy().into_owned();
                if name != except {
                    names.push(name);
                }
            }
        }
        nix::libc::endpwent();
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_current_user_both_ways() {
        let me = Account::by_uid(current_uid()).unwrap();
        assert_eq!(Account::by_name(&me.name).unwrap(), me);
        assert!(Account::by_name("no-such-user-properpin").is_err());
    }

    #[test]
    fn root_group_is_not_private_to_a_user() {
        let fake = Account { name: "someone".into(), uid: 4242, gid: 0 };
        assert!(private_group(&fake).is_err());
    }
}
