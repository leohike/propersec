use nix::unistd::{Group, Uid, User, getegid, geteuid, getgid, getuid};
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

pub fn current_gid() -> u32 {
    getgid().as_raw()
}

pub fn current_egid() -> u32 {
    getegid().as_raw()
}

/// The gid of the group named `name`, or of `name` itself when it is a number.
pub fn group_by_name(name: &str) -> Result<u32, Error> {
    if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
        return name.parse().map_err(|error| system(format!("group {name:?}"), error));
    }
    let group = Group::from_name(name).map_err(|error| system(format!("group {name:?}"), error))?;
    group.map(|group| group.gid.as_raw()).ok_or_else(|| Error::System(format!("no group named {name:?}")))
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
    fn finds_groups_by_name_or_number() {
        assert_eq!(group_by_name("root").unwrap(), 0);
        assert_eq!(group_by_name("4242").unwrap(), 4242);
        assert!(group_by_name("no-such-group-properpin").is_err());
    }
}
