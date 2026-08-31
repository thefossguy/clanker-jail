// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Pratham Patel <prathampatel@thefossguy.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; only as version 2
// of the License, NOT as a later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.

use crate::config::ClankerJailConfig;

use std::collections::{HashMap, hash_map};
use std::error::Error;
use std::fmt;

use landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetError, RulesetStatus, make_bitflags, path_beneath_rules,
};

pub type ClankerPermissions = BitFlags<AccessFs>;
pub const CLANKER_PERMISSIONS_RO: ClankerPermissions =
    make_bitflags!(AccessFs::{ ReadDir | ReadFile });
pub const CLANKER_PERMISSIONS_ROX: ClankerPermissions =
    make_bitflags!(AccessFs::{ ReadDir | ReadFile | Execute});
pub const CLANKER_PERMISSIONS_RW: ClankerPermissions = make_bitflags!(AccessFs::{ ReadDir | ReadFile | MakeDir | MakeReg | MakeSym | Refer | Truncate | WriteFile });
pub const CLANKER_PERMISSIONS_RWX: ClankerPermissions = make_bitflags!(AccessFs::{ ReadDir | ReadFile | MakeDir | MakeReg | MakeSym | Refer | Truncate | WriteFile | Execute});
pub const CLANKER_PERMISSIONS_RW_RM: ClankerPermissions = make_bitflags!(AccessFs::{ ReadDir | ReadFile | MakeDir | MakeReg | MakeSym | Refer | Truncate | WriteFile | RemoveDir | RemoveFile });
pub const CLANKER_PERMISSIONS_RWX_RM: ClankerPermissions = make_bitflags!(AccessFs::{ ReadDir | ReadFile | MakeDir | MakeReg | MakeSym | Refer | Truncate | WriteFile | RemoveDir | RemoveFile | Execute});

type AccessiblePathsInner = HashMap<String, ClankerPermissions>;
pub struct AccessiblePaths(AccessiblePathsInner);
impl AccessiblePaths {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn iter(&self) -> hash_map::Iter<'_, String, ClankerPermissions> {
        self.0.iter()
    }

    pub fn insert(&mut self, allowed_path_to_insert: (String, ClankerPermissions)) {
        self.0
            .insert(allowed_path_to_insert.0, allowed_path_to_insert.1);
    }

    pub fn insert_lossy(&mut self, allowed_path_to_insert: (&str, ClankerPermissions)) {
        if let Ok(allowed_path) = std::path::absolute(allowed_path_to_insert.0)
            && allowed_path.exists()
        {
            self.0
                .insert(allowed_path.display().to_string(), allowed_path_to_insert.1);
        }
    }

    pub fn extend_lossy(
        &mut self,
        sandbox_permission: ClankerPermissions,
        paths_to_sandbox: &[&str],
    ) {
        for path_to_sandbox in paths_to_sandbox {
            self.insert_lossy((path_to_sandbox, sandbox_permission));
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&ClankerPermissions> {
        self.0.get(key)
    }
}
impl IntoIterator for AccessiblePaths {
    type Item = (String, ClankerPermissions);
    type IntoIter = hash_map::IntoIter<String, ClankerPermissions>;
    fn into_iter(self) -> hash_map::IntoIter<String, ClankerPermissions> {
        self.0.into_iter()
    }
}
impl fmt::Debug for AccessiblePaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut allowed_paths = self.iter().collect::<Vec<_>>();
        allowed_paths.sort_by_key(|(key, _)| *key);
        f.debug_map().entries(allowed_paths).finish()
    }
}

pub fn jail_the_clanker(clanker_jail_config: &ClankerJailConfig) -> Result<(), Box<dyn Error>> {
    let mut self_ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V3))?
        .create()?;

    for (path_to_allow, path_permissions) in clanker_jail_config.accessible_paths.iter() {
        let rules: Vec<Result<PathBeneath<PathFd>, RulesetError>> =
            path_beneath_rules(&[path_to_allow], *path_permissions).collect();
        if rules.is_empty() {
            return Err(format!("Landlock did not jail the path '{path_to_allow}'").into());
        }
        self_ruleset = self_ruleset.add_rules(rules)?;
    }

    let status = self_ruleset.restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => Err("The clanker is only partially jailed".into()),
        RulesetStatus::NotEnforced => Err("The clanker is not at all jailed".into()),
    }
}
