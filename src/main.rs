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

mod config;
mod exec;
mod landlock_wrapper;

use std::error::Error;

fn check_landlock_abi_compatibility() -> Result<(), Box<dyn Error>> {
    use landlock::{AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};
    match Ruleset::default().set_compatibility(CompatLevel::HardRequirement).handle_access(AccessFs::Truncate).is_ok() {
        true => Ok(()),
        false => Err("Landlock LSM's 'truncate' permission from landlock ABI v3 cannot be enforced for this kernel. Please look at <https://docs.kernel.org/userspace-api/landlock.html> for further documentation.".into()),
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn Error>> {
    check_landlock_abi_compatibility()?;
    let clanker_jail_config = config::configure_clanker_jail()?;
    landlock_wrapper::jail_the_clanker(&clanker_jail_config)?;
    exec::exec(&clanker_jail_config)
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn Error>> {
    Err("Linux or bust".into())
}
