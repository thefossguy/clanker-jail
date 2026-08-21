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

use std::error::Error;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn populate_clanker_agent_env_in_jail(
    jailed_clanker_command: &mut Command,
    env_var_name: &str,
    env_var_default_value: &str,
) {
    let env_var_final_value =
        std::env::var(env_var_name).unwrap_or_else(|_| env_var_default_value.to_string());
    jailed_clanker_command.env(env_var_name, env_var_final_value);
}

pub fn exec(clanker_jail_config: &ClankerJailConfig) -> Result<(), Box<dyn Error>> {
    let mut jailed_clanker_command = Command::new(&clanker_jail_config.clanker);
    jailed_clanker_command
        .args(&clanker_jail_config.clanker_operands)
        .env("IN_CLANKER_JAIL", "1");

    // Hardening by default, but not overriding
    populate_clanker_agent_env_in_jail(&mut jailed_clanker_command, "PI_OFFLINE", "1");
    populate_clanker_agent_env_in_jail(&mut jailed_clanker_command, "PI_SKIP_VERSION_CHECK", "1");
    populate_clanker_agent_env_in_jail(&mut jailed_clanker_command, "PI_TELEMETRY", "0");

    Err(Box::new(jailed_clanker_command.exec()))
}
