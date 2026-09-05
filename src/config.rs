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

use crate::landlock_wrapper::{
    AccessiblePaths, CLANKER_PERMISSIONS_RO, CLANKER_PERMISSIONS_ROX, CLANKER_PERMISSIONS_RW,
    CLANKER_PERMISSIONS_RW_RM, CLANKER_PERMISSIONS_RWX, CLANKER_PERMISSIONS_RWX_RM,
    ClankerPermissions,
};

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi;
use std::fmt;
use std::path;

struct DefaultAccessiblePathsConfig {
    cargo_home: String,
    clanker: String,
    current_working_directory: String,
    rustup_home: String,
    tmpdir: String,
    user_home_dir: String,
    xdg_config_home: String,
    xdg_data_home: String,
    xdg_cache_home: String,
}

#[derive(PartialEq, PartialOrd)]
enum ClankerPermissionsLevel {
    NoPermissions,
    Read,
    Write,
    Remove,
}
impl ClankerPermissionsLevel {
    fn from_str(level: &str) -> Option<Self> {
        match level {
            "deny-all" => Some(Self::NoPermissions),
            "read" => Some(Self::Read),
            "write" | "read,write" | "read+write" => Some(Self::Write),
            "remove" | "read,write,remove" | "read+write+remove" => Some(Self::Remove),
            _ => None,
        }
    }
}
impl fmt::Debug for ClankerPermissionsLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let clanker_permissions_level_as_str = match self {
            Self::NoPermissions => "deny-all",
            Self::Read => "read",
            Self::Write => "read+write",
            Self::Remove => "read+write+remove",
        };
        write!(f, "{clanker_permissions_level_as_str}")
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClankerJailConfig {
    pub clanker: String,
    pub clanker_operands: Vec<std::ffi::OsString>,
    pub accessible_paths: AccessiblePaths,
    sensitive_path_configs: HashMap<String, ClankerPermissionsLevel>,
}

fn print_help() {
    let help_message = "
        Usage: clanker-jail [OPTION...] [--] [OPERAND...]

        Run the CLANKER binary inside a Landlock LSM.

        Arguments:
            OPERAND...                                       Argument(s) passed through to the clanker binary.

        Options:
            --clanker CLANKER                                The clanker binary to jail (mandatory).

            --sensitive-path-config PERMISSION_LEVEL:PATH    Explicitly allow/deny a sensitive path at a permission level.
            --allow-ro PATH                                  Allow read-only access to PATH.
            --allow-rox PATH                                 Allow read + execute access to PATH.
            --allow-rw PATH                                  Allow read + write access to PATH.
            --allow-rwx PATH                                 Allow read + write + execute access to PATH.
            --allow-rw-rm PATH                               Allow read, write and remove access to PATH.
            --allow-rwx-rm PATH                              Allow read, write, remove and execute access to PATH.

            --show-config                                    Show the config.
            --show-config-and-exit                           Show the config and then exit.


            --help                                           Show this help message and exit.

        Permission levels (--sensitive-path-config):
            deny-all        Landlock works on a \"deny everything, approve selectively\" philosophy. Ensure a path is denied no matter what.
            read            Allow only read-only permissions for a PATH.
            write           Allow only reading and writing to a PATH.
            remove          Allow reading, writing and removals from PATH.

        Examples:
            clanker-jail --clanker /usr/bin/pi \
                -- --offline                                      Equivalent to `pi --offline`.

            clanker-jail --clanker /usr/bin/pi \
                --allow-rw .                                      Allow clanker to read + write from $PWD.

            clanker-jail --clanker /usr/bin/pi \
                --sensitive-path-config deny-all:~/.ssh/config    $HOME/.ssh/config shouldn't be allowed in the sandbox.
    ";
    println!(
        "{}",
        help_message
            .trim()
            .lines()
            .map(|line| line.strip_prefix("        ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn make_accessible_paths_inner_unstructured(
    user_overrides: &mut AccessiblePaths,
    specified_path: &ffi::OsString,
    permission: ClankerPermissions,
) -> Result<(), Box<dyn Error>> {
    match path::absolute(specified_path) {
        Ok(specified_absolute_path) => {
            if specified_absolute_path.exists() {
                user_overrides.insert((specified_absolute_path.display().to_string(), permission));
                Ok(())
            } else {
                Err(format!(
                    "Could not determine the absolute path for '{}'",
                    specified_path.display()
                )
                .into())
            }
        }
        Err(_) => Err(format!(
            "Could not determine the absolute path for '{}'",
            specified_path.display()
        )
        .into()),
    }
}

fn get_paths_from_env_var(env_var_name: &str) -> Vec<String> {
    let env_var_value = env::var(env_var_name).unwrap_or_else(|_| String::new());
    if env_var_value.is_empty() {
        Vec::new()
    } else {
        env_var_value
            .split(':')
            .filter_map(|path_in_env_var_value| path::absolute(path_in_env_var_value).ok())
            .map(|path_in_env_var_value| path_in_env_var_value.display().to_string())
            .collect()
    }
}

fn get_default_accessible_paths(local_conf: &DefaultAccessiblePathsConfig) -> AccessiblePaths {
    let mut default_accessible_paths = AccessiblePaths::new();

    // NixOS
    default_accessible_paths.insert_lossy(("/nix/store", CLANKER_PERMISSIONS_ROX));
    default_accessible_paths.insert_lossy((
        format!("{}/nix", local_conf.xdg_cache_home).as_str(),
        CLANKER_PERMISSIONS_RW,
    ));
    // Non-NixOS
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_ROX,
        &[
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/lib64",
            "/usr/libexec",
            "/usr/local/lib",
        ],
    );

    // DNS
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &["/etc/resolv.conf", "/etc/resolvconf.conf"],
    );
    // TLS
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            // NixOS
            "/etc/ssl/certs/ca-bundle.crt",
            "/etc/ssl/certs/ca-certificates.crt",
            // Fedora
            "/etc/ssl/certs/ca-bundle.trust.crt",
        ],
    );

    // Git config
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            "/etc/gitconfig",
            format!("{}/.gitconfig", local_conf.user_home_dir).as_str(),
            format!("{}/git", local_conf.xdg_config_home).as_str(),
        ],
    );

    // Rust
    default_accessible_paths.insert_lossy((&local_conf.cargo_home, CLANKER_PERMISSIONS_RW));
    default_accessible_paths.insert_lossy((&local_conf.rustup_home, CLANKER_PERMISSIONS_ROX));

    // Neovim
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            "/usr/share/nvim", // required on non-NixOS
            format!("{}/nvim", local_conf.xdg_config_home).as_str(),
        ],
    );

    // git-adjacent CLIs
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            // forgejo
            format!("{}/forgejo-cli", local_conf.xdg_data_home).as_str(),
            // github
            format!("{}/gh", local_conf.xdg_config_home).as_str(),
            // gitlab
            format!("{}/glab-cli", local_conf.xdg_config_home).as_str(),
            // gitea
            format!("{}/tea", local_conf.xdg_config_home).as_str(),
        ],
    );

    // tmux
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            "/etc/tmux.conf",
            "/etc/tmux/tmux.conf",
            format!("{}/.tmux", local_conf.user_home_dir).as_str(),
            format!("{}/.tmux.conf", local_conf.user_home_dir).as_str(),
        ],
    );

    // clankers
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RW_RM,
        &[
            // pi
            format!("{}/.pi", local_conf.user_home_dir).as_str(),
            format!("{}/pi", local_conf.xdg_config_home).as_str(),
            // claude
            format!("{}/.claude", local_conf.user_home_dir).as_str(),
            // codex
            format!("{}/.codex", local_conf.user_home_dir).as_str(),
        ],
    );
    // clanker itself
    default_accessible_paths.insert_lossy((&local_conf.clanker, CLANKER_PERMISSIONS_ROX));

    // $PWD
    default_accessible_paths.insert_lossy((
        &local_conf.current_working_directory,
        CLANKER_PERMISSIONS_RO,
    ));

    // $TMPDIR
    default_accessible_paths.insert_lossy((&local_conf.tmpdir, CLANKER_PERMISSIONS_RWX_RM));

    // $PATH
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_ROX,
        &get_paths_from_env_var("PATH")
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>(),
    );

    // LD_LIBRARY_PATH
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_ROX,
        &get_paths_from_env_var("LD_LIBRARY_PATH")
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>(),
    );

    // Miscellaneous
    default_accessible_paths.extend_lossy(
        CLANKER_PERMISSIONS_RO,
        &[
            "/dev/random",
            "/dev/urandom",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/self",
        ],
    );
    default_accessible_paths.insert_lossy(("/dev/null", CLANKER_PERMISSIONS_RW));

    default_accessible_paths
}

fn get_permission_level(
    sandbox_permissions: ClankerPermissions,
) -> Option<ClankerPermissionsLevel> {
    if sandbox_permissions.contains(landlock::AccessFs::RemoveFile) {
        Some(ClankerPermissionsLevel::Remove)
    } else if sandbox_permissions.contains(landlock::AccessFs::WriteFile) {
        Some(ClankerPermissionsLevel::Write)
    } else if sandbox_permissions.contains(landlock::AccessFs::ReadFile) {
        Some(ClankerPermissionsLevel::Read)
    } else {
        None
    }
}

fn ensure_sensitive_paths_are_explicitly_allowed(
    accessible_paths: &AccessiblePaths,
    sensitive_path_configs: &HashMap<String, ClankerPermissionsLevel>,
) -> Result<(), Box<dyn Error>> {
    for (sensitive_path, default_sandbox_permission_level) in sensitive_path_configs {
        if accessible_paths.contains_key(sensitive_path) {
            match accessible_paths.get(sensitive_path) {
                None => return Err(format!("The sandbox paths HashMap contains the sensitive path '{sensitive_path}' but its permissions could not be fetched. This should NEVER happen.").into()),
                Some(current_sandbox_permissions) => match get_permission_level(*current_sandbox_permissions) {
                    None => return Err(format!("Could not determine the permission level for path '{sensitive_path}'. This should NEVER happen.").into()),
                    Some(current_sandbox_permission_level) => {
                        if *default_sandbox_permission_level < current_sandbox_permission_level {
                            return Err(format!("'{sensitive_path}' is a sensitive path with '{current_sandbox_permission_level:?}' permissions, but this wasn't allowed explicitly. Ideally, you should use leaf path(s) to allow. Use `--sensitive-path-config <LEVEL>:<PATH>` to allow it.").into());
                        }
                    },
                },
            }
        }
    }
    Ok(())
}

pub fn configure_clanker_jail() -> Result<ClankerJailConfig, Box<dyn Error>> {
    use lexopt::prelude::*;

    let current_working_directory = env::current_dir()?.display().to_string();

    let user_home_dir = env::var("HOME")?;
    let tmpdir = env::var("TMPDIR").unwrap_or("/tmp".to_string());
    let xdg_config_home = match env::var("XDG_CONFIG_HOME") {
        Ok(xdg_config_home) => xdg_config_home,
        Err(_) => format!("{user_home_dir}/.config"),
    };
    let xdg_data_home = match env::var("XDG_DATA_HOME") {
        Ok(xdg_data_home) => xdg_data_home,
        Err(_) => format!("{user_home_dir}/.local/share"),
    };
    let xdg_cache_home = match env::var("XDG_CACHE_HOME") {
        Ok(xdg_cache_home) => xdg_cache_home,
        Err(_) => format!("{user_home_dir}/.cache"),
    };
    std::fs::create_dir_all(&tmpdir)?;
    let cargo_home = env::var("CARGO_HOME").unwrap_or_else(|_| format!("{user_home_dir}/.cargo"));
    let rustup_home =
        env::var("RUSTUP_HOME").unwrap_or_else(|_| format!("{user_home_dir}/.rustup"));

    unsafe {
        env::set_var("TMPDIR", &tmpdir);
        env::set_var("CARGO_HOME", &cargo_home);
        env::set_var("RUSTUP_HOME", &rustup_home);
    }

    let mut sensitive_path_configs: HashMap<String, ClankerPermissionsLevel> = HashMap::new();
    for sensitive_path in [
        "/".to_string(),
        "/etc".to_string(),
        "/root".to_string(),
        "/usr/share/doc".to_string(),
        "/usr/share/info".to_string(),
        "/usr/share/locale".to_string(),
        "/usr/share/man".to_string(),
        "/var/lib".to_string(),
        "/var/private".to_string(),
        format!("{user_home_dir}/.aws"),
        format!("{user_home_dir}/.azure"),
        format!("{user_home_dir}/.docker"),
        format!("{user_home_dir}/.gcloud"),
        format!("{user_home_dir}/.gnupg"),
        format!("{user_home_dir}/.kube"),
        format!("{user_home_dir}/.local/share"),
        format!("{user_home_dir}/.local/state"),
        format!("{user_home_dir}/.password-store"),
        format!("{user_home_dir}/.ssh"),
        user_home_dir.clone(),
        xdg_config_home.clone(),
    ] {
        sensitive_path_configs.insert(sensitive_path, ClankerPermissionsLevel::NoPermissions);
    }

    let mut clanker = None;
    let mut clanker_operands = Vec::new();
    let mut user_overrides = AccessiblePaths::new();

    let mut show_config = false;
    let mut show_config_and_exit = false;

    let mut lexopt_parser = lexopt::Parser::from_env();
    while let Some(arg) = lexopt_parser.next()? {
        match arg {
            Long("clanker") => {
                let specified_clanker = lexopt_parser.value()?;
                match path::absolute(&specified_clanker) {
                    Ok(specified_clanker_path) => {
                        if specified_clanker_path.exists() {
                            clanker = Some(specified_clanker_path.display().to_string());
                        } else {
                            return Err(format!(
                                "The clanker path '{}' does not exist",
                                specified_clanker.display()
                            )
                            .into());
                        }
                    }
                    Err(_) => {
                        return Err(format!(
                            "Could not determine the absolute path for clanker '{}'",
                            specified_clanker.display()
                        )
                        .into());
                    }
                }
            }

            Value(operand) => clanker_operands.push(operand),

            Long("allow-ro") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_RO,
            )?,
            Long("allow-rox") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_ROX,
            )?,
            Long("allow-rw") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_RW,
            )?,
            Long("allow-rwx") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_RWX,
            )?,
            Long("allow-rw-rm") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_RW_RM,
            )?,
            Long("allow-rwx-rm") => make_accessible_paths_inner_unstructured(
                &mut user_overrides,
                &lexopt_parser.value()?,
                CLANKER_PERMISSIONS_RWX_RM,
            )?,

            Long("sensitive-path-config") => {
                let specified_sensitive_path_config = lexopt_parser.value()?.string()?;
                let (specified_sandbox_level, specified_path_to_sandbox) =
                    specified_sensitive_path_config
                        .split_once(':')
                        .ok_or("`--sensitive-path-config` expects `<permission-level>:<path>`")?;
                match path::absolute(specified_path_to_sandbox) {
                    Err(_) => {
                        return Err(format!(
                            "Could not determine the absolute path for '{specified_path_to_sandbox}'",

                        )
                        .into());
                    }
                    Ok(specified_path_to_sandbox) => {
                        match ClankerPermissionsLevel::from_str(specified_sandbox_level) {
                            None => {
                                return Err(format!(
                                    "Unknown permission level '{specified_sandbox_level}'"
                                )
                                .into());
                            }
                            Some(specified_sandbox_level) => sensitive_path_configs.insert(
                                specified_path_to_sandbox.display().to_string(),
                                specified_sandbox_level,
                            ),
                        }
                    }
                };
            }

            Long("show-config") => show_config = true,
            Long("show-config-and-exit") => {
                show_config = true;
                show_config_and_exit = true;
            }

            Long("help") => {
                print_help();
                std::process::exit(0);
            }

            /*
             * TODO: String -> ClankerPermissions
            Long("landlock-rule") => {
                let specified_landlock_rules = lexopt_parser.value()?.string()?;
                let permissions = ();
            },
            */
            _ => return Err(arg.unexpected().into()),
        }
    }

    let Some(clanker) = clanker else {
        return Err("`--clanker` is a mandatory option".into());
    };

    let mut accessible_paths = get_default_accessible_paths(&DefaultAccessiblePathsConfig {
        cargo_home,
        clanker: clanker.clone(),
        current_working_directory,
        rustup_home,
        tmpdir,
        user_home_dir: user_home_dir.clone(),
        xdg_config_home,
        xdg_data_home,
        xdg_cache_home,
    });
    user_overrides.into_iter().for_each(|accessible_path| {
        accessible_paths.insert((accessible_path.0, accessible_path.1));
    });

    ensure_sensitive_paths_are_explicitly_allowed(&accessible_paths, &sensitive_path_configs)?;

    let clanker_jail_config = ClankerJailConfig {
        clanker,
        clanker_operands,
        accessible_paths,
        sensitive_path_configs,
    };

    if show_config {
        eprintln!("{clanker_jail_config:#?}");
        if show_config_and_exit {
            std::process::exit(0);
        }
    }

    Ok(clanker_jail_config)
}
