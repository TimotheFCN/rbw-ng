use crate::prelude::*;

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server =
        percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
            .to_string();
    cache_dir().join(format!("{server}:{email}.json"))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

// The vault key, encrypted with a session key that the program that made
// the session keeps (see rbw unlock --session).
pub fn session_file() -> std::path::PathBuf {
    data_dir().join("session.json")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

// The SSH socket that launchd holds for the macOS service. launchd creates it
// at login, before anything could create the runtime folder, so it lives in
// a folder that outlasts restarts.
pub fn service_ssh_agent_socket_file() -> std::path::PathBuf {
    data_dir().join("ssh-agent-socket")
}

// Every profile on this computer that has a configuration, with its
// configuration file. The default profile has no name.
pub fn profiles() -> Vec<(Option<String>, std::path::PathBuf)> {
    let Some(entries) = config_dir()
        .parent()
        .and_then(|parent| std::fs::read_dir(parent).ok())
    else {
        return vec![];
    };
    let mut profiles: Vec<_> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            let profile = match name.strip_prefix("rbw-") {
                _ if name == "rbw" => None,
                Some(profile) if !profile.is_empty() => {
                    Some(profile.to_string())
                }
                _ => return None,
            };
            let config = entry.path().join("config.json");
            config.is_file().then_some((profile, config))
        })
        .collect();
    profiles.sort();
    profiles
}

// Every folder the profile keeps files in. On macOS the configuration and
// the data share one.
pub fn profile_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![config_dir(), data_dir(), cache_dir(), runtime_dir()];
    dirs.dedup();
    dirs
}

fn config_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.config_dir().to_path_buf()
}

fn cache_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.cache_dir().to_path_buf()
}

fn data_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.data_dir().to_path_buf()
}

fn runtime_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.runtime_dir().map_or_else(
        || {
            format!(
                "{}/{}-{}",
                std::env::temp_dir().to_string_lossy(),
                profile(),
                rustix::process::getuid().as_raw()
            )
            .into()
        },
        std::path::Path::to_path_buf,
    )
}

// The name of the profile's folders, from RBW_PROFILE, which rbw and
// rbw-agent check with check_profile before anything else.
pub fn profile() -> String {
    folder_name(std::env::var_os("RBW_PROFILE").as_deref())
        .expect("RBW_PROFILE is checked at startup")
}

// Fails for an RBW_PROFILE that would put the profile's folders somewhere
// else than its own: with RBW_PROFILE=a/../.. the configuration folder would
// be the home folder, which rbw purge --all removes.
pub fn check_profile() -> Result<()> {
    folder_name(std::env::var_os("RBW_PROFILE").as_deref()).map(drop)
}

fn folder_name(profile: Option<&std::ffi::OsStr>) -> Result<String> {
    let Some(profile) = profile.filter(|profile| !profile.is_empty()) else {
        return Ok("rbw".to_string());
    };
    let invalid = |reason: &str| Error::InvalidProfile {
        reason: reason.to_string(),
    };
    let profile = profile
        .to_str()
        .ok_or_else(|| invalid("RBW_PROFILE isn't valid UTF-8"))?;
    if profile.contains('/') {
        return Err(invalid("RBW_PROFILE can't contain '/'"));
    }
    Ok(format!("rbw-{profile}"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn profiles_stay_in_their_own_folders() {
        use std::os::unix::ffi::OsStrExt as _;

        let name = |profile: &[u8]| {
            folder_name(Some(std::ffi::OsStr::from_bytes(profile)))
        };
        assert_eq!(folder_name(None).unwrap(), "rbw");
        assert_eq!(name(b"").unwrap(), "rbw");
        assert_eq!(name(b"work").unwrap(), "rbw-work");
        assert_eq!(name(b"..").unwrap(), "rbw-..");
        for invalid in [&b"work/../.."[..], b"/", b"../x", b"\xff"] {
            assert!(
                matches!(name(invalid), Err(Error::InvalidProfile { .. })),
                "{invalid:?}"
            );
        }
    }
}
