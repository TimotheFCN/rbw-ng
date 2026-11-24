// Systems without launchd or systemd: rbw starts the agent itself.

// the same signatures as the service managers' modules
#![allow(clippy::unnecessary_wraps)]

pub fn check_supported() -> anyhow::Result<()> {
    anyhow::bail!(
        "rbw ssh-agent install needs launchd (macOS) or systemd (Linux); \
        start the agent with `rbw unlock` instead, and set SSH_AUTH_SOCK to \
        the path that `rbw ssh-agent socket` prints"
    )
}

pub fn describe(_name: &str) -> String {
    "a service".to_string()
}

pub fn installed(_name: &str) -> bool {
    false
}

pub fn other_installs(_name: &str) -> anyhow::Result<Vec<String>> {
    Ok(vec![])
}

pub fn state(_name: &str) -> String {
    String::new()
}

pub fn unload(_name: &str) -> anyhow::Result<()> {
    Ok(())
}

pub fn install(_service: &super::Service) -> anyhow::Result<()> {
    check_supported()
}

pub fn install_notes() -> Vec<String> {
    vec![]
}

pub fn uninstall(_name: &str) -> anyhow::Result<bool> {
    Ok(false)
}

pub fn uninstall_notes() -> Vec<String> {
    vec![]
}

pub fn log(_name: &str) -> String {
    rbw::dirs::agent_stderr_file().display().to_string()
}

pub fn start(_name: &str) -> anyhow::Result<()> {
    check_supported()
}

pub fn service_socket(_name: &str) -> Option<std::path::PathBuf> {
    None
}

pub fn pinentry_note(_pinentry: &std::path::Path) -> Option<String> {
    None
}
