// The service as a launchd job in the login session (gui/<uid>). launchd
// holds the agent's SSH socket at a fixed path and starts the agent when a
// program connects to it.
//
// Apple's ssh-agent job keeps SSH_AUTH_SOCK, and is left alone: macOS doesn't
// let it stay disabled, and both agents stay usable. SSH reaches rbw-agent
// through IdentityAgent in ~/.ssh/config, for all hosts or for some, and
// tools that only read SSH_AUTH_SOCK through the shell profile.

pub const MANAGER: &str = "launchd";

const LAUNCHCTL: &str = "/bin/launchctl";
const LABEL_PREFIX: &str = "io.github.timothefcn.rbw-ng.";

// The longest path a Unix socket address holds on macOS (sun_path, without
// its terminating NUL).
const MAX_SOCKET_PATH: usize = 103;

// the same signature as on the systems that can fail it
#[allow(clippy::unnecessary_wraps)]
pub fn check_supported() -> anyhow::Result<()> {
    Ok(())
}

pub fn describe(name: &str) -> String {
    format!("the launchd job {}", label(name))
}

pub fn installed(name: &str) -> bool {
    plist_path(name).is_ok_and(|path| path.exists())
}

// Each profile has a socket of its own, and none takes SSH_AUTH_SOCK.
#[allow(clippy::unnecessary_wraps)]
pub fn other_installs(_name: &str) -> anyhow::Result<Vec<String>> {
    Ok(vec![])
}

pub fn state(name: &str) -> String {
    if loaded(name) {
        "loaded".to_string()
    } else {
        "not loaded; it loads at the next login".to_string()
    }
}

pub fn unload(name: &str) -> anyhow::Result<()> {
    if loaded(name) {
        launchctl(&["bootout", &target(&label(name))])?;
    }
    Ok(())
}

pub fn install(service: &super::Service) -> anyhow::Result<()> {
    let socket = rbw::dirs::service_ssh_agent_socket_file();
    if super::text(&socket)?.len() > MAX_SOCKET_PATH {
        anyhow::bail!(
            "the SSH socket's path, {}, is too long for a socket",
            socket.display()
        );
    }
    // the socket's folder, which only this user can open
    rbw::dirs::make_all()?;
    // launchd binds the path itself
    remove_socket(&socket)?;

    let path = plist_path(&service.name)?;
    super::write_file(&path, &plist(service, &socket)?)?;
    let label = label(&service.name);
    launchctl(&["enable", &target(&label)])?;
    launchctl(&["bootstrap", &domain(), super::text(&path)?])?;
    Ok(())
}

pub fn next_steps(socket: &std::path::Path) -> Vec<super::Step> {
    if super::ssh_config_uses(socket) {
        return vec![];
    }
    let line = format!("    IdentityAgent \"{}\"", super::tilde(socket));
    vec![super::Step {
        text: "Paste this so that SSH uses it for every host:".to_string(),
        command: Some(format!(
            "mkdir -p ~/.ssh && printf '\\nHost *\\n%s\\n' {} >> ~/.ssh/config",
            super::shell_quote(&line)
        )),
        note: Some(
            "For some hosts only, put that IdentityAgent line under their \
            Host entries instead."
                .to_string(),
        ),
    }]
}

pub fn uninstall(name: &str) -> anyhow::Result<bool> {
    if !installed(name) {
        return Ok(false);
    }
    unload(name)?;
    super::remove_file(&plist_path(name)?)?;
    remove_socket(&rbw::dirs::service_ssh_agent_socket_file())?;
    Ok(true)
}

pub fn uninstall_notes() -> Vec<String> {
    if super::ssh_config_uses(&rbw::dirs::service_ssh_agent_socket_file()) {
        vec!["Remove its IdentityAgent line from ~/.ssh/config.".to_string()]
    } else {
        vec![]
    }
}

pub fn log(_name: &str) -> String {
    rbw::dirs::agent_stderr_file().display().to_string()
}

pub fn start(name: &str) -> anyhow::Result<()> {
    launchctl(&["kickstart", &target(&label(name))])?;
    Ok(())
}

// the same signature as on the systems without a socket of their own
#[allow(clippy::unnecessary_wraps)]
pub fn service_socket(_name: &str) -> Option<std::path::PathBuf> {
    Some(rbw::dirs::service_ssh_agent_socket_file())
}

pub fn pinentry_note(pinentry: &std::path::Path) -> Option<String> {
    let name = pinentry.file_name()?.to_string_lossy();
    if name.starts_with("pinentry-mac") {
        return None;
    }
    Some(format!(
        "an SSH request that finds the vault locked asks for the master \
        password through pinentry, with no terminal to show it in; \
        '{}' may need one: pinentry-mac shows a dialog \
        (`brew install pinentry-mac`, then `rbw config set pinentry \
        pinentry-mac`)",
        pinentry.display()
    ))
}

fn loaded(name: &str) -> bool {
    launchctl(&["print", &target(&label(name))]).is_ok()
}

// Removes a socket left at the path, and refuses to replace anything else.
fn remove_socket(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            super::remove_file(path)
        }
        Ok(_) => anyhow::bail!(
            "{} is in the way of the SSH socket; remove it first",
            path.display()
        ),
        Err(_) => Ok(()),
    }
}

fn label(name: &str) -> String {
    format!("{LABEL_PREFIX}{name}")
}

fn domain() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}

fn target(label: &str) -> String {
    format!("{}/{label}", domain())
}

fn plist_path(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let home = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("couldn't find the home folder"))?
        .home_dir()
        .to_path_buf();
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", label(name))))
}

fn launchctl(args: &[&str]) -> anyhow::Result<String> {
    super::run(LAUNCHCTL, args)
}

fn plist(
    service: &super::Service,
    socket: &std::path::Path,
) -> anyhow::Result<String> {
    let environment = super::environment(service)?
        .iter()
        .map(|(key, value)| {
            format!(
                "\t\t<key>{key}</key>\n\t\t<string>{}</string>\n",
                xml(value)
            )
        })
        .collect::<Vec<_>>()
        .concat();

    // SockPathMode is 0600, in decimal.
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{agent}</string>
		<string>--service</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
{environment}	</dict>
	<key>Sockets</key>
	<dict>
		<key>Listeners</key>
		<dict>
			<key>SockPathName</key>
			<string>{socket}</string>
			<key>SockPathMode</key>
			<integer>384</integer>
		</dict>
	</dict>
	<key>StandardOutPath</key>
	<string>{stdout}</string>
	<key>StandardErrorPath</key>
	<string>{stderr}</string>
</dict>
</plist>
"#,
        label = xml(&label(&service.name)),
        agent = xml(super::text(&service.agent)?),
        socket = xml(super::text(socket)?),
        stdout = xml(super::text(&rbw::dirs::agent_stdout_file())?),
        stderr = xml(super::text(&rbw::dirs::agent_stderr_file())?),
    ))
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_escapes_text_and_holds_the_socket() {
        let plist = super::plist(
            &super::super::Service {
                name: "rbw-agent".to_string(),
                agent: "/opt/a&b/<rbw-agent>".into(),
                path: "/usr/bin:/bin".into(),
            },
            std::path::Path::new(
                "/Users/me/Library/Application Support/rbw/s",
            ),
        )
        .unwrap();
        assert!(
            plist.contains("<string>/opt/a&amp;b/&lt;rbw-agent&gt;</string>")
        );
        assert!(plist.contains(
            "<string>io.github.timothefcn.rbw-ng.rbw-agent</string>"
        ));
        assert!(plist.contains(
            "<key>SockPathName</key>\n\t\t\t<string>/Users/me/Library/Application Support/rbw/s</string>"
        ));
        assert!(plist.contains("<integer>384</integer>"));
        assert!(!plist.contains("SSH_AUTH_SOCK"));
        assert!(!plist.contains("KeepAlive"));
        assert!(!plist.contains("RunAtLoad"));
    }
}
