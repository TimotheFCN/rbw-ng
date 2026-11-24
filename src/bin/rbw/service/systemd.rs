// The service as systemd user units: two socket units hold the agent's
// usual sockets (rbw's and the SSH one) and start the service unit when a
// program connects. An environment.d file sets SSH_AUTH_SOCK for the
// programs that the user's systemd and graphical session start.

const SYSTEMCTL: &str = "systemctl";

pub fn check_supported() -> anyhow::Result<()> {
    // how sd_booted() tells
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        anyhow::bail!(
            "rbw ssh-agent install needs systemd, which this system doesn't \
            run; start the agent with `rbw unlock` instead, and set \
            SSH_AUTH_SOCK to the path that `rbw ssh-agent socket` prints"
        );
    }
    Ok(())
}

pub fn describe(name: &str) -> String {
    format!("the systemd user units {}", units(name).join(", "))
}

pub fn installed(name: &str) -> bool {
    unit_dir().is_ok_and(|dir| dir.join(service_unit(name)).exists())
}

pub fn other_installs(name: &str) -> anyhow::Result<Vec<String>> {
    let own = ssh_socket_unit(name);
    let dir = unit_dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(vec![]);
    };
    Ok(entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|file| {
            file.starts_with("rbw")
                && file.ends_with("-agent-ssh.socket")
                && *file != own
        })
        .map(|file| dir.join(file).display().to_string())
        .collect())
}

pub fn state(name: &str) -> String {
    let sockets = [control_socket_unit(name), ssh_socket_unit(name)];
    let mut args = vec!["--user", "is-active"];
    args.extend(sockets.iter().map(String::as_str));
    // one line per unit; fails unless all are active
    match super::run(SYSTEMCTL, &args) {
        Ok(_) => "listening".to_string(),
        Err(_) => {
            "sockets not listening; check `systemctl --user status \
            "
            .to_string()
                + &sockets.join(" ")
                + "`"
        }
    }
}

pub fn unload(name: &str) -> anyhow::Result<()> {
    if installed(name) {
        let units = units(name);
        let mut args = vec!["--user", "stop"];
        args.extend(units.iter().map(String::as_str));
        systemctl(&args)?;
    }
    Ok(())
}

pub fn install(service: &super::Service) -> anyhow::Result<()> {
    let dir = unit_dir()?;
    let name = &service.name;
    let control = rbw::dirs::socket_file();
    let ssh = rbw::dirs::ssh_agent_socket_file();

    super::write_file(
        &dir.join(service_unit(name)),
        &service_file(service)?,
    )?;
    super::write_file(
        &dir.join(control_socket_unit(name)),
        &socket_file(name, "control", &control, "rbw-agent's socket")?,
    )?;
    super::write_file(
        &dir.join(ssh_socket_unit(name)),
        &socket_file(name, "ssh", &ssh, "rbw-agent's SSH socket")?,
    )?;
    super::write_file(
        &environment_file(name)?,
        &format!("SSH_AUTH_SOCK={}\n", environment_value(&ssh)?),
    )?;

    // left by an agent that rbw started, which has stopped by now
    for socket in [&control, &ssh] {
        if is_socket(socket) {
            super::remove_file(socket)?;
        }
    }

    systemctl(&["--user", "daemon-reload"])?;
    let sockets = [control_socket_unit(name), ssh_socket_unit(name)];
    let mut args = vec!["--user", "enable", "--now"];
    args.extend(sockets.iter().map(String::as_str));
    systemctl(&args)?;
    Ok(())
}

pub fn install_notes() -> Vec<String> {
    let mut notes = vec![
        "Graphical sessions get SSH_AUTH_SOCK from the next login on, through \
        environment.d."
            .to_string(),
        "Logins that don't read environment.d, such as SSH and the console, \
        need this in the shell profile:"
            .to_string(),
        "  export SSH_AUTH_SOCK=\"$(rbw ssh-agent socket)\"".to_string(),
    ];
    if let Some(current) = std::env::var_os("SSH_AUTH_SOCK") {
        let ssh = rbw::dirs::ssh_agent_socket_file();
        if std::path::Path::new(&current) != ssh {
            notes.push(format!(
                "SSH_AUTH_SOCK is {} in this shell: if another agent sets it \
                at login, such as GNOME Keyring's, `rbw ssh-agent status` \
                will show it after you log in again.",
                std::path::Path::new(&current).display()
            ));
        }
    }
    notes
}

pub fn uninstall(name: &str) -> anyhow::Result<bool> {
    if !installed(name) {
        return Ok(false);
    }
    let sockets = [control_socket_unit(name), ssh_socket_unit(name)];
    let mut args = vec!["--user", "disable", "--now"];
    args.extend(sockets.iter().map(String::as_str));
    systemctl(&args)?;
    systemctl(&["--user", "stop", &service_unit(name)])?;

    let dir = unit_dir()?;
    for unit in units(name) {
        super::remove_file(&dir.join(unit))?;
    }
    super::remove_file(&environment_file(name)?)?;
    systemctl(&["--user", "daemon-reload"])?;
    Ok(true)
}

pub fn uninstall_notes() -> Vec<String> {
    vec![
        "Log out and back in so that SSH_AUTH_SOCK goes back to what it was."
            .to_string(),
    ]
}

pub fn log(name: &str) -> String {
    format!("`journalctl --user -u {}`", service_unit(name))
}

pub fn start(name: &str) -> anyhow::Result<()> {
    // also starts the sockets, which the service requires
    systemctl(&["--user", "start", &service_unit(name)])
}

pub fn service_socket(_name: &str) -> Option<std::path::PathBuf> {
    // the SSH socket unit listens at the agent's usual path
    None
}

pub fn pinentry_note(_pinentry: &std::path::Path) -> Option<String> {
    None
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    super::run(SYSTEMCTL, args).map(|_| ())
}

fn service_unit(name: &str) -> String {
    format!("{name}.service")
}

fn control_socket_unit(name: &str) -> String {
    format!("{name}.socket")
}

fn ssh_socket_unit(name: &str) -> String {
    format!("{name}-ssh.socket")
}

fn units(name: &str) -> [String; 3] {
    [
        control_socket_unit(name),
        ssh_socket_unit(name),
        service_unit(name),
    ]
}

fn config_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("couldn't find the home folder"))?
        .config_dir()
        .to_path_buf())
}

fn unit_dir() -> anyhow::Result<std::path::PathBuf> {
    Ok(config_dir()?.join("systemd/user"))
}

fn environment_file(name: &str) -> anyhow::Result<std::path::PathBuf> {
    // late in the order, so that it wins over earlier files
    Ok(config_dir()?.join(format!("environment.d/90-{name}.conf")))
}

fn is_socket(path: &std::path::Path) -> bool {
    std::os::unix::fs::FileTypeExt::is_socket(
        &match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.file_type(),
            Err(_) => return false,
        },
    )
}

fn service_file(service: &super::Service) -> anyhow::Result<String> {
    let name = &service.name;
    let environment = super::environment(service)?
        .iter()
        .map(|(key, value)| {
            format!("Environment={}\n", quoted(&format!("{key}={value}")))
        })
        .collect::<Vec<_>>()
        .concat();
    Ok(format!(
        "[Unit]
Description=rbw-agent, the Bitwarden vault and SSH key agent of rbw
Documentation=https://github.com/TimotheFCN/rbw-ng/wiki
Requires={control} {ssh}
After={control} {ssh}

[Service]
ExecStart={agent} --service
{environment}",
        control = control_socket_unit(name),
        ssh = ssh_socket_unit(name),
        agent = quoted(super::text(&service.agent)?).replace('$', "$$"),
    ))
}

fn socket_file(
    name: &str,
    fd_name: &str,
    path: &std::path::Path,
    description: &str,
) -> anyhow::Result<String> {
    let path = super::text(path)?;
    if path.chars().any(char::is_whitespace) {
        anyhow::bail!("the socket path {path} holds spaces");
    }
    Ok(format!(
        "[Unit]
Description={description}

[Socket]
ListenStream={path}
SocketMode=0600
RemoveOnStop=yes
DirectoryMode=0700
FileDescriptorName={fd_name}
Service={service}

[Install]
WantedBy=sockets.target
",
        path = path.replace('%', "%%"),
        service = service_unit(name),
    ))
}

// A quoted unit file value, where systemd also expands % specifiers.
fn quoted(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

// environment.d expands $ and \, so a path that holds them is refused
// rather than escaped.
fn environment_value(path: &std::path::Path) -> anyhow::Result<&str> {
    let text = super::text(path)?;
    if text.contains(['$', '\\']) || text.chars().any(char::is_whitespace) {
        anyhow::bail!("the socket path {text} can't go in environment.d");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    fn service(agent: &str) -> super::super::Service {
        super::super::Service {
            name: "rbw-agent".to_string(),
            agent: agent.into(),
            path: "/usr/bin:/bin".into(),
        }
    }

    #[test]
    fn values_are_quoted_and_specifiers_escaped() {
        assert_eq!(super::quoted(r#"a"b\c%d"#), r#""a\"b\\c%%d""#);
    }

    #[test]
    fn service_runs_the_agent_in_service_mode() {
        let unit =
            super::service_file(&service("/opt/my $dir/rbw-agent")).unwrap();
        assert!(unit
            .contains("\nExecStart=\"/opt/my $$dir/rbw-agent\" --service\n"));
        assert!(unit.contains("\nEnvironment=\"PATH=/usr/bin:/bin\"\n"));
        assert!(unit
            .contains("\nRequires=rbw-agent.socket rbw-agent-ssh.socket\n"));
    }

    #[test]
    fn paths_that_would_break_a_unit_are_refused() {
        assert!(super::service_file(&service("/opt/rbw\nExecStartPre=/x"))
            .is_err());
        assert!(super::socket_file(
            "rbw-agent",
            "ssh",
            std::path::Path::new("/run/user/1000/a b/s"),
            "test",
        )
        .is_err());
        assert!(super::environment_value(std::path::Path::new(
            "/run/$HOME/s"
        ))
        .is_err());
    }

    #[test]
    fn sockets_are_private_and_named() {
        let unit = super::socket_file(
            "rbw-agent",
            "ssh",
            std::path::Path::new("/run/user/1000/rbw/ssh-agent-socket"),
            "test",
        )
        .unwrap();
        assert!(unit.contains(
            "\nListenStream=/run/user/1000/rbw/ssh-agent-socket\n"
        ));
        assert!(unit.contains("\nSocketMode=0600\n"));
        assert!(unit.contains("\nFileDescriptorName=ssh\n"));
        assert!(unit.contains("\nService=rbw-agent.service\n"));
    }
}
