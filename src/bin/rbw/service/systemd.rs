// The service as systemd user units: two socket units hold the agent's
// usual sockets (rbw's and the SSH one) and start the service unit when a
// program connects. An environment.d file sets SSH_AUTH_SOCK for the
// programs that the user's systemd and graphical session start.
//
// The sockets are at the paths where an agent that rbw starts listens, and
// systemd would take them from a running agent. So the sockets start only
// while no agent runs: an agent that runs keeps its sockets and the vault
// until it stops, and the sockets start then (activate). The other way
// round, the service only wants its sockets, and they stay where they are
// when they stop, so that uninstalling leaves a running agent serving at
// the same paths until it stops too.

pub const MANAGER: &str = "systemd";

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

// The names of the other profiles' services: only one can set the session's
// SSH_AUTH_SOCK.
pub fn other_installs(name: &str) -> anyhow::Result<Vec<String>> {
    let dir = unit_dir()?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(vec![]);
    };
    Ok(entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|file| {
            file.strip_suffix("-ssh.socket")
                .filter(|other| {
                    other.starts_with("rbw")
                        && other.ends_with("-agent")
                        && *other != name
                })
                .map(str::to_string)
        })
        .collect())
}

pub fn state(name: &str) -> String {
    if listening(name) {
        "listening".to_string()
    } else if super::running_agent().is_some() {
        "waiting: the agent that runs now serves until it stops".to_string()
    } else {
        format!(
            "sockets not listening; check `systemctl --user status {}`",
            sockets(name).join(" ")
        )
    }
}

fn listening(name: &str) -> bool {
    let sockets = sockets(name);
    let mut args = vec!["--user", "is-active"];
    args.extend(sockets.iter().map(String::as_str));
    // one line per unit; fails unless all are active
    super::run(SYSTEMCTL, &args).is_ok()
}

// Returns whether the service waits for the agent that runs to stop.
pub fn install(
    service: &super::Service,
    agent_runs: bool,
) -> anyhow::Result<bool> {
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

    // an agent that runs while the sockets don't holds their paths
    let waits = agent_runs && !listening(name);
    systemctl(&["--user", "daemon-reload"])?;
    let sockets = sockets(name);
    let mut args = vec!["--user", "enable"];
    if !waits {
        args.push("--now");
    }
    args.extend(sockets.iter().map(String::as_str));
    systemctl(&args)?;
    Ok(waits)
}

// Starts the sockets that waited for an agent, once it has stopped.
pub fn activate(name: &str) -> anyhow::Result<()> {
    let sockets = sockets(name);
    let mut args = vec!["--user", "start"];
    args.extend(sockets.iter().map(String::as_str));
    systemctl(&args)
}

pub fn next_steps(socket: &std::path::Path) -> Vec<super::Step> {
    let mut steps = vec![];
    if std::env::var_os("SSH_AUTH_SOCK").as_deref()
        != Some(socket.as_os_str())
    {
        steps.push(super::Step {
            text:
                "Log out and back in, so that your desktop session uses it."
                    .to_string(),
            command: None,
            note: None,
        });
    }
    steps.extend(shell_profile_step());
    steps
}

// environment.d doesn't reach SSH and console logins, but the shell's
// startup file does.
fn shell_profile_step() -> Option<super::Step> {
    let Some((file, line)) = shell_profile() else {
        return Some(super::Step {
            text:
                "For SSH and console logins, also add this to your shell's \
                startup file:"
                    .to_string(),
            command: Some(EXPORT.to_string()),
            note: None,
        });
    };
    if profile_sets_socket(file) {
        return None;
    }
    Some(super::Step {
        text: "For SSH and console logins, also paste this:".to_string(),
        command: Some(format!(
            "echo {} >> ~/{file}",
            super::shell_quote(line)
        )),
        note: None,
    })
}

const EXPORT: &str = "export SSH_AUTH_SOCK=\"$(rbw ssh-agent socket)\"";

// The startup file of the user's shell, in the home folder, and the line
// that sets SSH_AUTH_SOCK there.
fn shell_profile() -> Option<(&'static str, &'static str)> {
    let shell = std::env::var_os("SHELL")?;
    match std::path::Path::new(&shell).file_name()?.to_str()? {
        "bash" => Some((".bashrc", EXPORT)),
        "zsh" => Some((".zshrc", EXPORT)),
        "fish" => Some((
            ".config/fish/config.fish",
            "set -gx SSH_AUTH_SOCK (rbw ssh-agent socket)",
        )),
        _ => None,
    }
}

fn profile_sets_socket(file: &str) -> bool {
    super::home_dir().is_some_and(|home| {
        std::fs::read_to_string(home.join(file))
            .is_ok_and(|text| text.contains("rbw ssh-agent socket"))
    })
}

pub fn uninstall(name: &str) -> anyhow::Result<bool> {
    if !installed(name) {
        return Ok(false);
    }
    // an agent that runs keeps going, with the sockets, until it stops; its
    // unit goes away then
    let sockets = sockets(name);
    let mut args = vec!["--user", "disable", "--now"];
    args.extend(sockets.iter().map(String::as_str));
    systemctl(&args)?;

    let dir = unit_dir()?;
    for unit in units(name) {
        super::remove_file(&dir.join(unit))?;
    }
    super::remove_file(&environment_file(name)?)?;
    systemctl(&["--user", "daemon-reload"])?;
    Ok(true)
}

pub fn uninstall_notes() -> Vec<String> {
    let mut notes = vec![
        "Log out and back in so that SSH_AUTH_SOCK goes back to what it was."
            .to_string(),
    ];
    if let Some((file, _)) =
        shell_profile().filter(|(file, _)| profile_sets_socket(file))
    {
        notes.push(format!(
            "Remove the `rbw ssh-agent socket` line from ~/{file}."
        ));
    }
    notes
}

pub fn log(name: &str) -> String {
    format!("`journalctl --user -u {}`", service_unit(name))
}

pub fn start(name: &str) -> anyhow::Result<()> {
    // also starts the sockets, which the service wants
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

fn sockets(name: &str) -> [String; 2] {
    [control_socket_unit(name), ssh_socket_unit(name)]
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
Wants={control} {ssh}
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
RemoveOnStop=no
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
        assert!(
            unit.contains("\nWants=rbw-agent.socket rbw-agent-ssh.socket\n")
        );
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
        assert!(unit.contains("\nRemoveOnStop=no\n"));
        assert!(unit.contains("\nFileDescriptorName=ssh\n"));
        assert!(unit.contains("\nService=rbw-agent.service\n"));
    }
}
