// rbw ssh-agent: runs rbw-agent as a login service of the system's service
// manager (launchd on macOS, systemd on Linux). The manager holds the
// agent's sockets and starts the agent when a program connects. On Linux the
// login session's SSH_AUTH_SOCK points to it; on macOS, where Apple's agent
// keeps SSH_AUTH_SOCK, ~/.ssh/config does.
//
// Installing and uninstalling leave a running agent alone, so that the
// vault stays unlocked: its keys can't move to another process without
// being exposed on the way. Installed while an agent runs, the service
// waits until that agent stops, which rbw notices (activate), and the
// agent serves SSH where the service will meanwhile.

// elsewhere there is no service to write files for
#![cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]

use std::os::unix::fs::PermissionsExt as _;

use anyhow::Context as _;

#[cfg(target_os = "macos")]
#[path = "service/launchd.rs"]
mod platform;
#[cfg(target_os = "linux")]
#[path = "service/systemd.rs"]
mod platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[path = "service/unsupported.rs"]
mod platform;

// What the service runs.
pub struct Service {
    // The launchd label's last part, or the systemd units' base name.
    pub name: String,
    pub agent: std::path::PathBuf,
    // PATH for the agent, which looks up pinentry in it.
    pub path: std::ffi::OsString,
}

// Something the user should do after installing.
pub struct Step {
    pub text: String,
    // a command to paste, on a line of its own
    pub command: Option<String>,
    pub note: Option<String>,
}

// How long rbw waits for the service's agent to answer.
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn install() -> anyhow::Result<()> {
    platform::check_supported()?;
    let name = name()?;
    if let Some(other) = platform::other_installs(&name)?.first() {
        anyhow::bail!(
            "another rbw profile's service already serves SSH keys ({}), \
            and only one can; uninstall it first with \
            `RBW_PROFILE=<profile> rbw ssh-agent uninstall`",
            platform::describe(other)
        );
    }

    let path = search_path();
    let agent = agent_path(&path)?;
    check_pinentry(&path)?;

    let service = Service { name, agent, path };
    let waits = platform::install(&service, running_agent().is_some())?;

    println!(
        "rbw-agent is installed as a {} service: it starts whenever SSH or \
        rbw needs it.",
        platform::MANAGER
    );
    if waits {
        println!(
            "The agent that runs now keeps the vault as it is, and serves \
            SSH, until it stops; the service takes over then."
        );
    }
    print_steps(&platform::next_steps(&ssh_socket(&service.name)));
    println!();
    println!("Check the setup with: rbw ssh-agent status");
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    platform::check_supported()?;
    let name = name()?;
    if !platform::uninstall(&name)? {
        println!("rbw-agent is not installed as a service.");
        return Ok(());
    }
    println!(
        "rbw-agent is no longer a {} service: rbw starts it itself again.",
        platform::MANAGER
    );
    if running_agent().is_some() {
        println!(
            "The agent that runs now keeps the vault as it is until it stops."
        );
    }
    for line in platform::uninstall_notes() {
        println!("{line}");
    }
    Ok(())
}

// After rbw stopped the agent: starts the service, if it waited for that
// agent, so that SSH reaches it again without waiting for rbw to need the
// agent. The agent did stop either way.
pub fn activate() {
    if let Ok(name) = name() {
        if platform::installed(&name) {
            if let Err(e) = platform::activate(&name) {
                log::warn!(
                    "{e:#}; the service starts when rbw next needs the agent"
                );
            }
        }
    }
}

// For rbw purge --all: removes the service, if the profile has one.
pub fn uninstall_if_installed() -> anyhow::Result<()> {
    if let Ok(name) = name() {
        if platform::installed(&name) {
            platform::uninstall(&name)?;
        }
    }
    Ok(())
}

// rbw ssh-agent status --json, for programs that show the setup.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    // whether this system has a service manager rbw supports
    supported: bool,
    installed: bool,
    // the profiles whose service keeps this one from being installed; null
    // is the default profile
    other_profiles: Vec<Option<String>>,
    running: bool,
    // the socket that serves this profile's keys
    socket: std::path::PathBuf,
    // the agent ssh uses for a host without settings of its own
    ssh: SshStatus,
}

#[derive(serde::Serialize)]
struct SshStatus {
    // rbw, other, none or unknown
    agent: &'static str,
    socket: Option<std::path::PathBuf>,
}

pub fn status(json: bool) -> anyhow::Result<()> {
    if json {
        return status_json();
    }
    let name = name()?;
    let installed = platform::installed(&name);
    let service = if installed {
        format!("{} ({})", platform::describe(&name), platform::state(&name))
    } else {
        "not installed".to_string()
    };
    println!("service:       {service}");

    let agent = running_agent().map_or_else(
        || "not running".to_string(),
        |pid| format!("running (pid {pid})"),
    );
    println!("agent:         {agent}");

    let socket = ssh_socket(&name);
    println!("ssh socket:    {}", socket.display());
    let is_rbw = |path: &std::path::Path| {
        path == socket || path == rbw::dirs::ssh_agent_socket_file()
    };
    let agent_at = |path: &std::path::Path| {
        if is_rbw(path) {
            "rbw-agent".to_string()
        } else if path == rbw::dirs::service_ssh_agent_socket_file() {
            "nothing: rbw-agent's socket, but its service isn't installed"
                .to_string()
        } else {
            format!("another agent, at {}", path.display())
        }
    };
    let ssh = match ssh_default_agent() {
        Ok(SshAgent::Configured(path)) => {
            format!("{} (IdentityAgent in ~/.ssh/config)", agent_at(&path))
        }
        Ok(SshAgent::Variable { name, .. }) => std::env::var_os(&name)
            .map_or_else(
                || format!("no agent ({name} is not set)"),
                |path| {
                    format!(
                        "{} (through {name})",
                        agent_at(std::path::Path::new(&path))
                    )
                },
            ),
        Ok(SshAgent::Disabled) => "no agent (IdentityAgent none)".to_string(),
        Err(e) => format!("unknown: {e:#}"),
    };
    println!("ssh default:   {ssh}");

    let auth_sock = std::env::var_os("SSH_AUTH_SOCK").map_or_else(
        || "not set".to_string(),
        |value| {
            let value = std::path::PathBuf::from(value);
            let owner = if value == socket
                || value == rbw::dirs::ssh_agent_socket_file()
            {
                "rbw-agent"
            } else {
                "another agent"
            };
            format!("{} ({owner})", value.display())
        },
    );
    println!("SSH_AUTH_SOCK: {auth_sock}");
    Ok(())
}

fn status_json() -> anyhow::Result<()> {
    let name = name()?;
    let socket = ssh_socket(&name);
    let is_rbw = |path: &std::path::Path| {
        path == socket || path == rbw::dirs::ssh_agent_socket_file()
    };
    let at = |path: std::path::PathBuf| SshStatus {
        agent: if is_rbw(&path) { "rbw" } else { "other" },
        socket: Some(path),
    };
    let none = SshStatus {
        agent: "none",
        socket: None,
    };
    let ssh = match ssh_default_agent() {
        Ok(SshAgent::Configured(path)) => at(path),
        Ok(SshAgent::Variable { name, .. }) => {
            std::env::var_os(name).map_or(none, |path| at(path.into()))
        }
        Ok(SshAgent::Disabled) => none,
        Err(_) => SshStatus {
            agent: "unknown",
            socket: None,
        },
    };
    let status = Status {
        supported: platform::check_supported().is_ok(),
        installed: platform::installed(&name),
        other_profiles: platform::other_installs(&name)?
            .iter()
            .map(|other| profile_of(other))
            .collect(),
        running: running_agent().is_some(),
        socket,
        ssh,
    };
    serde_json::to_writer(std::io::stdout(), &status)
        .context("failed to write the status")?;
    println!();
    Ok(())
}

// The profile of a service name: rbw-<profile>-agent, or rbw-agent for
// the default profile.
fn profile_of(name: &str) -> Option<String> {
    name.strip_suffix("-agent")
        .and_then(|dir| dir.strip_prefix("rbw-"))
        .map(str::to_string)
}

pub fn socket() {
    let socket = name().map_or_else(
        |_| rbw::dirs::ssh_agent_socket_file(),
        |name| ssh_socket(&name),
    );
    println!("{}", socket.display());
}

fn print_steps(steps: &[Step]) {
    let numbered = steps.len() > 1;
    for (i, step) in steps.iter().enumerate() {
        // a step after a pasted command stands apart from it
        if i == 0
            || steps[i - 1].command.is_some()
            || steps[i - 1].note.is_some()
        {
            println!();
        }
        let indent = if numbered {
            if i == 0 {
                println!("Next:");
            }
            print!("  {}. ", i + 1);
            "     "
        } else {
            print!("Next: ");
            "  "
        };
        let mut text = step.text.chars();
        let first = text.next().map(|first| {
            if numbered {
                first
            } else {
                first.to_ascii_lowercase()
            }
        });
        println!("{}{}", first.unwrap_or_default(), text.as_str());
        if let Some(command) = &step.command {
            println!();
            println!("{indent}  {command}");
            if step.note.is_some() {
                println!();
            }
        }
        if let Some(note) = &step.note {
            println!("{indent}{note}");
        }
    }
}

// Quotes text for a POSIX shell (and fish).
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

// The SSH socket to point programs at: the service's when it has one of its
// own (launchd), or the agent's.
fn ssh_socket(name: &str) -> std::path::PathBuf {
    platform::installed(name)
        .then(|| platform::service_socket(name))
        .flatten()
        .unwrap_or_else(rbw::dirs::ssh_agent_socket_file)
}

fn home_dir() -> Option<std::path::PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

// A path as ~/... when it is in the home folder, as ssh_config accepts it.
#[cfg(target_os = "macos")]
fn tilde(path: &std::path::Path) -> String {
    home_dir()
        .and_then(|home| {
            path.strip_prefix(home)
                .ok()
                .map(|rest| rest.display().to_string())
        })
        .map_or_else(
            || path.display().to_string(),
            |rest| format!("~/{rest}"),
        )
}

// The agent SSH uses for a host without settings of its own.
// (macOS reads all of it, to tell how to point SSH at rbw-agent)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum SshAgent {
    // IdentityAgent with a socket path
    Configured(std::path::PathBuf),
    // the socket in an environment variable: SSH_AUTH_SOCK without an
    // IdentityAgent (explicit: false), or IdentityAgent SSH_AUTH_SOCK or
    // $NAME
    Variable { name: String, explicit: bool },
    // IdentityAgent none
    Disabled,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl SshAgent {
    fn describe(&self) -> String {
        match self {
            Self::Configured(path) => path.display().to_string(),
            Self::Variable { name, .. } => name.clone(),
            Self::Disabled => "none".to_string(),
        }
    }
}

// Asks ssh, without connecting, what it would use for a host that no Host or
// Match entry names, so that Include, Match and the order of the entries
// count as they do for ssh. Like every ssh run, this runs the commands of
// Match exec entries.
fn ssh_default_agent() -> anyhow::Result<SshAgent> {
    let output = std::process::Command::new("ssh")
        .args(["-G", "rbw-ssh-agent-check.invalid"])
        .stdin(std::process::Stdio::null())
        .output()
        .context("failed to run ssh")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ssh can't read its configuration: {}",
            stderr.lines().next().unwrap_or_default().trim()
        );
    }
    Ok(parse_ssh_agent(&String::from_utf8_lossy(&output.stdout)))
}

// From the "identityagent <value>" line of `ssh -G`, which has no such line
// without an IdentityAgent.
fn parse_ssh_agent(output: &str) -> SshAgent {
    let value = output
        .lines()
        .find_map(|line| line.strip_prefix("identityagent "));
    match value {
        None => SshAgent::Variable {
            name: "SSH_AUTH_SOCK".to_string(),
            explicit: false,
        },
        Some("none") => SshAgent::Disabled,
        Some("SSH_AUTH_SOCK") => SshAgent::Variable {
            name: "SSH_AUTH_SOCK".to_string(),
            explicit: true,
        },
        Some(value) if value.starts_with('$') => SshAgent::Variable {
            name: value
                .trim_start_matches('$')
                .trim_start_matches('{')
                .trim_end_matches('}')
                .to_string(),
            explicit: true,
        },
        Some(value) => SshAgent::Configured(value.into()),
    }
}

// Asks the service to start the agent and waits until it answers, when the
// service is installed. Returns false when it isn't, or can't start it, and
// rbw should start the agent itself.
pub fn start_agent() -> anyhow::Result<bool> {
    let Ok(name) = name() else {
        return Ok(false);
    };
    if !platform::installed(&name) {
        return Ok(false);
    }
    if let Err(e) = platform::start(&name) {
        log::warn!("{e:#}; starting rbw-agent without the service");
        return Ok(false);
    }

    let deadline = std::time::Instant::now() + START_TIMEOUT;
    loop {
        match crate::actions::version() {
            Ok(version) if version == rbw::protocol::VERSION => {
                return Ok(true);
            }
            Ok(version) => {
                let _ = crate::actions::quit();
                anyhow::bail!(
                    "the service runs an rbw-agent of another version \
                    ({version}, while rbw is {}); run `rbw ssh-agent \
                    install` again to point it at this one",
                    rbw::protocol::VERSION
                );
            }
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(e).context(format!(
                    "{} didn't start rbw-agent; its log is in {}",
                    platform::describe(&name),
                    platform::log(&name)
                ));
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

// The variables the service sets for the agent.
fn environment(
    service: &Service,
) -> anyhow::Result<Vec<(&'static str, String)>> {
    let path = std::path::PathBuf::from(&service.path);
    let mut environment = vec![("PATH", text(&path)?.to_string())];
    if let Ok(profile) = std::env::var("RBW_PROFILE") {
        if !profile.is_empty() {
            environment.push(("RBW_PROFILE", profile));
        }
    }
    Ok(environment)
}

// One service name per rbw profile, so each profile's files stay apart.
fn name() -> anyhow::Result<String> {
    let name = format!("{}-agent", rbw::dirs::profile());
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        anyhow::bail!(
            "to run as a service, RBW_PROFILE may only hold letters, digits, \
            '-', '_' and '.'"
        );
    }
    Ok(name)
}

// The PATH the agent gets: this shell's, so it finds the same programs as
// when rbw starts it, without relative entries, which would depend on the
// folder the service manager starts it in.
fn search_path() -> std::ffi::OsString {
    let mut dirs: Vec<std::path::PathBuf> = vec![];
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.is_absolute() && !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    std::env::join_paths(dirs)
        .ok()
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into())
}

// The rbw-agent that rbw would start: RBW_AGENT, or the one in PATH. The
// path is kept as found, not resolved: package managers point a stable
// path at each new version.
fn agent_path(path: &std::ffi::OsStr) -> anyhow::Result<std::path::PathBuf> {
    let agent = std::env::var_os("RBW_AGENT")
        .map_or_else(|| "rbw-agent".into(), std::path::PathBuf::from);
    let found = find_program(&agent, path).with_context(|| {
        format!("couldn't find {} in PATH", agent.display())
    })?;

    // rbw-agent from one install with rbw from another would disagree on
    // the protocol version
    let resolved = std::fs::canonicalize(&found).ok();
    let beside_rbw = std::env::current_exe()
        .ok()
        .and_then(|exe| std::fs::canonicalize(exe).ok())
        .and_then(|exe| Some(exe.parent()?.join("rbw-agent")));
    if let (Some(resolved), Some(beside_rbw)) = (resolved, beside_rbw) {
        if beside_rbw.exists() && resolved != beside_rbw {
            eprintln!(
                "warning: the service will run {}, not {} which comes with \
                this rbw",
                found.display(),
                beside_rbw.display()
            );
        }
    }
    Ok(found)
}

fn find_program(
    program: &std::path::Path,
    path: &std::ffi::OsStr,
) -> Option<std::path::PathBuf> {
    if program.components().count() > 1 {
        return std::path::absolute(program)
            .ok()
            .filter(|program| is_executable(program));
    }
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

// The agent asks for the master password through pinentry, also when an
// SSH request finds the vault locked, with no terminal to prompt in.
fn check_pinentry(path: &std::ffi::OsStr) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let pinentry = std::path::Path::new(&config.pinentry);
    if find_program(pinentry, path).is_none() {
        eprintln!(
            "warning: the agent won't find the pinentry program '{}'; set \
            it with `rbw config set pinentry <program>`",
            pinentry.display()
        );
    }
    if let Some(note) = platform::pinentry_note(pinentry) {
        eprintln!("note: {note}");
    }
    Ok(())
}

// The pid of the agent that holds the pid file lock, if one runs.
fn running_agent() -> Option<u32> {
    let pidfile = std::fs::File::open(rbw::dirs::pid_file()).ok()?;
    match rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockShared,
    ) {
        Err(rustix::io::Errno::WOULDBLOCK) => {
            let pid = std::fs::read_to_string(rbw::dirs::pid_file()).ok()?;
            pid.trim().parse().ok()
        }
        // no agent holds it; the lock goes with the file
        _ => None,
    }
}

// Writes a file in one step, so the service manager never reads half of it.
fn write_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    let dir = path.parent().context("no parent folder")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to write {}", path.display()))?;
    std::io::Write::write_all(&mut file, contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.persist(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn remove_file(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e)
            .with_context(|| format!("failed to remove {}", path.display())),
        _ => Ok(()),
    }
}

// Text that goes into a service file, which must stay on one line and be
// valid UTF-8.
fn text(path: &std::path::Path) -> anyhow::Result<&str> {
    let text = path
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
    if text.chars().any(char::is_control) {
        anyhow::bail!("{} holds control characters", path.display());
    }
    Ok(text)
}

// Runs a service manager command, with its error output in the error.
fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn profiles_of_service_names() {
        assert_eq!(super::profile_of("rbw-agent"), None);
        assert_eq!(
            super::profile_of("rbw-work-agent").as_deref(),
            Some("work")
        );
    }

    #[test]
    fn shell_quoting_survives_quotes() {
        assert_eq!(super::shell_quote("a b"), "'a b'");
        assert_eq!(super::shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn ssh_agent_settings_are_read() {
        use super::{parse_ssh_agent, SshAgent};

        let output = "user me\nidentityagent /Users/me/a b/s\nport 22\n";
        assert!(matches!(
            parse_ssh_agent(output),
            SshAgent::Configured(path) if path == std::path::Path::new("/Users/me/a b/s")
        ));
        assert!(matches!(
            parse_ssh_agent("user me\n"),
            SshAgent::Variable { name, explicit: false } if name == "SSH_AUTH_SOCK"
        ));
        assert!(matches!(
            parse_ssh_agent("identityagent SSH_AUTH_SOCK\n"),
            SshAgent::Variable { name, explicit: true } if name == "SSH_AUTH_SOCK"
        ));
        assert!(matches!(
            parse_ssh_agent("identityagent ${MY_SOCK}\n"),
            SshAgent::Variable { name, explicit: true } if name == "MY_SOCK"
        ));
        assert!(matches!(
            parse_ssh_agent("identityagent none\n"),
            SshAgent::Disabled
        ));
    }

    #[test]
    fn service_text_is_one_line() {
        assert!(super::text(std::path::Path::new("/a\nb")).is_err());
        assert_eq!(
            super::text(std::path::Path::new("/a b")).unwrap(),
            "/a b"
        );
    }
}
