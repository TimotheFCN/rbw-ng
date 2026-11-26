use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlocked() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = sock.recv()?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error, code } => {
                    Err(agent_error(error, code))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                anyhow::bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request::new(
                get_environment(),
                rbw::protocol::Action::Quit,
            ))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

// decrypt a batch of cipherstrings with a single agent round trip; each
// item succeeds or fails individually
pub fn decrypt_many(
    items: Vec<rbw::protocol::DecryptItem>,
) -> anyhow::Result<Vec<Result<String, rbw::protocol::DecryptError>>> {
    if items.is_empty() {
        return Ok(vec![]);
    }

    let req = rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::DecryptMany { items },
    );
    let mut sock = connect()?;
    sock.send(&req)?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::DecryptMany { plaintexts } => Ok(plaintexts
            .into_iter()
            .map(|plaintext| plaintext.map(into_string))
            .collect()),
        rbw::protocol::Response::Error { error, .. }
            if error.contains("unknown variant `DecryptMany`") =>
        {
            // an agent from before batch decryption with the same protocol
            // version (a development build, for example) can't parse the
            // request. its error quotes the whole request, so don't show it,
            // and decrypt one value per request like that agent expects.
            log::debug!("agent does not support DecryptMany, falling back");
            let (rbw::protocol::Action::DecryptMany { items }, _) =
                req.into_parts()
            else {
                unreachable!()
            };
            items.iter().map(decrypt_one).collect()
        }
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code).context("failed to decrypt"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// decrypt a single cipherstring. connection and protocol problems are
// returned as errors, and a decryption failure reported by the agent as the
// inner Err, matching one item of decrypt_many.
fn decrypt_one(
    item: &rbw::protocol::DecryptItem,
) -> anyhow::Result<Result<String, rbw::protocol::DecryptError>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Decrypt {
            cipherstring: item.cipherstring.clone(),
            entry_key: item.entry_key.clone(),
            org_id: item.org_id.clone(),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => {
            Ok(Ok(into_string(plaintext)))
        }
        rbw::protocol::Response::Error { error, code } => {
            Ok(Err(rbw::protocol::DecryptError { error, code }))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// The plaintexts go into what rbw prints, so it takes the strings without
// a copy.
fn into_string(mut secret: rbw::protocol::Secret) -> String {
    std::mem::take(&mut *secret)
}

pub fn encrypt(
    plaintext: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string().into(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code).context("failed to encrypt"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string().into(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Version,
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code).context("failed to get version"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn login_with(
    password: rbw::protocol::Secret,
    code: Option<rbw::protocol::LoginCode>,
    session: bool,
) -> anyhow::Result<Option<rbw::protocol::Secret>> {
    session_action(rbw::protocol::Action::LoginWith {
        password,
        code,
        session,
    })
}

pub fn register_with(
    client_id: String,
    client_secret: rbw::protocol::Secret,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::RegisterWith {
        client_id,
        client_secret,
    })
}

pub fn unlock_with(
    password: rbw::protocol::Secret,
    session: bool,
) -> anyhow::Result<Option<rbw::protocol::Secret>> {
    session_action(rbw::protocol::Action::UnlockWith { password, session })
}

pub fn unlock_entry(
    id: String,
    password: Option<rbw::protocol::Secret>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::UnlockEntry { id, password })
}

pub fn reload_config() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ReloadConfig)
}

#[cfg(target_os = "macos")]
pub fn serve_service_socket() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ServeServiceSocket)
}

pub fn unlock_touch_id() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::UnlockTouchId)
}

// Whether the vault is unlocked, and whether Touch ID can unlock it.
pub fn status() -> anyhow::Result<(bool, bool)> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::new(
        get_environment(),
        rbw::protocol::Action::Status,
    ))?;
    match sock.recv()? {
        rbw::protocol::Response::Status { unlocked, touch_id } => {
            Ok((unlocked, touch_id))
        }
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code))
        }
        res => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn unlock_session(session: rbw::protocol::Secret) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::UnlockSession { session })
}

// An action that answers with a session key when it made one.
fn session_action(
    action: rbw::protocol::Action,
) -> anyhow::Result<Option<rbw::protocol::Secret>> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new(get_environment(), action))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(None),
        rbw::protocol::Response::Session { session } => Ok(Some(session)),
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::new(get_environment(), action))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error, code } => {
            Err(agent_error(error, code))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// An error the agent answered with, with its code.
fn agent_error(
    error: String,
    code: Option<rbw::protocol::ErrorCode>,
) -> anyhow::Error {
    rbw::error::coded(code.unwrap_or(rbw::protocol::ErrorCode::Other), error)
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().map_err(|e| {
        let log = rbw::dirs::agent_stderr_file();
        rbw::error::coded(
            rbw::protocol::ErrorCode::Agent,
            format!(
                "failed to connect to rbw-agent \
                (this often means that the agent failed to start; \
                check {} for agent logs): {e}",
                log.display()
            ),
        )
    })
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}
