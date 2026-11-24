// Commands for programs that drive rbw, such as a browser's password
// manager: status as JSON, logging in and unlocking with secrets on stdin
// or in the environment, and sessions. See docs/scripting.md.

use anyhow::Context as _;
use rbw::error::coded;
use rbw::protocol::ErrorCode;

// Set by a program that can't answer a prompt: rbw fails instead of
// opening pinentry.
const NONINTERACTIVE: &str = "RBW_NONINTERACTIVE";
// A session key from rbw unlock --session, which unlocks the vault again
// without the master password.
const SESSION: &str = "RBW_SESSION";
const CLIENT_ID: &str = "RBW_CLIENT_ID";
const CLIENT_SECRET: &str = "RBW_CLIENT_SECRET";

pub fn noninteractive() -> bool {
    std::env::var_os(NONINTERACTIVE)
        .is_some_and(|value| !value.is_empty() && value != "0")
}

fn env_secret(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

// The master password, from stdin: everything up to the end, without the
// final line break.
fn password_from_stdin() -> anyhow::Result<String> {
    let mut password = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut password)
        .context("failed to read the master password from stdin")?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err(coded(
            ErrorCode::InvalidInput,
            "no master password on stdin",
        ));
    }
    Ok(password)
}

fn logged_in() -> bool {
    crate::commands::load_db().is_ok_and(|db| !db.needs_login())
}

// The unlock before a command, for a program: with RBW_SESSION, unlock with
// the session; with RBW_NONINTERACTIVE, fail instead of asking. Returns
// false when neither is set, for the usual unlock.
pub fn unlock_for_program() -> anyhow::Result<bool> {
    let session = env_secret(SESSION);
    if session.is_none() && !noninteractive() {
        return Ok(false);
    }
    if !logged_in() {
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    }
    if crate::actions::unlocked().is_ok() {
        return Ok(true);
    }
    match session {
        Some(session) => crate::actions::unlock_session(session)?,
        None => {
            return Err(coded(ErrorCode::Locked, "the vault is locked"));
        }
    }
    Ok(true)
}

fn print_session(session: Option<String>) {
    if let Some(session) = session {
        println!("{session}");
    }
}

pub fn login(
    password_stdin: bool,
    method: Option<u8>,
    code: Option<String>,
    session: bool,
) -> anyhow::Result<()> {
    if !password_stdin {
        if method.is_some() || code.is_some() || session {
            anyhow::bail!(
                "--method, --code and --session need --password-stdin"
            );
        }
        crate::commands::login()?;
        return Ok(());
    }
    if method.is_some() && code.is_none() {
        anyhow::bail!("--method needs --code");
    }
    let password = password_from_stdin()?;
    crate::commands::ensure_agent()?;
    let code = code.map(|code| rbw::protocol::LoginCode { method, code });
    print_session(crate::actions::login_with(password, code, session)?);
    Ok(())
}

pub fn register(api_key_env: bool) -> anyhow::Result<()> {
    if !api_key_env {
        return crate::commands::register();
    }
    let (Some(client_id), Some(client_secret)) =
        (env_secret(CLIENT_ID), env_secret(CLIENT_SECRET))
    else {
        anyhow::bail!("--api-key-env needs {CLIENT_ID} and {CLIENT_SECRET}");
    };
    crate::commands::ensure_agent()?;
    crate::actions::register_with(client_id, client_secret)
}

pub fn unlock(password_stdin: bool, session: bool) -> anyhow::Result<()> {
    if !password_stdin {
        if session {
            anyhow::bail!("--session needs --password-stdin");
        }
        return crate::commands::unlock();
    }
    let password = password_from_stdin()?;
    crate::commands::ensure_agent()?;
    if !logged_in() {
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    }
    print_session(crate::actions::unlock_with(password, session)?);
    Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    status: &'static str,
    // null for bitwarden.com
    server_url: Option<String>,
    user_email: Option<String>,
}

pub fn status(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load().unwrap_or_default();
    let status = if logged_in() {
        // not ensure_agent: a stopped agent means a locked vault
        let _ = crate::commands::check_agent_version();
        if crate::actions::unlocked().is_ok() {
            "unlocked"
        } else {
            "locked"
        }
    } else {
        "unauthenticated"
    };
    let status = Status {
        status,
        server_url: config.base_url,
        user_email: config.email,
    };
    if json {
        serde_json::to_writer(std::io::stdout(), &status)
            .context("failed to write the status")?;
        println!();
    } else {
        println!("{}", status.status);
    }
    Ok(())
}
