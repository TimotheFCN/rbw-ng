// Commands for programs that drive rbw, such as a desktop app: status as
// JSON, logging in and unlocking with secrets on stdin or in the
// environment, and sessions. See docs/scripting.md.

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
// The code of rbw login --code-env, which an argument would show to every
// user in the process list.
const CODE: &str = "RBW_CODE";

pub fn noninteractive() -> bool {
    std::env::var_os(NONINTERACTIVE)
        .is_some_and(|value| !value.is_empty() && value != "0")
}

fn env_secret(name: &str) -> Option<rbw::protocol::Secret> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(Into::into)
}

// The master password, from stdin: everything up to the end, without the
// final line break.
pub fn password_from_stdin() -> anyhow::Result<rbw::protocol::Secret> {
    // room for any password, so that the buffer doesn't grow and leave
    // copies behind
    let mut password =
        rbw::protocol::Secret::new(String::with_capacity(1024));
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

// What the db says of the login, without reading its entries: this runs
// before every command of a program, and for each status poll.
fn logged_in_db(config: &rbw::config::Config) -> Option<rbw::db::DbMeta> {
    let email = config.email.as_deref()?;
    rbw::db::Db::load_meta(&config.server_name(), email)
        .ok()
        .filter(|db| !db.needs_login())
}

fn logged_in() -> bool {
    rbw::config::Config::load()
        .ok()
        .and_then(|config| logged_in_db(&config))
        .is_some()
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

fn print_session(session: Option<rbw::protocol::Secret>) {
    if let Some(session) = session {
        println!("{}", session.as_str());
    }
}

pub fn login(
    password_stdin: bool,
    method: Option<u8>,
    code: Option<String>,
    code_env: bool,
    session: bool,
) -> anyhow::Result<()> {
    if !password_stdin {
        if method.is_some() || code.is_some() || code_env || session {
            anyhow::bail!(
                "--method, --code, --code-env and --session need \
                 --password-stdin"
            );
        }
        crate::commands::login()?;
        return Ok(());
    }
    let code = if code_env {
        // empty asks the server to email a code, as --code "" does
        Some(
            std::env::var(CODE)
                .map_err(|_| anyhow::anyhow!("--code-env needs {CODE}"))?,
        )
    } else {
        code
    };
    if method.is_some() && code.is_none() {
        anyhow::bail!("--method needs --code or --code-env");
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
    crate::actions::register_with(client_id.to_string(), client_secret)
}

pub fn unlock(
    password_stdin: bool,
    session: bool,
    touch_id: bool,
) -> anyhow::Result<()> {
    if touch_id {
        if password_stdin || session {
            anyhow::bail!(
                "--touch-id can't go with --password-stdin or --session"
            );
        }
        crate::commands::ensure_agent()?;
        if !logged_in() {
            return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
        }
        return crate::actions::unlock_touch_id();
    }
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
    last_sync: Option<String>,
    touch_id: bool,
}

// What rbw status says of a vault, which rbw profiles --status says of each
// profile's: whether it is logged in and unlocked, when it last synced, and
// whether Touch ID can unlock it.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    status: &'static str,
    last_sync: Option<String>,
    touch_id: bool,
}

// From the db of a logged in account, if it is, and from its agent if that
// is: whether the vault is unlocked, and whether Touch ID can unlock it. A
// stopped agent means a locked vault.
fn vault_status(
    db: Option<rbw::db::DbMeta>,
    agent_status: impl FnOnce() -> anyhow::Result<(bool, bool)>,
) -> VaultStatus {
    let Some(db) = db else {
        return VaultStatus {
            status: "unauthenticated",
            last_sync: None,
            touch_id: false,
        };
    };
    let (status, touch_id) = match agent_status() {
        Ok((true, _)) => ("unlocked", false),
        Ok((false, touch_id)) => ("locked", touch_id),
        Err(_) => ("locked", false),
    };
    VaultStatus {
        status,
        last_sync: db.last_sync,
        touch_id,
    }
}

// The status of a profile that rbw profiles lists, with its configuration.
// Its agent isn't started, nor restarted when it is of another version.
pub fn profile_status(
    profile: Option<&str>,
    config: &rbw::config::Config,
) -> VaultStatus {
    let db = config
        .email
        .as_deref()
        .and_then(|email| {
            rbw::dirs::profile_db_file(profile, &config.server_name(), email)
                .ok()
        })
        .and_then(|file| rbw::db::DbMeta::load_from(file).ok())
        .filter(|db| !db.needs_login());
    vault_status(db, || {
        crate::actions::profile_status(&rbw::dirs::profile_socket_file(
            profile,
        )?)
    })
}

pub fn status(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load().unwrap_or_default();
    let vault = vault_status(logged_in_db(&config), || {
        // not ensure_agent: a stopped agent means a locked vault
        let _ = crate::commands::check_agent_version();
        crate::actions::status()
    });
    let status = Status {
        status: vault.status,
        server_url: config.base_url,
        user_email: config.email,
        last_sync: vault.last_sync,
        touch_id: vault.touch_id,
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

// A website's icon from the icon service of the profile's server, as the
// image the service sends. The official clients send it the host name of
// a login's website, never of a .onion or .i2p site.
pub fn icon(host: &str) -> anyhow::Result<()> {
    let host = icon_host(host)?;
    let Some(icon) = rbw::actions::icon(&host)? else {
        return Err(coded(
            ErrorCode::NotFound,
            format!("the server has no icon for {host}"),
        ));
    };
    std::io::Write::write_all(&mut std::io::stdout(), &icon)
        .context("failed to write the icon")
}

// The host name to send to the icon service, without the final dot that
// a fully qualified name may end with.
fn icon_host(host: &str) -> anyhow::Result<String> {
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');
    let valid = host.contains('.')
        && !host.starts_with('.')
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !valid {
        return Err(coded(
            ErrorCode::InvalidInput,
            format!("{host} isn't a host name"),
        ));
    }
    if matches!(host.rsplit('.').next(), Some("onion" | "i2p")) {
        return Err(coded(
            ErrorCode::InvalidInput,
            "the icons of .onion and .i2p sites aren't fetched",
        ));
    }
    Ok(host.to_string())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn vault_status_is_the_same_for_status_and_profiles() {
        let db = || {
            Some(rbw::db::DbMeta {
                last_sync: Some("2026-11-26T10:00:00Z".to_string()),
                ..rbw::db::DbMeta::default()
            })
        };
        let json =
            |status: VaultStatus| serde_json::to_string(&status).unwrap();

        assert_eq!(
            json(vault_status(None, || unreachable!())),
            r#"{"status":"unauthenticated","lastSync":null,"touchId":false}"#
        );
        assert_eq!(
            json(vault_status(db(), || Ok((true, true)))),
            r#"{"status":"unlocked","lastSync":"2026-11-26T10:00:00Z","touchId":false}"#
        );
        assert_eq!(
            json(vault_status(db(), || Ok((false, true)))),
            r#"{"status":"locked","lastSync":"2026-11-26T10:00:00Z","touchId":true}"#
        );
        // a stopped agent
        assert_eq!(
            json(vault_status(db(), || Err(anyhow::anyhow!("refused")))),
            r#"{"status":"locked","lastSync":"2026-11-26T10:00:00Z","touchId":false}"#
        );
    }

    #[test]
    fn icons_are_fetched_for_host_names_but_hidden_sites() {
        assert_eq!(icon_host("GitHub.com").unwrap(), "github.com");
        assert_eq!(icon_host("github.com.").unwrap(), "github.com");
        for refused in [
            "hidden.onion",
            "hidden.onion.",
            "site.i2p..",
            "localhost",
            ".com",
            "github.com/login",
            "",
            ".",
        ] {
            let error = icon_host(refused).unwrap_err();
            assert_eq!(rbw::error::code(&error), ErrorCode::InvalidInput);
        }
    }
}
