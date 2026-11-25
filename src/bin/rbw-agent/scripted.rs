// Logging in and unlocking with secrets that the caller passes, instead of
// asking through pinentry: for programs that drive rbw, such as a desktop
// app. See docs/scripting.md.

use anyhow::Context as _;
use rbw::error::coded;
use rbw::protocol::ErrorCode;

// The ways rbw can finish a two-step login, with Bitwarden's ids.
const TWO_STEP_METHODS: &[(rbw::api::TwoFactorProviderType, u8)] = &[
    (rbw::api::TwoFactorProviderType::Authenticator, 0),
    (rbw::api::TwoFactorProviderType::Email, 1),
    (rbw::api::TwoFactorProviderType::Yubikey, 3),
];

fn password(text: &str) -> rbw::locked::Password {
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(text.as_bytes().iter().copied());
    rbw::locked::Password::new(bytes)
}

async fn respond(
    sock: &mut crate::sock::Sock,
    session: Option<String>,
) -> anyhow::Result<()> {
    match session {
        Some(session) => {
            sock.send(&rbw::protocol::Response::Session { session })
                .await
        }
        None => sock.send(&rbw::protocol::Response::Ack).await,
    }
}

fn method_ids(methods: &[(rbw::api::TwoFactorProviderType, u8)]) -> String {
    methods
        .iter()
        .map(|(_, id)| id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub async fn login_with(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    typed_password: &str,
    code: Option<&rbw::protocol::LoginCode>,
    session: bool,
) -> anyhow::Result<()> {
    let db = crate::actions::load_db()
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());
    if !db.needs_login() {
        // like rbw login, logging in again only unlocks
        return unlock_with(sock, state, typed_password, session).await;
    }
    let email = crate::actions::config_email().await?;

    let method = match code.and_then(|code| code.method) {
        None => None,
        Some(id) => Some(
            TWO_STEP_METHODS
                .iter()
                .copied()
                .find(|(_, method_id)| *method_id == id)
                .map(|(method, _)| method)
                .ok_or_else(|| {
                    coded(
                        ErrorCode::InvalidInput,
                        format!(
                            "two-step login method {id} isn't supported; \
                             use one of {}",
                            method_ids(TWO_STEP_METHODS)
                        ),
                    )
                })?,
        ),
    };
    let token = code.map(|code| code.code.trim()).filter(|c| !c.is_empty());
    let login_code = match (method, token) {
        (Some(provider), Some(token)) => {
            Some(rbw::api::LoginCode::TwoFactor { provider, token })
        }
        (None, Some(token)) => Some(rbw::api::LoginCode::NewDevice(token)),
        _ => None,
    };

    let master_password = password(typed_password);
    match rbw::actions::login(&email, master_password.clone(), login_code)
        .await
    {
        Ok((
            access_token,
            refresh_token,
            kdf,
            iterations,
            memory,
            parallelism,
            protected_key,
        )) => {
            crate::actions::login_success(
                state.clone(),
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                master_password,
                db,
                email,
            )
            .await?;
            let session = new_session(&state, session).await?;
            respond(sock, session).await
        }
        Err(rbw::error::Error::TwoFactorRequired {
            providers,
            sso_email_2fa_session_token,
        }) => {
            if token.is_some() {
                return Err(coded(
                    ErrorCode::IncorrectCode,
                    "the two-step login code is incorrect",
                ));
            }
            let offered: Vec<_> = TWO_STEP_METHODS
                .iter()
                .copied()
                .filter(|(method, _)| providers.contains(method))
                .collect();
            if offered.is_empty() {
                return Err(coded(
                    ErrorCode::TwoStepUnsupported,
                    "none of this account's two-step login methods are \
                     supported",
                ));
            }
            if method == Some(rbw::api::TwoFactorProviderType::Email) {
                if let Some(token) = sso_email_2fa_session_token {
                    rbw::actions::send_two_factor_email(&email, &token)
                        .await?;
                }
                return Err(coded(
                    ErrorCode::TwoStepCodeSent,
                    "two-step login code required; Bitwarden emailed it",
                ));
            }
            Err(coded(
                ErrorCode::TwoStepRequired {
                    methods: offered.iter().map(|(_, id)| *id).collect(),
                },
                format!(
                    "two-step login code required; methods: {}",
                    method_ids(&offered)
                ),
            ))
        }
        Err(rbw::error::Error::NewDeviceVerificationRequired) => {
            if token.is_some() {
                return Err(coded(
                    ErrorCode::IncorrectCode,
                    "the new device verification code is incorrect; \
                     Bitwarden emailed a new one",
                ));
            }
            Err(coded(
                ErrorCode::NewDeviceCodeRequired,
                format!(
                    "new device verification code required; Bitwarden \
                     emailed it to {email}"
                ),
            ))
        }
        Err(rbw::error::Error::IncorrectPassword { message }) => {
            if token.is_some() {
                Err(coded(
                    ErrorCode::IncorrectCode,
                    format!(
                        "the two-step login code is incorrect: {message}"
                    ),
                ))
            } else {
                Err(coded(
                    ErrorCode::IncorrectPassword,
                    format!("incorrect master password: {message}"),
                ))
            }
        }
        Err(e) => Err(e).context("failed to log in to bitwarden instance"),
    }
}

pub async fn register_with(
    sock: &mut crate::sock::Sock,
    client_id: &str,
    client_secret: &str,
) -> anyhow::Result<()> {
    let db = crate::actions::load_db()
        .await
        .unwrap_or_else(|_| rbw::db::Db::new());
    if db.needs_login() {
        let email = crate::actions::config_email().await?;
        let apikey = rbw::locked::ApiKey::new(
            password(client_id),
            password(client_secret),
        );
        match rbw::actions::register(&email, apikey).await {
            Ok(()) => {}
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                return Err(coded(
                    ErrorCode::IncorrectPassword,
                    format!("incorrect api key: {message}"),
                ))
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }
    sock.send(&rbw::protocol::Response::Ack).await
}

// The account's unlock material, from the local copy of a logged in vault.
struct Account {
    email: String,
    db: rbw::db::Db,
}

async fn logged_in_account() -> anyhow::Result<Account> {
    let db = crate::actions::load_db()
        .await
        .ok()
        .filter(|db| !db.needs_login());
    let Some(db) = db else {
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    };
    let email = crate::actions::config_email().await?;
    Ok(Account { email, db })
}

pub async fn unlock_with(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    typed_password: &str,
    session: bool,
) -> anyhow::Result<()> {
    let account = logged_in_account().await?;
    let db = &account.db;
    let (Some(kdf), Some(iterations), Some(protected_key), Some(private_key)) = (
        db.kdf,
        db.iterations,
        db.protected_key.clone(),
        db.protected_private_key.clone(),
    ) else {
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    };
    let memory = db.memory;
    let parallelism = db.parallelism;
    let org_keys = db.protected_org_keys.clone();
    let email = account.email.clone();
    let master_password = password(typed_password);
    let derive_key = protected_key.clone();
    // the key derivation takes a moment, so keep it off the event loop
    let (keys, org_keys) = tokio::task::spawn_blocking(move || {
        rbw::actions::unlock(
            &email,
            &master_password,
            kdf,
            iterations,
            memory,
            parallelism,
            &derive_key,
            &private_key,
            &org_keys,
        )
    })
    .await
    .context("the password check stopped")?
    .map_err(|e| match e {
        rbw::error::Error::IncorrectPassword { .. } => {
            coded(ErrorCode::IncorrectPassword, "incorrect master password")
        }
        e => anyhow::Error::new(e).context("failed to unlock database"),
    })?;
    crate::actions::unlock_success(
        state.clone(),
        keys,
        org_keys,
        &protected_key,
    )
    .await?;
    let session = new_session(&state, session).await?;
    respond(sock, session).await
}

// After an unlock with the master password: a new session when the caller
// asked for one, replacing the earlier one.
async fn new_session(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    wanted: bool,
) -> anyhow::Result<Option<String>> {
    if !wanted {
        return Ok(None);
    }
    let db = crate::actions::load_db().await?;
    let protected_key = db
        .protected_key
        .ok_or_else(|| coded(ErrorCode::NotLoggedIn, "not logged in"))?;
    let (session_key, wrapped) = {
        let state = state.lock().await;
        let vault_key = state
            .key(None)
            .ok_or_else(|| coded(ErrorCode::Locked, "the vault is locked"))?;
        crate::session::wrap(vault_key, &protected_key)?
    };
    crate::session::save(&wrapped)?;
    Ok(Some(session_key))
}

pub async fn unlock_session(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    session_key: &str,
) -> anyhow::Result<()> {
    if !state.lock().await.needs_unlock() {
        return sock.send(&rbw::protocol::Response::Ack).await;
    }
    let account = logged_in_account().await?;
    let db = &account.db;
    let (Some(protected_key), Some(private_key)) = (
        db.protected_key.as_deref(),
        db.protected_private_key.as_deref(),
    ) else {
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    };
    let invalid =
        || coded(ErrorCode::SessionInvalid, "the session key is invalid");
    let Some(wrapped) = crate::session::load() else {
        return Err(invalid());
    };
    if !wrapped.is_for(protected_key) {
        // made before the master password changed: it can never work again
        crate::session::delete();
        return Err(invalid());
    }
    let vault_key =
        crate::session::unwrap(&wrapped, session_key, protected_key)
            .map_err(|_| invalid())?;
    let (keys, org_keys) = rbw::actions::unlock_with_key(
        vault_key,
        private_key,
        &db.protected_org_keys,
    )
    .map_err(|_| invalid())?;
    crate::actions::unlock_success(state, keys, org_keys, protected_key)
        .await?;
    sock.send(&rbw::protocol::Response::Ack).await
}

pub async fn forget_session(
    sock: &mut crate::sock::Sock,
) -> anyhow::Result<()> {
    crate::session::delete();
    sock.send(&rbw::protocol::Response::Ack).await
}
