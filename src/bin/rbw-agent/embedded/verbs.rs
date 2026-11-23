// What the embedding application can ask the agent: docs/embedding.md ›
// Verbs.

use anyhow::Context as _;
use serde_json::{json, Value};
use sha2::Digest as _;

use super::hostkey;

type Shared<T> = std::sync::Arc<tokio::sync::Mutex<T>>;

// Writes messages to the host.
#[derive(Clone)]
pub struct Out {
    writer: super::transport::Writer,
}

impl Out {
    pub const fn new(writer: super::transport::Writer) -> Self {
        Self { writer }
    }

    pub fn send(&self, message: &Value) {
        self.writer.send(message);
    }
}

// Everything a verb needs.
#[derive(Clone)]
pub struct Ctx {
    pub state: Shared<crate::state::State>,
    pub out: Out,
    pub host: Shared<HostState>,
    // signing in, unlocking and writes wait for each other
    pub writes: Shared<()>,
}

// What the agent keeps for the host beyond the agent's own state.
#[derive(Default)]
pub struct HostState {
    pub synced_at: Option<u64>,
    // the vault key wrapped with a host key the host keeps in memory
    pub session_key: Option<hostkey::Wrapped>,
}

impl Ctx {
    pub fn event(&self, event: &str, data: &Value) {
        self.out.send(&super::framing::event(event, data, None));
    }

    fn state_event(&self, state: &str) {
        self.event("state", &json!({ "state": state }));
    }

    async fn is_unlocked(&self) -> bool {
        !self.state.lock().await.needs_unlock()
    }

    async fn synced(&self) {
        let now = now_ms();
        self.host.lock().await.synced_at = Some(now);
        self.event("changed", &json!({ "syncedAt": now }));
    }

    pub async fn sync(&self) -> Result<(), VaultError> {
        crate::actions::sync(None, self.state.clone()).await?;
        self.synced().await;
        Ok(())
    }

    // Locks the vault if its time ran out, and tells the host.
    pub async fn lock_if_expired(&self) {
        let mut state = self.state.lock().await;
        let was_unlocked = !state.needs_unlock();
        state.lock_if_expired();
        if was_unlocked && state.needs_unlock() {
            drop(state);
            self.state_event("locked");
        }
    }

    pub async fn lock(&self) {
        let mut state = self.state.lock().await;
        let was_unlocked = !state.needs_unlock();
        state.clear();
        drop(state);
        if was_unlocked {
            self.state_event("locked");
        }
    }
}

// An answer's error: a code from the table in docs/embedding.md, and a message
// for logs. Messages never carry a secret.
#[derive(Debug)]
pub struct VaultError {
    pub code: &'static str,
    pub message: String,
}

impl VaultError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    fn signed_out() -> Self {
        Self::new("signed_out", "Sign in to Bitwarden first.")
    }

    fn locked() -> Self {
        Self::new("locked", "The vault is locked.")
    }

    fn not_found() -> Self {
        Self::new("not_found", "There's no such login.")
    }

    pub fn to_json(&self) -> Value {
        json!({ "code": self.code, "message": self.message })
    }
}

impl From<anyhow::Error> for VaultError {
    fn from(e: anyhow::Error) -> Self {
        let too_many = e.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<rbw::error::Error>(),
                Some(rbw::error::Error::RequestFailed { status: 429 })
            )
        });
        if too_many {
            return Self::new(
                "server",
                "Bitwarden saw too many attempts. Wait a minute and try \
                 again.",
            );
        }
        let message = format!("{e:#}");
        let code = e
            .chain()
            .find_map(|cause| {
                cause.downcast_ref::<rbw::error::Error>().map(|e| match e {
                    rbw::error::Error::Reqwest { .. } => "offline",
                    rbw::error::Error::RequestFailed { .. }
                    | rbw::error::Error::RequestUnauthorized
                    | rbw::error::Error::RefreshTokenInvalid
                    | rbw::error::Error::DeviceRejected { .. } => "server",
                    rbw::error::Error::IncorrectPassword { .. } => {
                        "wrong_password"
                    }
                    rbw::error::Error::CipherOutOfDate => "conflict",
                    _ => "failed",
                })
            })
            .unwrap_or("failed");
        Self::new(code, message)
    }
}

impl From<rbw::error::Error> for VaultError {
    fn from(e: rbw::error::Error) -> Self {
        anyhow::Error::new(e).into()
    }
}

type Answer = Result<Value, VaultError>;

pub async fn dispatch(ctx: &Ctx, verb: &str, params: &Value) -> Answer {
    ctx.lock_if_expired().await;
    match verb {
        "status" => status(ctx).await,
        "signIn" => sign_in(ctx, params).await,
        "unlock" => unlock(ctx, params).await,
        "lock" => {
            ctx.lock().await;
            Ok(json!({ "ok": true }))
        }
        "signOut" => sign_out(ctx).await,
        "sync" => {
            ctx.sync().await?;
            Ok(json!({ "ok": true }))
        }
        "configure" => configure(ctx, params).await,
        "forgetHostKey" => forget_host_key(ctx, params).await,
        "items" => items(ctx).await,
        "match" => match_origin(ctx, params).await,
        "fill" => fill(ctx, params).await,
        "totp" => totp(ctx, params).await,
        "save" => save(ctx, params).await,
        "update" => update(ctx, params).await,
        "delete" => delete(ctx, params).await,
        "reveal" => reveal(ctx, params).await,
        "generate" => generate(params),
        _ => Err(VaultError::new(
            "unknown_verb",
            format!("Protocol 1 has no verb {verb:?}."),
        )),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| {
            u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
        })
}

fn string<'a>(params: &'a Value, name: &str) -> Option<&'a str> {
    params.get(name).and_then(Value::as_str)
}

fn required<'a>(
    params: &'a Value,
    name: &str,
) -> Result<&'a str, VaultError> {
    string(params, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| VaultError::bad_request(format!("{name} is missing.")))
}

fn password(text: &str) -> rbw::locked::Password {
    let mut password = rbw::locked::Vec::new();
    password.extend(text.bytes());
    rbw::locked::Password::new(password)
}

// The base_url setting for the server the host names: none for
// bitwarden.com.
fn base_url_for(server: &str) -> Result<Option<String>, VaultError> {
    let trimmed = server.trim().trim_end_matches('/');
    match trimmed.to_ascii_lowercase().as_str() {
        ""
        | "us"
        | "bitwarden.com"
        | "https://bitwarden.com"
        | "https://vault.bitwarden.com" => return Ok(None),
        "eu"
        | "bitwarden.eu"
        | "https://bitwarden.eu"
        | "https://vault.bitwarden.eu" => {
            return Ok(Some("https://api.bitwarden.eu".to_string()))
        }
        _ => {}
    }
    let url = url::Url::parse(trimmed).map_err(|_| {
        VaultError::bad_request("Enter the server as an https address.")
    })?;
    let local =
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(VaultError::bad_request(
            "Enter the server as an https address.",
        ));
    }
    Ok(Some(trimmed.to_string()))
}

// The page address a fill is for. Only secure pages get secrets.
fn origin(params: &Value) -> Result<url::Url, VaultError> {
    let origin = required(params, "origin")?;
    let url = url::Url::parse(origin)
        .map_err(|_| VaultError::bad_request("origin isn't an address."))?;
    let local =
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() == "https" || (url.scheme() == "http" && local) {
        Ok(url)
    } else {
        Err(VaultError::new(
            "origin_mismatch",
            "Logins are only filled on https pages.",
        ))
    }
}

async fn status(ctx: &Ctx) -> Answer {
    let config = rbw::config::Config::load_async().await.ok();
    let signed_in = crate::actions::load_db()
        .await
        .is_ok_and(|db| !db.needs_login());
    let state = if !signed_in {
        "signedOut"
    } else if ctx.state.lock().await.needs_unlock() {
        "locked"
    } else {
        "unlocked"
    };
    let host = ctx.host.lock().await;
    let host_key = if host.session_key.is_some() {
        Some("session")
    } else if hostkey::load_persistent().is_some() {
        Some("persistent")
    } else {
        None
    };
    Ok(json!({
        "state": state,
        "account": config.as_ref().and_then(|c| c.email.clone()),
        "server": config.as_ref().map(rbw::config::Config::ui_url),
        "syncedAt": host.synced_at,
        "hostKey": host_key,
    }))
}

const TWO_FACTOR_METHODS: &[(rbw::api::TwoFactorProviderType, &str, &str)] =
    &[
        (
            rbw::api::TwoFactorProviderType::Authenticator,
            "0",
            "Authenticator app",
        ),
        (rbw::api::TwoFactorProviderType::Email, "1", "Email"),
        (rbw::api::TwoFactorProviderType::Yubikey, "3", "YubiKey OTP"),
    ];

fn method_json(
    methods: &[(rbw::api::TwoFactorProviderType, &str, &str)],
) -> Value {
    Value::Array(
        methods
            .iter()
            .map(|(_, id, name)| json!({ "id": id, "name": name }))
            .collect(),
    )
}

async fn sign_in(ctx: &Ctx, params: &Value) -> Answer {
    let writes = ctx.writes.lock().await;

    let email = required(params, "email")?;
    if !email.contains('@')
        || email.starts_with('-')
        || email.chars().any(char::is_whitespace)
        || email.len() > 320
    {
        return Err(VaultError::bad_request("That isn't an email address."));
    }
    let typed_password = required(params, "password")?;
    let base_url = base_url_for(string(params, "server").unwrap_or(""))?;
    let method = match string(params, "method") {
        None => None,
        Some(id) => Some(
            TWO_FACTOR_METHODS
                .iter()
                .find(|(_, method_id, _)| *method_id == id)
                .map(|(provider, _, _)| *provider)
                .ok_or_else(|| {
                    VaultError::bad_request(
                        "Choose a two-step login method from the list.",
                    )
                })?,
        ),
    };
    let code = string(params, "code").filter(|code| !code.is_empty());
    if let Some(code) = code {
        if code.len() > 64 || !code.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(VaultError::new(
                "wrong_code",
                "That code doesn't look right.",
            ));
        }
    }
    let wrap = wrap_kind(params)?;

    let mut config =
        rbw::config::Config::load_async().await.unwrap_or_default();
    if let Ok(db) = crate::actions::load_db().await {
        if !db.needs_login() {
            if config.email.as_deref() == Some(email)
                && config.base_url == base_url
            {
                drop(writes);
                return unlock_with_password(ctx, typed_password, wrap).await;
            }
            return Err(VaultError::bad_request(
                "Sign out of the current account first.",
            ));
        }
    }
    config.email = Some(email.to_string());
    config.base_url = base_url;
    config.identity_url = None;
    config.ui_url = None;
    config.notifications_url = None;
    config
        .save()
        .context("failed to save the account settings")?;

    let login_code = match (method, code) {
        (Some(provider), Some(token)) => {
            Some(rbw::api::LoginCode::TwoFactor { provider, token })
        }
        (None, Some(token)) => Some(rbw::api::LoginCode::NewDevice(token)),
        _ => None,
    };
    let master_password = password(typed_password);
    match rbw::actions::login(email, master_password.clone(), login_code)
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
            let db = crate::actions::load_db()
                .await
                .unwrap_or_else(|_| rbw::db::Db::new());
            crate::actions::login_success(
                ctx.state.clone(),
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                master_password,
                db,
                email.to_string(),
            )
            .await?;
            ctx.synced().await;
            let host_key = wrap_after_unlock(ctx, wrap).await?;
            ctx.state_event("unlocked");
            Ok(json!({ "state": "unlocked", "hostKey": host_key }))
        }
        Err(rbw::error::Error::TwoFactorRequired {
            providers,
            sso_email_2fa_session_token,
        }) => {
            if method.is_some() && code.is_some() {
                return Err(VaultError::new(
                    "wrong_code",
                    "That code didn't work. Try a new one.",
                ));
            }
            let offered: Vec<_> = TWO_FACTOR_METHODS
                .iter()
                .filter(|(provider, _, _)| providers.contains(provider))
                .copied()
                .collect();
            if offered.is_empty() {
                return Err(VaultError::new(
                    "failed",
                    "This account's two-step login methods aren't \
                     supported. Add an authenticator app, email or a \
                     YubiKey to it.",
                ));
            }
            if method == Some(rbw::api::TwoFactorProviderType::Email) {
                if let Some(token) = sso_email_2fa_session_token {
                    rbw::actions::send_two_factor_email(email, &token)
                        .await?;
                }
                let email_only: Vec<_> = offered
                    .iter()
                    .filter(|(provider, _, _)| {
                        *provider == rbw::api::TwoFactorProviderType::Email
                    })
                    .copied()
                    .collect();
                return Ok(json!({
                    "needs": "code",
                    "methods": method_json(&email_only),
                }));
            }
            Ok(json!({ "needs": "code", "methods": method_json(&offered) }))
        }
        Err(rbw::error::Error::NewDeviceVerificationRequired) => {
            if code.is_some() {
                return Err(VaultError::new(
                    "wrong_code",
                    "That code didn't work. Bitwarden emailed a new one.",
                ));
            }
            Ok(json!({ "needs": "newDeviceCode", "email": email }))
        }
        Err(rbw::error::Error::IncorrectPassword { message }) => {
            if code.is_some() {
                Err(VaultError::new("wrong_code", message))
            } else {
                Err(VaultError::new("wrong_password", message))
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn wrap_kind(params: &Value) -> Result<Option<hostkey::Kind>, VaultError> {
    match params.get("wrapKey") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(kind)) => {
            hostkey::Kind::parse(kind).map(Some).ok_or_else(|| {
                VaultError::bad_request(
                    "wrapKey is session, persistent or null.",
                )
            })
        }
        Some(_) => Err(VaultError::bad_request(
            "wrapKey is session, persistent or null.",
        )),
    }
}

// After an unlock with the master password: a new host key of the kind
// the host asked for, replacing the earlier one of that kind.
async fn wrap_after_unlock(
    ctx: &Ctx,
    kind: Option<hostkey::Kind>,
) -> Result<Option<String>, VaultError> {
    let Some(kind) = kind else {
        return Ok(None);
    };
    let db = crate::actions::load_db().await?;
    let protected_key = db.protected_key.ok_or_else(|| {
        VaultError::new("failed", "The account has no key.")
    })?;
    let (host_key, wrapped) = {
        let state = ctx.state.lock().await;
        let vault_key = state.key(None).ok_or_else(VaultError::locked)?;
        hostkey::wrap(vault_key, &protected_key, kind)?
    };
    match kind {
        hostkey::Kind::Session => {
            ctx.host.lock().await.session_key = Some(wrapped);
        }
        hostkey::Kind::Persistent => hostkey::save_persistent(&wrapped)?,
    }
    Ok(Some(host_key))
}

async fn unlock(ctx: &Ctx, params: &Value) -> Answer {
    let wrap = wrap_kind(params)?;
    if let Some(host_key) = string(params, "hostKey") {
        let _writes = ctx.writes.lock().await;
        return unlock_with_host_key(ctx, host_key).await;
    }
    let typed_password = required(params, "password")?;
    unlock_with_password(ctx, typed_password, wrap).await
}

// The account's unlock material, from a signed in db.
struct Account {
    email: String,
    db: rbw::db::Db,
}

async fn signed_in_account() -> Result<Account, VaultError> {
    let db = crate::actions::load_db()
        .await
        .map_err(|_| VaultError::signed_out())?;
    if db.needs_login() {
        return Err(VaultError::signed_out());
    }
    let email = crate::actions::config_email()
        .await
        .map_err(|_| VaultError::signed_out())?;
    Ok(Account { email, db })
}

// Checks a master password without changing the agent's state.
async fn check_password(
    account: &Account,
    typed_password: &str,
) -> Result<
    (
        rbw::locked::Keys,
        std::collections::HashMap<String, rbw::locked::Keys>,
    ),
    VaultError,
> {
    let db = &account.db;
    let (Some(kdf), Some(iterations), Some(protected_key), Some(private_key)) = (
        db.kdf,
        db.iterations,
        db.protected_key.clone(),
        db.protected_private_key.clone(),
    ) else {
        return Err(VaultError::signed_out());
    };
    let memory = db.memory;
    let parallelism = db.parallelism;
    let org_keys = db.protected_org_keys.clone();
    let email = account.email.clone();
    let master_password = password(typed_password);
    // the key derivation takes a moment, so keep it off the event loop
    tokio::task::spawn_blocking(move || {
        rbw::actions::unlock(
            &email,
            &master_password,
            kdf,
            iterations,
            memory,
            parallelism,
            &protected_key,
            &private_key,
            &org_keys,
        )
    })
    .await
    .context("the password check stopped")?
    .map_err(|e| match e {
        rbw::error::Error::IncorrectPassword { .. } => VaultError::new(
            "wrong_password",
            "That master password isn't right.",
        ),
        e => e.into(),
    })
}

async fn unlock_with_password(
    ctx: &Ctx,
    typed_password: &str,
    wrap: Option<hostkey::Kind>,
) -> Answer {
    let _writes = ctx.writes.lock().await;
    let account = signed_in_account().await?;
    let (keys, org_keys) = check_password(&account, typed_password).await?;
    let protected_key = account.db.protected_key.clone().unwrap_or_default();
    let was_unlocked = ctx.is_unlocked().await;
    crate::actions::unlock_success(
        ctx.state.clone(),
        keys,
        org_keys,
        &protected_key,
    )
    .await?;
    ctx.state.lock().await.set_timeout();
    let host_key = wrap_after_unlock(ctx, wrap).await?;
    if !was_unlocked {
        ctx.state_event("unlocked");
    }
    Ok(json!({ "state": "unlocked", "hostKey": host_key }))
}

async fn unlock_with_host_key(ctx: &Ctx, host_key: &str) -> Answer {
    let account = signed_in_account().await?;
    let db = &account.db;
    let (Some(protected_key), Some(private_key)) = (
        db.protected_key.as_deref(),
        db.protected_private_key.as_deref(),
    ) else {
        return Err(VaultError::signed_out());
    };

    let session = ctx.host.lock().await.session_key.clone();
    let persistent = hostkey::load_persistent();
    // a wrapped key made for an earlier account key can never open the
    // vault again
    if session.as_ref().is_some_and(|w| !w.is_for(protected_key)) {
        ctx.host.lock().await.session_key = None;
    }
    if persistent
        .as_ref()
        .is_some_and(|w| !w.is_for(protected_key))
    {
        hostkey::delete_persistent();
    }

    let vault_key = [session, persistent]
        .into_iter()
        .flatten()
        .filter(|wrapped| wrapped.is_for(protected_key))
        .find_map(|wrapped| {
            hostkey::unwrap(&wrapped, host_key, protected_key).ok()
        });
    let Some(vault_key) = vault_key else {
        return Err(VaultError::new(
            "wrong_password",
            "Touch ID can't unlock the vault now. Enter the master password.",
        ));
    };
    let (keys, org_keys) = rbw::actions::unlock_with_key(
        vault_key,
        private_key,
        &db.protected_org_keys,
    )
    .map_err(|_| {
        VaultError::new(
            "wrong_password",
            "Touch ID can't unlock the vault now. Enter the master password.",
        )
    })?;
    let was_unlocked = ctx.is_unlocked().await;
    crate::actions::unlock_success(
        ctx.state.clone(),
        keys,
        org_keys,
        protected_key,
    )
    .await?;
    ctx.state.lock().await.set_timeout();
    if !was_unlocked {
        ctx.state_event("unlocked");
    }
    Ok(json!({ "state": "unlocked" }))
}

async fn forget_host_key(ctx: &Ctx, params: &Value) -> Answer {
    let kind = wrap_kind(params)?;
    if kind != Some(hostkey::Kind::Persistent) {
        ctx.host.lock().await.session_key = None;
    }
    if kind != Some(hostkey::Kind::Session) {
        hostkey::delete_persistent();
    }
    Ok(json!({ "ok": true }))
}

async fn sign_out(ctx: &Ctx) -> Answer {
    let _writes = ctx.writes.lock().await;
    let was_signed_in = crate::actions::load_db()
        .await
        .is_ok_and(|db| !db.needs_login());
    {
        let mut state = ctx.state.lock().await;
        state.clear_all();
        if let Err(e) = state.notifications_handler.disconnect().await {
            log::warn!("failed to stop listening for changes: {e}");
        }
    }
    {
        let mut host = ctx.host.lock().await;
        host.session_key = None;
        host.synced_at = None;
    }
    hostkey::delete_persistent();
    if let Ok(mut config) = rbw::config::Config::load_async().await {
        if let Some(email) = config.email.take() {
            if let Err(e) = rbw::db::Db::remove(&config.server_name(), &email)
            {
                log::warn!("failed to delete the vault copy: {e}");
            }
        }
        config
            .save()
            .context("failed to save the account settings")?;
    }
    if was_signed_in {
        ctx.state_event("signedOut");
    }
    Ok(json!({ "ok": true }))
}

async fn configure(ctx: &Ctx, params: &Value) -> Answer {
    let Some(lock_timeout) = params.get("lockTimeout") else {
        return Ok(json!({ "ok": true }));
    };
    let seconds = lock_timeout
        .as_u64()
        .filter(|seconds| (60..=7 * 24 * 3600).contains(seconds))
        .ok_or_else(|| {
            VaultError::bad_request(
                "lockTimeout is a number of seconds, from 60 to a week.",
            )
        })?;
    let mut config =
        rbw::config::Config::load_async().await.unwrap_or_default();
    config.lock_timeout = seconds;
    config.save().context("failed to save the lock timeout")?;
    let mut state = ctx.state.lock().await;
    state.timeout_duration = std::time::Duration::from_secs(seconds);
    if !state.needs_unlock() {
        state.set_timeout();
    }
    Ok(json!({ "ok": true }))
}

// The unlocked vault: the db and the agent's keys.
async fn unlocked() -> Result<rbw::db::Db, VaultError> {
    let account = signed_in_account().await?;
    Ok(account.db)
}

// Decrypts the values of one entry with the agent's keys.
struct Opened<'a> {
    keys: &'a rbw::locked::Keys,
    entry_key: Option<rbw::locked::Keys>,
}

impl<'a> Opened<'a> {
    fn new(
        state: &'a crate::state::State,
        entry: &rbw::db::Entry,
    ) -> Result<Self, VaultError> {
        let keys = state
            .key(entry.org_id.as_deref())
            .ok_or_else(VaultError::locked)?;
        let entry_key = match &entry.key {
            Some(key) => Some(rbw::locked::Keys::new(
                rbw::cipherstring::CipherString::new(key)?
                    .decrypt_locked_symmetric(keys)?,
            )),
            None => None,
        };
        Ok(Self { keys, entry_key })
    }

    fn decrypt(&self, cipherstring: &str) -> Result<String, VaultError> {
        let plaintext =
            rbw::cipherstring::CipherString::new(cipherstring)?
                .decrypt_symmetric(self.keys, self.entry_key.as_ref())?;
        String::from_utf8(plaintext).map_err(|_| {
            VaultError::new("failed", "A value in the login isn't text.")
        })
    }

    fn decrypt_opt(
        &self,
        cipherstring: Option<&str>,
    ) -> Result<Option<String>, VaultError> {
        cipherstring.map(|s| self.decrypt(s)).transpose()
    }

    fn encrypt(&self, plaintext: &str) -> Result<String, VaultError> {
        Ok(rbw::cipherstring::CipherString::encrypt_symmetric(
            self.entry_key.as_ref().unwrap_or(self.keys),
            plaintext.as_bytes(),
        )?
        .to_string())
    }

    fn uris(
        &self,
        uris: &[rbw::db::Uri],
    ) -> Vec<(String, Option<rbw::api::UriMatchType>)> {
        uris.iter()
            .filter_map(|uri| {
                self.decrypt(&uri.uri)
                    .ok()
                    .map(|address| (address, uri.match_type))
            })
            .collect()
    }
}

fn is_login(entry: &rbw::db::Entry) -> bool {
    matches!(entry.data, rbw::db::EntryData::Login { .. }) && !entry.archived
}

fn match_json(match_type: Option<rbw::api::UriMatchType>) -> Value {
    let name = match match_type {
        None => return Value::Null,
        Some(rbw::api::UriMatchType::Domain) => "domain",
        Some(rbw::api::UriMatchType::Host) => "host",
        Some(rbw::api::UriMatchType::StartsWith) => "startsWith",
        Some(rbw::api::UriMatchType::Exact) => "exact",
        Some(rbw::api::UriMatchType::RegularExpression) => "regex",
        Some(rbw::api::UriMatchType::Never) => "never",
    };
    Value::String(name.to_string())
}

// Whether showing this entry's secrets needs the master password again. The
// agent trusts its own record from the last sync over the flag on disk.
fn needs_reprompt(
    state: &crate::state::State,
    entry: &rbw::db::Entry,
) -> bool {
    if entry.master_password_reprompt() {
        return true;
    }
    let rbw::db::EntryData::Login { password, totp, .. } = &entry.data else {
        return false;
    };
    [password, totp].into_iter().flatten().any(|cipherstring| {
        let mut sha256 = sha2::Sha256::new();
        sha256.update(cipherstring);
        let digest: [u8; 32] = sha256.finalize().into();
        state.master_password_reprompt.contains(&digest)
    })
}

fn item_json(
    state: &crate::state::State,
    entry: &rbw::db::Entry,
) -> Result<Value, VaultError> {
    let opened = Opened::new(state, entry)?;
    let rbw::db::EntryData::Login {
        username,
        totp,
        uris,
        ..
    } = &entry.data
    else {
        return Err(VaultError::not_found());
    };
    let uris: Vec<Value> = opened
        .uris(uris)
        .into_iter()
        .map(|(uri, match_type)| {
            json!({ "uri": uri, "match": match_json(match_type) })
        })
        .collect();
    Ok(json!({
        "id": entry.id,
        "title": opened.decrypt(&entry.name)?,
        "username": opened.decrypt_opt(username.as_deref())?.unwrap_or_default(),
        "uris": uris,
        "hasTotp": totp.is_some(),
        "hasNotes": entry.notes.is_some(),
        "organization": entry.org_id.is_some(),
        "favorite": entry.favorite,
        "reprompt": needs_reprompt(state, entry),
        "revision": entry.revision_date,
    }))
}

async fn reprompt_ready<'a>(
    ctx: &'a Ctx,
    db: &rbw::db::Db,
) -> tokio::sync::MutexGuard<'a, crate::state::State> {
    let mut state = ctx.state.lock().await;
    if !state.master_password_reprompt_initialized() {
        state.set_master_password_reprompt(&db.entries);
    }
    state
}

async fn items(ctx: &Ctx) -> Answer {
    let db = unlocked().await?;
    let state = reprompt_ready(ctx, &db).await;
    if state.needs_unlock() {
        return Err(VaultError::locked());
    }
    let mut items = vec![];
    for entry in db.entries.iter().filter(|entry| is_login(entry)) {
        match item_json(&state, entry) {
            Ok(item) => items.push(item),
            Err(e) => {
                log::warn!("leaving out login {}: {}", entry.id, e.message);
            }
        }
    }
    Ok(json!({ "items": items }))
}

fn matches_origin(
    opened: &Opened<'_>,
    entry: &rbw::db::Entry,
    origin: &url::Url,
) -> bool {
    let rbw::db::EntryData::Login { uris, .. } = &entry.data else {
        return false;
    };
    opened.uris(uris).iter().any(|(uri, match_type)| {
        rbw::uri_match::matches(uri, *match_type, origin)
    })
}

async fn match_origin(ctx: &Ctx, params: &Value) -> Answer {
    let origin = origin(params)?;
    let db = unlocked().await?;
    let state = ctx.state.lock().await;
    if state.needs_unlock() {
        return Err(VaultError::locked());
    }
    let ids: Vec<&str> = db
        .entries
        .iter()
        .filter(|entry| is_login(entry))
        .filter(|entry| {
            Opened::new(&state, entry)
                .is_ok_and(|opened| matches_origin(&opened, entry, &origin))
        })
        .map(|entry| entry.id.as_str())
        .collect();
    Ok(json!({ "ids": ids }))
}

// The page a fill or a code is for, and whether the login must match it: not
// when the person chose a login for a site it isn't saved for.
fn fill_origin(params: &Value) -> Result<(url::Url, bool), VaultError> {
    let origin = origin(params)?;
    let chosen = params.get("chosen").and_then(Value::as_bool) == Some(true);
    Ok((origin, !chosen))
}

// The login a verb is for, after the origin and reprompt checks. With an
// origin, the login must match it.
async fn checked_login(
    ctx: &Ctx,
    params: &Value,
    origin: Option<&url::Url>,
) -> Result<(rbw::db::Db, usize), VaultError> {
    let id = required(params, "id")?;
    let db = unlocked().await?;
    let index = db
        .entries
        .iter()
        .position(|entry| entry.id == id && is_login(entry))
        .ok_or_else(VaultError::not_found)?;
    let reprompt = {
        let state = reprompt_ready(ctx, &db).await;
        let entry = &db.entries[index];
        let opened = Opened::new(&state, entry)?;
        if let Some(origin) = origin {
            if !matches_origin(&opened, entry, origin) {
                return Err(VaultError::new(
                    "origin_mismatch",
                    "This login isn't for this site.",
                ));
            }
        }
        needs_reprompt(&state, entry)
    };
    if reprompt {
        let Some(typed) = string(params, "masterPassword") else {
            return Err(VaultError::new(
                "reprompt",
                "This login asks for the master password again.",
            ));
        };
        let account = signed_in_account().await?;
        check_password(&account, typed).await?;
    }
    Ok((db, index))
}

async fn fill(ctx: &Ctx, params: &Value) -> Answer {
    let fields: Vec<&str> = params
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| VaultError::bad_request("fields is missing."))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if fields.is_empty() {
        return Err(VaultError::bad_request("fields is empty."));
    }
    let (origin, bound) = fill_origin(params)?;
    let (db, index) =
        checked_login(ctx, params, bound.then_some(&origin)).await?;
    let entry = &db.entries[index];
    let state = ctx.state.lock().await;
    let opened = Opened::new(&state, entry)?;
    let rbw::db::EntryData::Login {
        username,
        password,
        totp,
        ..
    } = &entry.data
    else {
        return Err(VaultError::not_found());
    };
    let mut values = serde_json::Map::new();
    for field in fields {
        let value = match field {
            "username" => opened.decrypt_opt(username.as_deref())?,
            "password" => opened.decrypt_opt(password.as_deref())?,
            "totp" => opened
                .decrypt_opt(totp.as_deref())?
                .map(|secret| rbw::totp::current(&secret))
                .transpose()
                .map_err(|_| {
                    VaultError::new(
                        "failed",
                        "The login's verification code setup isn't valid.",
                    )
                })?
                .map(|code| code.code),
            _ => {
                return Err(VaultError::bad_request(format!(
                    "{field:?} isn't a field: use username, password or totp."
                )))
            }
        };
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            values.insert(field.to_string(), Value::String(value));
        }
    }
    if values.is_empty() {
        return Err(VaultError::not_found());
    }
    drop(state);
    ctx.state.lock().await.set_timeout();
    Ok(json!({ "values": values }))
}

async fn totp(ctx: &Ctx, params: &Value) -> Answer {
    let (origin, bound) = fill_origin(params)?;
    let (db, index) =
        checked_login(ctx, params, bound.then_some(&origin)).await?;
    let entry = &db.entries[index];
    let state = ctx.state.lock().await;
    let opened = Opened::new(&state, entry)?;
    let rbw::db::EntryData::Login { totp, .. } = &entry.data else {
        return Err(VaultError::not_found());
    };
    let secret = opened
        .decrypt_opt(totp.as_deref())?
        .ok_or_else(VaultError::not_found)?;
    let code = rbw::totp::current(&secret).map_err(|_| {
        VaultError::new(
            "failed",
            "The login's verification code setup isn't valid.",
        )
    })?;
    Ok(json!({
        "code": code.code,
        "period": code.period,
        "expiresAt": code.expires_at.saturating_mul(1000),
    }))
}

// The tokens and user id a write to the server needs.
fn write_credentials(
    db: &rbw::db::Db,
) -> Result<(String, String, String), VaultError> {
    match (&db.access_token, &db.refresh_token, &db.user_id) {
        (Some(access), Some(refresh), Some(user)) => {
            Ok((access.clone(), refresh.clone(), user.clone()))
        }
        _ => Err(VaultError::signed_out()),
    }
}

// Keeps tokens the server refreshed during a write.
async fn keep_tokens(
    tokens: Option<rbw::actions::RefreshedTokens>,
) -> Result<(), VaultError> {
    if let Some(tokens) = tokens {
        let mut db = crate::actions::load_db().await?;
        tokens.store_in(&mut db);
        crate::actions::save_db(&db).await?;
    }
    Ok(())
}

// After a write: syncs, and answers with the item as `items` shows it.
async fn saved_item(ctx: &Ctx, id: &str) -> Answer {
    ctx.sync().await?;
    let db = unlocked().await?;
    let entry =
        db.entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| {
                VaultError::new(
                "failed",
                "Bitwarden saved the login but didn't send it back. Sync \
                 before saving it again.",
            )
            })?;
    let state = reprompt_ready(ctx, &db).await;
    Ok(json!({ "item": item_json(&state, entry)? }))
}

// A login's addresses as the host sends them: [{"uri", "match"}].
type UriList = Vec<(String, Option<rbw::api::UriMatchType>)>;

const MAX_URIS: usize = 100;
const MAX_URI_LEN: usize = 2048;

fn match_type(
    value: Option<&Value>,
) -> Result<Option<rbw::api::UriMatchType>, VaultError> {
    use rbw::api::UriMatchType;

    let name = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(name)) => name.as_str(),
        Some(_) => "",
    };
    Ok(Some(match name {
        "domain" => UriMatchType::Domain,
        "host" => UriMatchType::Host,
        "startsWith" => UriMatchType::StartsWith,
        "exact" => UriMatchType::Exact,
        "regex" => UriMatchType::RegularExpression,
        "never" => UriMatchType::Never,
        _ => {
            return Err(VaultError::bad_request(
                "match is domain, host, startsWith, exact, regex, never or \
                 null.",
            ))
        }
    }))
}

// The uris in the request, or None when it has none.
fn uri_list(params: &Value) -> Result<Option<UriList>, VaultError> {
    let Some(value) = params.get("uris") else {
        return Ok(None);
    };
    let list = value.as_array().ok_or_else(|| {
        VaultError::bad_request("uris is a list of {uri, match}.")
    })?;
    if list.len() > MAX_URIS {
        return Err(VaultError::bad_request(format!(
            "A login keeps at most {MAX_URIS} addresses."
        )));
    }
    list.iter()
        .map(|uri| {
            let address = uri
                .get("uri")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|address| {
                    !address.is_empty() && address.len() <= MAX_URI_LEN
                })
                .ok_or_else(|| {
                    VaultError::bad_request(
                        "Each of uris needs a uri, up to 2048 characters.",
                    )
                })?;
            Ok((address.to_string(), match_type(uri.get("match"))?))
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

impl Opened<'_> {
    // A new uri, with the checksum the official clients check.
    fn encrypt_uri(
        &self,
        uri: &str,
        match_type: Option<rbw::api::UriMatchType>,
    ) -> Result<rbw::db::Uri, VaultError> {
        Ok(rbw::db::Uri {
            uri: self.encrypt(uri)?,
            match_type,
            uri_checksum: Some(self.encrypt(&rbw::db::Uri::checksum(uri))?),
        })
    }

    // The uris of a login after an edit. A uri that stays as it was keeps
    // its ciphertext, so the server keeps its checksum.
    fn replace_uris(
        &self,
        old: &[rbw::db::Uri],
        new: &UriList,
    ) -> Result<Vec<rbw::db::Uri>, VaultError> {
        let old: Vec<(String, &rbw::db::Uri)> = old
            .iter()
            .filter_map(|uri| {
                self.decrypt(&uri.uri).ok().map(|plain| (plain, uri))
            })
            .collect();
        new.iter()
            .map(|(address, match_type)| {
                old.iter()
                    .find(|(plain, uri)| {
                        plain == address && uri.match_type == *match_type
                    })
                    .map_or_else(
                        || self.encrypt_uri(address, *match_type),
                        |(_, uri)| Ok((*uri).clone()),
                    )
            })
            .collect()
    }
}

fn valid_totp(change: &Change<'_>) -> Result<(), VaultError> {
    if let Change::Set(uri) = change {
        if !uri.is_empty() && rbw::totp::current(uri).is_err() {
            return Err(VaultError::bad_request(
                "totp isn't a verification code setup Bitwarden can use.",
            ));
        }
    }
    Ok(())
}

// Text to store, or None for an empty or removed value.
fn set_text(
    opened: &Opened<'_>,
    change: &Change<'_>,
    current: Option<&String>,
) -> Result<Option<String>, VaultError> {
    Ok(match change {
        Change::Keep => current.cloned(),
        Change::Remove | Change::Set("") => None,
        Change::Set(value) => Some(opened.encrypt(value)?),
    })
}

async fn save(ctx: &Ctx, params: &Value) -> Answer {
    let _writes = ctx.writes.lock().await;
    let origin = params
        .get("origin")
        .is_some()
        .then(|| origin(params))
        .transpose()?;
    let uris = uri_list(params)?.unwrap_or_else(|| {
        origin
            .iter()
            .map(|origin| (origin.origin().ascii_serialization(), None))
            .collect()
    });
    let new_password = required(params, "password")?;
    let username = change(params, "username")?;
    let notes = change(params, "notes")?;
    let totp = change(params, "totp")?;
    valid_totp(&totp)?;
    let title = string(params, "title")
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            uris.iter().find_map(|(address, _)| {
                url::Url::parse(address)
                    .ok()
                    .and_then(|url| url.host_str().map(ToString::to_string))
            })
        })
        .ok_or_else(|| VaultError::bad_request("title is missing."))?;

    let db = unlocked().await?;
    let (access_token, refresh_token, user_id) = write_credentials(&db)?;
    let (name, data, notes) = {
        let state = ctx.state.lock().await;
        let keys = state.key(None).ok_or_else(VaultError::locked)?;
        let opened = Opened {
            keys,
            entry_key: None,
        };
        (
            opened.encrypt(&title)?,
            rbw::db::EntryData::Login {
                username: set_text(&opened, &username, None)?,
                password: Some(opened.encrypt(new_password)?),
                totp: set_text(&opened, &totp, None)?,
                uris: uris
                    .iter()
                    .map(|(address, match_type)| {
                        opened.encrypt_uri(address, *match_type)
                    })
                    .collect::<Result<_, _>>()?,
            },
            set_text(&opened, &notes, None)?,
        )
    };
    let (tokens, saved) = tokio::task::spawn_blocking(move || {
        rbw::actions::add(
            &access_token,
            &refresh_token,
            &user_id,
            &name,
            &data,
            &[],
            notes.as_deref(),
            None,
        )
    })
    .await
    .context("saving the login stopped")??;
    keep_tokens(tokens).await?;
    saved_item(ctx, &saved.id).await
}

// The text of a change: absent (keep), null (remove) or a value.
enum Change<'a> {
    Keep,
    Remove,
    Set(&'a str),
}

fn change<'a>(
    params: &'a Value,
    name: &str,
) -> Result<Change<'a>, VaultError> {
    match params.get(name) {
        None => Ok(Change::Keep),
        Some(Value::Null) => Ok(Change::Remove),
        Some(Value::String(value)) => Ok(Change::Set(value)),
        Some(_) => {
            Err(VaultError::bad_request(format!("{name} is text or null.")))
        }
    }
}

// Bitwarden's apps keep the last five passwords.
const HISTORY_LEN: usize = 5;

// The login a change is for, if nobody changed it since the host read it.
fn current_login<'a>(
    db: &'a rbw::db::Db,
    params: &Value,
) -> Result<&'a rbw::db::Entry, VaultError> {
    let id = required(params, "id")?;
    let revision = required(params, "revision")?;
    let entry = db
        .entries
        .iter()
        .find(|entry| entry.id == id && is_login(entry))
        .ok_or_else(VaultError::not_found)?;
    if entry.revision_date.as_deref() != Some(revision) {
        return Err(VaultError::new(
            "conflict",
            "The login changed since it was last read.",
        ));
    }
    Ok(entry)
}

async fn update(ctx: &Ctx, params: &Value) -> Answer {
    let _writes = ctx.writes.lock().await;
    let new_title = change(params, "title")?;
    let new_username = change(params, "username")?;
    let new_password = change(params, "password")?;
    let new_totp = change(params, "totp")?;
    let new_notes = change(params, "notes")?;
    let new_uris = uri_list(params)?;
    if matches!(new_password, Change::Remove | Change::Set("")) {
        return Err(VaultError::bad_request(
            "A login keeps its password: send a new one instead of null.",
        ));
    }
    let new_title = match new_title {
        Change::Remove => Change::Set(""),
        Change::Set(title) => Change::Set(title.trim()),
        Change::Keep => Change::Keep,
    };
    if matches!(new_title, Change::Set("")) {
        return Err(VaultError::bad_request("A login needs a title."));
    }
    valid_totp(&new_totp)?;

    let db = unlocked().await?;
    let (access_token, refresh_token, user_id) = write_credentials(&db)?;
    let entry = current_login(&db, params)?;
    let revision = entry.revision_date.clone();
    let rbw::db::EntryData::Login {
        username,
        password,
        totp,
        uris,
    } = &entry.data
    else {
        return Err(VaultError::not_found());
    };

    let (name, data, notes, history) = {
        let state = ctx.state.lock().await;
        let opened = Opened::new(&state, entry)?;
        let name = match new_title {
            Change::Set(title) => opened.encrypt(title)?,
            _ => entry.name.clone(),
        };
        let mut history = entry.history.clone();
        let password = match new_password {
            Change::Keep | Change::Remove => password.clone(),
            Change::Set(value) => {
                let current = opened.decrypt_opt(password.as_deref())?;
                if current.as_deref() == Some(value) {
                    password.clone()
                } else {
                    if let Some(old) = password {
                        history.insert(
                            0,
                            rbw::db::HistoryEntry {
                                last_used_date: rbw::api::format_rfc3339(
                                    std::time::SystemTime::now(),
                                ),
                                password: old.clone(),
                            },
                        );
                        history.truncate(HISTORY_LEN);
                    }
                    Some(opened.encrypt(value)?)
                }
            }
        };
        let uris = match &new_uris {
            Some(new) => opened.replace_uris(uris, new)?,
            None => uris.clone(),
        };
        (
            name,
            rbw::db::EntryData::Login {
                username: set_text(
                    &opened,
                    &new_username,
                    username.as_ref(),
                )?,
                password,
                totp: set_text(&opened, &new_totp, totp.as_ref())?,
                uris,
            },
            set_text(&opened, &new_notes, entry.notes.as_ref())?,
            history,
        )
    };

    let entry = entry.clone();
    let id = entry.id.clone();
    let (tokens, _) = tokio::task::spawn_blocking(move || {
        rbw::actions::edit(
            &access_token,
            &refresh_token,
            &user_id,
            &entry.id,
            entry.org_id.as_deref(),
            &name,
            &data,
            &entry.fields,
            notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
            entry.key.as_deref(),
            revision.as_deref(),
        )
    })
    .await
    .context("saving the change stopped")?
    .map_err(|e| match e {
        rbw::error::Error::CipherOutOfDate => VaultError::new(
            "conflict",
            "The login changed on the server since it was last read.",
        ),
        e => e.into(),
    })?;
    keep_tokens(tokens).await?;
    saved_item(ctx, &id).await
}

// Moves a login to the trash: Bitwarden's apps can restore it for 30 days.
async fn delete(ctx: &Ctx, params: &Value) -> Answer {
    let _writes = ctx.writes.lock().await;
    let db = unlocked().await?;
    if !ctx.is_unlocked().await {
        return Err(VaultError::locked());
    }
    let (access_token, refresh_token, _) = write_credentials(&db)?;
    let id = current_login(&db, params)?.id.clone();
    let (tokens, ()) = tokio::task::spawn_blocking(move || {
        rbw::actions::trash(&access_token, &refresh_token, &id)
    })
    .await
    .context("deleting the login stopped")??;
    keep_tokens(tokens).await?;
    ctx.sync().await?;
    Ok(json!({ "ok": true }))
}

// A login's secrets for the host itself, such as an edit sheet: no page is
// involved, so there's no origin to check.
async fn reveal(ctx: &Ctx, params: &Value) -> Answer {
    let fields: Vec<&str> = params
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| VaultError::bad_request("fields is missing."))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let (db, index) = checked_login(ctx, params, None).await?;
    let entry = &db.entries[index];
    let state = ctx.state.lock().await;
    let opened = Opened::new(&state, entry)?;
    let rbw::db::EntryData::Login { password, totp, .. } = &entry.data else {
        return Err(VaultError::not_found());
    };
    let mut values = serde_json::Map::new();
    for field in fields {
        let value = match field {
            "password" => opened.decrypt_opt(password.as_deref())?,
            "totp" => opened.decrypt_opt(totp.as_deref())?,
            "notes" => opened.decrypt_opt(entry.notes.as_deref())?,
            _ => {
                return Err(VaultError::bad_request(format!(
                    "{field:?} isn't a field: use password, totp or notes."
                )))
            }
        };
        if let Some(value) = value {
            values.insert(field.to_string(), Value::String(value));
        }
    }
    drop(state);
    ctx.state.lock().await.set_timeout();
    Ok(json!({ "values": values }))
}

// A new password. It needs no account, so the accounts router answers it
// too.
pub fn generate(params: &Value) -> Answer {
    use rbw::pwgen::Type;

    let kind = string(params, "kind").unwrap_or("random");
    let (ty, default, range) = match kind {
        "random" => (Type::AllChars, 20, 8..=128),
        "letters" => (Type::NoSymbols, 20, 8..=128),
        "numbers" => (Type::Numbers, 6, 4..=128),
        "words" => (Type::Diceware, 5, 3..=20),
        _ => {
            return Err(VaultError::bad_request(
                "kind is random, letters, numbers or words.",
            ))
        }
    };
    let length = match params.get("length") {
        None | Some(Value::Null) => default,
        Some(length) => length
            .as_u64()
            .and_then(|length| usize::try_from(length).ok())
            .filter(|length| range.contains(length))
            .ok_or_else(|| {
                VaultError::bad_request(format!(
                    "length is from {} to {} for {kind}.",
                    range.start(),
                    range.end()
                ))
            })?,
    };
    // sites often ask for a digit and a letter, and a symbol when the
    // password may have one
    let complete = |password: &str| match ty {
        Type::AllChars => {
            password.chars().any(|c| c.is_ascii_digit())
                && password.chars().any(|c| c.is_ascii_alphabetic())
                && password.chars().any(|c| c.is_ascii_punctuation())
        }
        Type::NoSymbols => {
            password.chars().any(|c| c.is_ascii_digit())
                && password.chars().any(|c| c.is_ascii_lowercase())
                && password.chars().any(|c| c.is_ascii_uppercase())
        }
        _ => true,
    };
    let password = std::iter::repeat_with(|| rbw::pwgen::pwgen(ty, length))
        .take(64)
        .find(|password| complete(password))
        .unwrap_or_else(|| rbw::pwgen::pwgen(ty, length));
    Ok(json!({ "password": password }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn servers() {
        assert_eq!(base_url_for("").unwrap(), None);
        assert_eq!(base_url_for("bitwarden.com").unwrap(), None);
        assert_eq!(
            base_url_for("EU").unwrap().as_deref(),
            Some("https://api.bitwarden.eu")
        );
        assert_eq!(
            base_url_for("https://vault.example.com/")
                .unwrap()
                .as_deref(),
            Some("https://vault.example.com")
        );
        assert_eq!(
            base_url_for("http://localhost:8080").unwrap().as_deref(),
            Some("http://localhost:8080")
        );
        for refused in [
            "http://vault.example.com",
            "ftp://vault.example.com",
            "https://user:pass@vault.example.com",
            "https://vault.example.com/?x=1",
            "vault.example.com",
        ] {
            assert!(base_url_for(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn origins() {
        let ok = |o: &str| origin(&json!({ "origin": o })).is_ok();
        assert!(ok("https://github.com"));
        assert!(ok("http://localhost:3000"));
        assert!(!ok("http://github.com"));
        assert!(!ok("file:///etc/passwd"));
        assert!(!ok("javascript:alert(1)"));
        assert!(origin(&json!({})).is_err());
    }

    #[test]
    fn changes() {
        let params = json!({ "username": "me", "totp": null });
        assert!(matches!(change(&params, "username"), Ok(Change::Set("me"))));
        assert!(matches!(change(&params, "totp"), Ok(Change::Remove)));
        assert!(matches!(change(&params, "password"), Ok(Change::Keep)));
        assert!(change(&json!({ "password": 4 }), "password").is_err());
    }

    #[test]
    fn uris() {
        let list = uri_list(&json!({ "uris": [
            { "uri": " https://github.com ", "match": "host" },
            { "uri": "https://example.com" },
        ] }))
        .unwrap()
        .unwrap();
        assert_eq!(
            list,
            vec![
                (
                    "https://github.com".to_string(),
                    Some(rbw::api::UriMatchType::Host)
                ),
                ("https://example.com".to_string(), None),
            ]
        );
        assert!(uri_list(&json!({})).unwrap().is_none());
        for refused in [
            json!({ "uris": "https://github.com" }),
            json!({ "uris": [{ "uri": "" }] }),
            json!({ "uris": [{ "uri": "https://a.b", "match": "sometimes" }] }),
            json!({ "uris": [{ "uri": "x".repeat(MAX_URI_LEN + 1) }] }),
            json!({ "uris": vec![json!({ "uri": "https://a.b" }); MAX_URIS + 1] }),
        ] {
            assert!(uri_list(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn generated_passwords() {
        let password = |params: Value| {
            generate(&params).unwrap()["password"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let random = password(json!({}));
        assert_eq!(random.len(), 20);
        assert!(random.chars().any(|c| c.is_ascii_digit()));
        assert!(random.chars().any(|c| c.is_ascii_punctuation()));
        let letters = password(json!({ "kind": "letters", "length": 12 }));
        assert_eq!(letters.len(), 12);
        assert!(letters.chars().all(|c| c.is_ascii_alphanumeric()));
        let pin = password(json!({ "kind": "numbers" }));
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            password(json!({ "kind": "words", "length": 4 }))
                .split(' ')
                .count(),
            4
        );
        for refused in [
            json!({ "kind": "emoji" }),
            json!({ "length": 4 }),
            json!({ "length": "20" }),
            json!({ "kind": "words", "length": 50 }),
        ] {
            assert!(generate(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn errors_name_their_cause() {
        let e: VaultError = rbw::error::Error::CipherOutOfDate.into();
        assert_eq!(e.code, "conflict");
        let e: VaultError = rbw::error::Error::IncorrectPassword {
            message: "nope".to_string(),
        }
        .into();
        assert_eq!(e.code, "wrong_password");
        let e: VaultError = anyhow::anyhow!("something else").into();
        assert_eq!(e.code, "failed");
    }
}
