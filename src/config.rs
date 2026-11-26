use crate::prelude::*;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    #[serde(default = "default_pinentry_timeout")]
    pub pinentry_timeout: u64,
    #[serde(default)]
    pub touch_id_unlock: bool,
    // Ask before every SSH agent signature. Read it with
    // confirms_ssh_signatures(), which honours touch_id_ssh too.
    #[serde(default)]
    pub ssh_confirm: bool,
    // The macOS-only name of ssh_confirm in 1.17.0, still read so those
    // configs keep asking. `rbw config` keeps it equal to ssh_confirm, so
    // that going back to 1.17.0, which only knows this key, keeps asking
    // too. It is only written while on.
    #[serde(default, skip_serializing_if = "is_false")]
    pub touch_id_ssh: bool,
    pub client_cert_path: Option<std::path::PathBuf>,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
    // Sent with every request to the server, as {"Name": "value"}.
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub extra_headers: std::collections::BTreeMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            pinentry_timeout: default_pinentry_timeout(),
            touch_id_unlock: false,
            ssh_confirm: false,
            touch_id_ssh: false,
            client_cert_path: None,
            device_id: None,
            extra_headers: std::collections::BTreeMap::new(),
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub const fn default_pinentry_timeout() -> u64 {
    120
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
const fn is_false(value: &bool) -> bool {
    !*value
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    // Writes to a temporary file next to the config and renames it into
    // place, so that a crash or a concurrent reader never sees a partly
    // written config. extra_headers can hold credentials, so the config is
    // private, and so is a folder made for it.
    pub fn save(&self) -> Result<()> {
        self.save_to(crate::dirs::config_file())
    }

    fn save_to(&self, file: std::path::PathBuf) -> Result<()> {
        let json = serde_json::to_string(self).map_err(|source| {
            Error::SaveConfigJson {
                source,
                file: file.clone(),
            }
        })?;
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(file.parent().unwrap())
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.clone(),
            })?;
        // a config that links to another file, for example in a dotfiles
        // repository, stays a link
        let target = std::fs::canonicalize(&file).unwrap_or(file);
        let temp = crate::db::temp_file(&target);
        let res = (|| {
            let mut fh = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            fh.write_all(json.as_bytes())?;
            fh.sync_all()?;
            std::fs::rename(&temp, &target)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        res.map_err(|source| Error::SaveConfig {
            source,
            file: target,
        })
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    // The icon service: Bitwarden's own for its cloud servers, /icons on a
    // self-hosted one.
    pub fn icons_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://icons.bitwarden.net".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://icons.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/icons")
                }
            },
        )
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn confirms_ssh_signatures(&self) -> bool {
        self.ssh_confirm || self.touch_id_ssh
    }

    // For `rbw config set` and `unset` of ssh_confirm and its old name
    // touch_id_ssh, which both end up with the same value.
    pub fn set_ssh_confirm(&mut self, enabled: bool) {
        self.ssh_confirm = enabled;
        self.touch_id_ssh = enabled;
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    // The extra_headers setting, checked. Header names are
    // case-insensitive, so two spellings of one name are refused.
    pub fn extra_headers(&self) -> Result<axum::http::HeaderMap> {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in &self.extra_headers {
            let (header_name, header_value) =
                parse_extra_header(name, value)?;
            if headers.contains_key(&header_name) {
                return Err(Error::DuplicateHttpHeader {
                    header_name: name.clone(),
                });
            }
            headers.insert(header_name, header_value);
        }
        Ok(headers)
    }
}

// Headers that rbw sets itself, or that belong to the HTTP or websocket
// connection rather than to the request. A copy from extra_headers would
// either be ignored or break the request, so they are refused.
const RESERVED_HEADERS: &[&str] = &[
    "auth-email",
    "authorization",
    "connection",
    "content-length",
    "content-type",
    "device-type",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
];
const RESERVED_HEADER_PREFIXES: &[&str] = &["bitwarden-", "sec-websocket-"];

// Checks one entry of extra_headers. The error never includes the value,
// which is often a secret.
pub fn parse_extra_header(
    name: &str,
    value: &str,
) -> Result<(axum::http::HeaderName, axum::http::HeaderValue)> {
    let header_name =
        axum::http::HeaderName::try_from(name).map_err(|_| {
            Error::InvalidHttpHeaderName {
                header_name: name.to_string(),
            }
        })?;
    // HeaderName is lowercase
    let lowercase = header_name.as_str();
    if RESERVED_HEADERS.contains(&lowercase)
        || RESERVED_HEADER_PREFIXES
            .iter()
            .any(|prefix| lowercase.starts_with(prefix))
    {
        return Err(Error::ReservedHttpHeader {
            header_name: name.to_string(),
        });
    }
    let mut header_value =
        axum::http::HeaderValue::try_from(value).map_err(|_| {
            Error::InvalidHttpHeaderValue {
                header_name: name.to_string(),
            }
        })?;
    // keeps the value out of Debug output
    header_value.set_sensitive(true);
    Ok((header_name, header_value))
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        let id = config.device_id.as_ref().map_or_else(
            || uuid::Uuid::new_v4().hyphenated().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::File::create(&file).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icons_come_from_the_servers_icon_service() {
        let mut config = Config::new();
        assert_eq!(config.icons_url(), "https://icons.bitwarden.net");
        config.base_url = Some("https://api.bitwarden.eu/".to_string());
        assert_eq!(config.icons_url(), "https://icons.bitwarden.eu");
        config.base_url = Some("https://vault.example.com/".to_string());
        assert_eq!(config.icons_url(), "https://vault.example.com/icons");
    }

    #[test]
    fn saves_are_atomic_and_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("rbw/config.json");
        let mut config = Config::new();
        config.email = Some("me@example.com".to_string());
        config.save_to(file.clone()).unwrap();
        config.email = Some("you@example.com".to_string());
        config.save_to(file.clone()).unwrap();

        let saved: Config =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap())
                .unwrap();
        assert_eq!(saved.email.as_deref(), Some("you@example.com"));
        let mode = |path: &std::path::Path| {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
        // no temporary file is left behind
        assert_eq!(
            std::fs::read_dir(file.parent().unwrap()).unwrap().count(),
            1
        );

        // a config that links elsewhere stays a link
        let target = dir.path().join("dotfiles.json");
        std::fs::write(&target, "{}").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        config.save_to(link.clone()).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert!(std::fs::read_to_string(&target)
            .unwrap()
            .contains("you@example.com"));
    }

    #[test]
    fn extra_headers_are_read_as_an_object() {
        let config: Config = serde_json::from_str(
            r#"{"extra_headers": {"CF-Access-Client-Id": "id.access",
                "CF-Access-Client-Secret": "secret"}}"#,
        )
        .unwrap();
        let headers = config.extra_headers().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers["cf-access-client-id"], "id.access");
        assert_eq!(headers["CF-Access-Client-Secret"], "secret");
        assert!(headers["CF-Access-Client-Secret"].is_sensitive());

        // written back as it was read, and left out when empty
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["extra_headers"]["CF-Access-Client-Id"], "id.access");
        let json = serde_json::to_value(Config::new()).unwrap();
        assert!(json.get("extra_headers").is_none());
        assert!(Config::new().extra_headers().unwrap().is_empty());
    }

    #[test]
    fn bad_extra_headers_are_refused() {
        let check = |name: &str, value: &str| {
            let mut config = Config::new();
            config
                .extra_headers
                .insert(name.to_string(), value.to_string());
            config.extra_headers().unwrap_err()
        };
        assert!(matches!(
            check("Bad Name", "x"),
            Error::InvalidHttpHeaderName { .. }
        ));
        assert!(matches!(
            check("", "x"),
            Error::InvalidHttpHeaderName { .. }
        ));
        let err = check("X-Token", "secret\r\nHost: evil");
        assert!(matches!(err, Error::InvalidHttpHeaderValue { .. }));
        assert!(!err.to_string().contains("secret"));
        for name in [
            "Authorization",
            "host",
            "Content-Type",
            "User-Agent",
            "Device-Type",
            "Bitwarden-Client-Version",
            "bitwarden-anything",
            "Sec-WebSocket-Key",
            "Transfer-Encoding",
        ] {
            assert!(
                matches!(check(name, "x"), Error::ReservedHttpHeader { .. }),
                "{name}"
            );
        }

        let mut config = Config::new();
        config
            .extra_headers
            .insert("X-Token".to_string(), "a".to_string());
        config
            .extra_headers
            .insert("x-token".to_string(), "b".to_string());
        assert!(matches!(
            config.extra_headers().unwrap_err(),
            Error::DuplicateHttpHeader { .. }
        ));

        // allowed: proxy credentials and cookies
        for name in ["Proxy-Authorization", "Cookie", "X-Forwarded-User"] {
            let mut config = Config::new();
            config
                .extra_headers
                .insert(name.to_string(), "x".to_string());
            assert!(config.extra_headers().is_ok(), "{name}");
        }
    }

    #[test]
    fn old_config_defaults_touch_id_unlock_to_false() {
        let config: Config = serde_json::from_str("{}").unwrap();
        assert!(!config.touch_id_unlock);
        assert!(!config.touch_id_ssh);
        assert!(!config.confirms_ssh_signatures());
        assert_eq!(config.pinentry_timeout, 120);
    }

    #[test]
    fn touch_id_ssh_still_turns_on_ssh_confirm() {
        let parse = |json| serde_json::from_str::<Config>(json).unwrap();

        // a 1.17.0 config
        let config = parse(r#"{"touch_id_ssh": true}"#);
        assert!(config.confirms_ssh_signatures());
        assert!(!config.ssh_confirm);
        // and saved again unchanged, so a downgrade keeps asking
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["touch_id_ssh"], true);

        assert!(
            !parse(r#"{"touch_id_ssh": false}"#).confirms_ssh_signatures()
        );
        assert!(parse(r#"{"ssh_confirm": true}"#).confirms_ssh_signatures());
        assert!(parse(r#"{"ssh_confirm": true, "touch_id_ssh": false}"#)
            .confirms_ssh_signatures());
        assert!(parse(r#"{"ssh_confirm": false, "touch_id_ssh": true}"#)
            .confirms_ssh_signatures());

        // turning it off through either key turns it off
        let mut config = parse(r#"{"touch_id_ssh": true}"#);
        config.set_ssh_confirm(false);
        assert!(!config.confirms_ssh_signatures());
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["ssh_confirm"], false);
        // the old key is only written while it is on
        assert!(json.get("touch_id_ssh").is_none());

        // turning it on writes the old key too, for a downgrade to 1.17.0
        let mut config = Config::new();
        config.set_ssh_confirm(true);
        assert!(config.confirms_ssh_signatures());
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["ssh_confirm"], true);
        assert_eq!(json["touch_id_ssh"], true);
    }
}
