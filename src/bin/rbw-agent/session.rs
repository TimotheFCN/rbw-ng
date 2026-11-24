// Sessions, for programs that drive rbw (rbw unlock --session). After an
// unlock with the master password, the agent encrypts the vault key with a
// random session key, keeps the encrypted copy on disk and hands the
// session key to the program. The program keeps the session key, for
// example behind Touch ID, and passes it back in RBW_SESSION to unlock
// again, even after the agent restarted. Either half alone opens nothing,
// and rbw lock, rbw purge or a new session retire it.

use anyhow::Context as _;
use rand::RngCore as _;
use sha2::Digest as _;

const SESSION_KEY_LEN: usize = 64;

// The vault key, encrypted with a session key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wrapped {
    // which account key this wraps: the sha256 of the protected key at the
    // time, so a changed master password retires it
    protected_key_digest: String,
    wrapped_key: String,
}

impl std::fmt::Debug for Wrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wrapped").finish_non_exhaustive()
    }
}

impl Wrapped {
    // Whether this was made for the account key the vault has now.
    pub fn is_for(&self, protected_key: &str) -> bool {
        self.protected_key_digest == digest(protected_key)
    }
}

fn digest(protected_key: &str) -> String {
    let mut sha256 = sha2::Sha256::new();
    sha256.update(protected_key);
    rbw::base64::encode(sha256.finalize())
}

// A new session key for the vault key, and the vault key encrypted with it.
// The session key is base64, for the caller to keep.
pub fn wrap(
    vault_key: &rbw::locked::Keys,
    protected_key: &str,
) -> anyhow::Result<(String, Wrapped)> {
    let mut session_key = rbw::locked::Vec::new();
    session_key.extend(std::iter::repeat_n(0, SESSION_KEY_LEN));
    rand::rng().fill_bytes(session_key.data_mut());
    let wrapping_keys = rbw::locked::Keys::new(session_key);
    let wrapped_key = rbw::cipherstring::CipherString::encrypt_symmetric(
        &wrapping_keys,
        vault_key.as_bytes(),
    )
    .context("failed to encrypt the vault key")?;
    Ok((
        rbw::base64::encode(wrapping_keys.as_bytes()),
        Wrapped {
            protected_key_digest: digest(protected_key),
            wrapped_key: wrapped_key.to_string(),
        },
    ))
}

// The vault key, from the encrypted copy and the session key the caller
// sent back.
// Fails when the session key is the wrong one, or the account key changed.
pub fn unwrap(
    wrapped: &Wrapped,
    session_key: &str,
    protected_key: &str,
) -> anyhow::Result<rbw::locked::Keys> {
    if wrapped.protected_key_digest != digest(protected_key) {
        return Err(anyhow::anyhow!(
            "the account key changed since this session key was made"
        ));
    }
    let mut decoded = rbw::base64::decode(session_key.trim())
        .context("the session key isn't base64")?;
    if decoded.len() != SESSION_KEY_LEN {
        zeroize::Zeroize::zeroize(&mut decoded);
        return Err(anyhow::anyhow!("the session key has the wrong length"));
    }
    let mut key = rbw::locked::Vec::new();
    key.extend(decoded.iter().copied());
    zeroize::Zeroize::zeroize(&mut decoded);
    let wrapping_keys = rbw::locked::Keys::new(key);
    let vault_key =
        rbw::cipherstring::CipherString::new(&wrapped.wrapped_key)
            .context("the wrapped vault key is damaged")?
            .decrypt_locked_symmetric(&wrapping_keys)
            .context("the session key doesn't open the wrapped vault key")?;
    Ok(rbw::locked::Keys::new(vault_key))
}

pub fn load() -> Option<Wrapped> {
    let json = std::fs::read(rbw::dirs::session_file()).ok()?;
    match serde_json::from_slice::<Wrapped>(&json) {
        Ok(wrapped) => Some(wrapped),
        Err(e) => {
            log::warn!("ignoring a damaged session: {e}");
            None
        }
    }
}

pub fn save(wrapped: &Wrapped) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = rbw::dirs::session_file();
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)
            .context("failed to create the data folder")?;
    }
    let json = serde_json::to_vec(wrapped)
        .context("failed to encode the session")?;
    // write a new file and rename it over the old one, so a crash never
    // leaves half a key
    let tmp = file.with_extension("json.tmp");
    let mut fh = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .context("failed to save the session")?;
    fh.write_all(&json)
        .and_then(|()| fh.sync_all())
        .context("failed to save the session")?;
    std::fs::rename(&tmp, &file).context("failed to save the session")?;
    Ok(())
}

pub fn delete() {
    let file = rbw::dirs::session_file();
    if let Err(e) = std::fs::remove_file(&file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("failed to delete the session: {e}");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn vault_key() -> rbw::locked::Keys {
        let mut key = rbw::locked::Vec::new();
        key.extend((0..64).map(|i: u8| i.wrapping_mul(7)));
        rbw::locked::Keys::new(key)
    }

    #[test]
    fn round_trip() {
        let key = vault_key();
        let (session_key, wrapped) = wrap(&key, "2.protected").unwrap();
        let back = unwrap(&wrapped, &session_key, "2.protected").unwrap();
        assert_eq!(back.enc_key(), key.enc_key());
        assert_eq!(back.mac_key(), key.mac_key());
    }

    #[test]
    fn each_wrap_has_its_own_key() {
        let key = vault_key();
        let (first, _) = wrap(&key, "2.protected").unwrap();
        let (second, wrapped) = wrap(&key, "2.protected").unwrap();
        assert_ne!(first, second);
        assert!(unwrap(&wrapped, &first, "2.protected").is_err());
    }

    #[test]
    fn refuses_a_changed_account_key() {
        let key = vault_key();
        let (session_key, wrapped) = wrap(&key, "2.protected").unwrap();
        assert!(unwrap(&wrapped, &session_key, "2.rotated").is_err());
    }

    #[test]
    fn refuses_malformed_session_keys() {
        let key = vault_key();
        let (_, wrapped) = wrap(&key, "2.protected").unwrap();
        assert!(unwrap(&wrapped, "not base64!", "2.protected").is_err());
        assert!(unwrap(&wrapped, "AAAA", "2.protected").is_err());
    }

    #[test]
    fn debug_hides_the_key() {
        let key = vault_key();
        let (_, wrapped) = wrap(&key, "2.protected").unwrap();
        let shown = format!("{wrapped:?}");
        assert!(!shown.contains(&wrapped.wrapped_key));
    }
}
