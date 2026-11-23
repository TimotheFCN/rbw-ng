// Unlocking without the master password, for example with Touch ID. The
// agent may run where it can't reach the system's keychain or biometrics
// (a browser's plugin sandbox), and the vault key must not leave it, so the
// agent encrypts the vault key with a random key it hands to the host (the
// host key) and keeps only the encrypted copy. The host guards the host key,
// for example behind Touch ID, and gives it back to unlock. Either half
// alone opens nothing.

use anyhow::Context as _;
use rand::RngCore as _;
use sha2::Digest as _;

const HOST_KEY_LEN: usize = 64;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    // The host keeps the host key in memory: gone when it quits.
    Session,
    // The host keeps the host key across restarts (a keychain, behind
    // biometrics).
    Persistent,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(Self::Session),
            "persistent" => Some(Self::Persistent),
            _ => None,
        }
    }
}

// The vault key, encrypted with a host key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wrapped {
    pub kind: Kind,
    // which account key this wraps: the sha256 of the protected key at the
    // time, so a changed master password retires it
    protected_key_digest: String,
    wrapped_key: String,
}

impl std::fmt::Debug for Wrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wrapped")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
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

// A new host key for the vault key, and the vault key encrypted with it.
// The host key is base64, for the host to keep.
pub fn wrap(
    vault_key: &rbw::locked::Keys,
    protected_key: &str,
    kind: Kind,
) -> anyhow::Result<(String, Wrapped)> {
    let mut host_key = rbw::locked::Vec::new();
    host_key.extend(std::iter::repeat_n(0, HOST_KEY_LEN));
    rand::rng().fill_bytes(host_key.data_mut());
    let wrapping_keys = rbw::locked::Keys::new(host_key);
    let wrapped_key = rbw::cipherstring::CipherString::encrypt_symmetric(
        &wrapping_keys,
        vault_key.as_bytes(),
    )
    .context("failed to encrypt the vault key")?;
    Ok((
        rbw::base64::encode(wrapping_keys.as_bytes()),
        Wrapped {
            kind,
            protected_key_digest: digest(protected_key),
            wrapped_key: wrapped_key.to_string(),
        },
    ))
}

// The vault key, from the encrypted copy and the host key the host sent
// back.
// Fails when the host key is the wrong one, or the account key changed.
pub fn unwrap(
    wrapped: &Wrapped,
    host_key: &str,
    protected_key: &str,
) -> anyhow::Result<rbw::locked::Keys> {
    if wrapped.protected_key_digest != digest(protected_key) {
        return Err(anyhow::anyhow!(
            "the account key changed since this host key was made"
        ));
    }
    let mut decoded = rbw::base64::decode(host_key.trim())
        .context("the host key isn't base64")?;
    if decoded.len() != HOST_KEY_LEN {
        zeroize::Zeroize::zeroize(&mut decoded);
        return Err(anyhow::anyhow!("the host key has the wrong length"));
    }
    let mut key = rbw::locked::Vec::new();
    key.extend(decoded.iter().copied());
    zeroize::Zeroize::zeroize(&mut decoded);
    let wrapping_keys = rbw::locked::Keys::new(key);
    let vault_key =
        rbw::cipherstring::CipherString::new(&wrapped.wrapped_key)
            .context("the wrapped vault key is damaged")?
            .decrypt_locked_symmetric(&wrapping_keys)
            .context("the host key doesn't open the wrapped vault key")?;
    Ok(rbw::locked::Keys::new(vault_key))
}

pub fn load_persistent() -> Option<Wrapped> {
    let json = std::fs::read(rbw::dirs::host_key_file()).ok()?;
    match serde_json::from_slice::<Wrapped>(&json) {
        Ok(wrapped) if wrapped.kind == Kind::Persistent => Some(wrapped),
        Ok(_) => None,
        Err(e) => {
            log::warn!("ignoring a damaged wrapped vault key: {e}");
            None
        }
    }
}

pub fn save_persistent(wrapped: &Wrapped) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = rbw::dirs::host_key_file();
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)
            .context("failed to create the data folder")?;
    }
    let json = serde_json::to_vec(wrapped)
        .context("failed to encode the wrapped vault key")?;
    // write a new file and rename it over the old one, so a crash never
    // leaves half a key
    let tmp = file.with_extension("json.tmp");
    let mut fh = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .context("failed to save the wrapped vault key")?;
    fh.write_all(&json)
        .and_then(|()| fh.sync_all())
        .context("failed to save the wrapped vault key")?;
    std::fs::rename(&tmp, &file)
        .context("failed to save the wrapped vault key")?;
    Ok(())
}

pub fn delete_persistent() {
    let file = rbw::dirs::host_key_file();
    if let Err(e) = std::fs::remove_file(&file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("failed to delete the wrapped vault key: {e}");
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
        let (host_key, wrapped) =
            wrap(&key, "2.protected", Kind::Session).unwrap();
        let back = unwrap(&wrapped, &host_key, "2.protected").unwrap();
        assert_eq!(back.enc_key(), key.enc_key());
        assert_eq!(back.mac_key(), key.mac_key());
    }

    #[test]
    fn each_wrap_has_its_own_key() {
        let key = vault_key();
        let (first, _) = wrap(&key, "2.protected", Kind::Session).unwrap();
        let (second, wrapped) =
            wrap(&key, "2.protected", Kind::Session).unwrap();
        assert_ne!(first, second);
        assert!(unwrap(&wrapped, &first, "2.protected").is_err());
    }

    #[test]
    fn refuses_a_changed_account_key() {
        let key = vault_key();
        let (host_key, wrapped) =
            wrap(&key, "2.protected", Kind::Persistent).unwrap();
        assert!(unwrap(&wrapped, &host_key, "2.rotated").is_err());
    }

    #[test]
    fn refuses_malformed_host_keys() {
        let key = vault_key();
        let (_, wrapped) = wrap(&key, "2.protected", Kind::Session).unwrap();
        assert!(unwrap(&wrapped, "not base64!", "2.protected").is_err());
        assert!(unwrap(&wrapped, "AAAA", "2.protected").is_err());
    }

    #[test]
    fn debug_hides_the_key() {
        let key = vault_key();
        let (_, wrapped) = wrap(&key, "2.protected", Kind::Session).unwrap();
        let shown = format!("{wrapped:?}");
        assert!(!shown.contains(&wrapped.wrapped_key));
    }
}
