use crate::prelude::*;

use sha1::Digest as _;

// The most memory, in MiB, that the key derivation may take. Bitwarden
// defaults to 64 MiB and allows up to 1024 MiB; the settings come from the
// server, and much more would let it make the agent run out of memory.
const ARGON2_MAX_MEMORY_MIB: u32 = 2048;

// The Argon2id settings the server sent, checked: memory in MiB.
fn argon2_params(
    memory: Option<u32>,
    iterations: u32,
    parallelism: Option<u32>,
) -> Result<argon2::Params> {
    let memory = memory
        .filter(|memory| (1..=ARGON2_MAX_MEMORY_MIB).contains(memory))
        .ok_or(Error::Argon2)?;
    // argon2 itself would overflow, and panic, on a larger one
    let parallelism = parallelism
        .filter(|parallelism| {
            (argon2::Params::MIN_P_COST..=argon2::Params::MAX_P_COST)
                .contains(parallelism)
        })
        .ok_or(Error::Argon2)?;
    argon2::Params::new(
        memory.checked_mul(1024).ok_or(Error::Argon2)?,
        iterations,
        parallelism,
        Some(32),
    )
    .map_err(|_| Error::Argon2)
}

pub struct Identity {
    pub email: String,
    pub keys: crate::locked::Keys,
    pub master_password_hash: crate::locked::PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &crate::locked::Password,
        kdf: crate::api::KdfType,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let email = email.trim().to_lowercase();

        let iterations = std::num::NonZeroU32::new(iterations)
            .ok_or(Error::Pbkdf2ZeroIterations)?;

        let mut keys = crate::locked::Vec::new();
        keys.extend(std::iter::repeat_n(0, 64));

        let enc_key = &mut keys.data_mut()[0..32];

        match kdf {
            crate::api::KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                    password.password(),
                    email.as_bytes(),
                    iterations.get(),
                    enc_key,
                )
                .map_err(|_| Error::Pbkdf2)?;
            }

            crate::api::KdfType::Argon2id => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(email.as_bytes());
                let salt = hasher.finalize();

                let argon2_config = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2_params(memory, iterations.get(), parallelism)?,
                );
                argon2::Argon2::hash_password_into(
                    &argon2_config,
                    password.password(),
                    &salt,
                    enc_key,
                )
                .map_err(|_| Error::Argon2)?;
            }
        }

        let mut hash = crate::locked::Vec::new();
        hash.extend(std::iter::repeat_n(0, 32));
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            enc_key,
            password.password(),
            1,
            hash.data_mut(),
        )
        .map_err(|_| Error::Pbkdf2)?;

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        hkdf.expand(b"enc", enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        let mac_key = &mut keys.data_mut()[32..64];
        hkdf.expand(b"mac", mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        let keys = crate::locked::Keys::new(keys);
        let master_password_hash = crate::locked::PasswordHash::new(hash);

        Ok(Self {
            email: email.clone(),
            keys,
            master_password_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_settings_from_the_server_are_checked() {
        let params = argon2_params(Some(64), 3, Some(4)).unwrap();
        assert_eq!(params.m_cost(), 64 * 1024);
        assert_eq!(params.t_cost(), 3);
        assert_eq!(params.p_cost(), 4);
        assert!(
            argon2_params(Some(ARGON2_MAX_MEMORY_MIB), 3, Some(4)).is_ok()
        );

        for (memory, iterations, parallelism) in [
            (None, 3, Some(4)),
            (Some(64), 3, None),
            (Some(0), 3, Some(4)),
            (Some(ARGON2_MAX_MEMORY_MIB + 1), 3, Some(4)),
            // would overflow when converted to KiB
            (Some(u32::MAX), 3, Some(4)),
            (Some(64), 3, Some(0)),
            (Some(64), 3, Some(u32::MAX)),
        ] {
            assert!(
                matches!(
                    argon2_params(memory, iterations, parallelism),
                    Err(Error::Argon2)
                ),
                "{memory:?} {iterations} {parallelism:?}"
            );
        }
    }

    #[test]
    fn missing_argon2_settings_fail_instead_of_panicking() {
        let mut password = crate::locked::Vec::new();
        password.extend(b"hunter2".iter().copied());
        let password = crate::locked::Password::new(password);
        for (memory, parallelism) in
            [(None, Some(4)), (Some(64), None), (Some(u32::MAX), Some(4))]
        {
            assert!(matches!(
                Identity::new(
                    "me@example.com",
                    &password,
                    crate::api::KdfType::Argon2id,
                    3,
                    memory,
                    parallelism,
                ),
                Err(Error::Argon2)
            ));
        }
    }
}
