use crate::prelude::*;

use aes::cipher::{
    BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _,
};
use hmac::Mac as _;
use pkcs8::DecodePrivateKey as _;
use rand::RngCore as _;
use sha2::Digest as _;
use zeroize::Zeroize as _;

pub enum CipherString {
    Symmetric {
        // ty: 2 (AES_256_CBC_HMAC_SHA256), always with its MAC: without it,
        // anyone could have changed the ciphertext
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
    },
    Asymmetric {
        // ty: 4 (RSA_2048_OAEP_SHA1)
        ciphertext: Vec<u8>,
    },
}

impl CipherString {
    pub fn new(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidCipherString {
                reason: "couldn't find type".to_string(),
            });
        }

        let ty = parts[0].as_bytes();
        if ty.len() != 1 {
            return Err(Error::UnimplementedCipherStringType {
                ty: parts[0].to_string(),
            });
        }

        let ty = ty[0].wrapping_sub(b'0');
        let contents = parts[1];

        match ty {
            2 => {
                let parts: Vec<&str> = contents.split('|').collect();
                if parts.len() != 3 {
                    return Err(Error::InvalidCipherString {
                        reason: format!(
                            "type 2 cipherstring with {} parts",
                            parts.len()
                        ),
                    });
                }

                let decode = |part| {
                    crate::base64::decode(part)
                        .map_err(|source| Error::InvalidBase64 { source })
                };
                let iv = decode(parts[0])?;
                let ciphertext = decode(parts[1])?;
                let mac = decode(parts[2])?;
                if iv.len() != 16 || mac.len() != 32 {
                    return Err(Error::InvalidCipherString {
                        reason: "type 2 cipherstring with a wrong IV or MAC \
                                 length"
                            .to_string(),
                    });
                }

                Ok(Self::Symmetric {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            4 | 6 => {
                // the only difference between 4 and 6 is the HMAC256
                // signature appended at the end
                // https://github.com/bitwarden/jslib/blob/785b681f61f81690de6df55159ab07ae710bcfad/src/enums/encryptionType.ts#L8
                // format is: <cipher_text_b64>|<hmac_sig>
                let contents = contents.split('|').next().unwrap();
                let ciphertext = crate::base64::decode(contents)
                    .map_err(|source| Error::InvalidBase64 { source })?;
                Ok(Self::Asymmetric { ciphertext })
            }
            _ => {
                if ty < 6 {
                    Err(Error::TooOldCipherStringType { ty: ty.to_string() })
                } else {
                    Err(Error::UnimplementedCipherStringType {
                        ty: ty.to_string(),
                    })
                }
            }
        }
    }

    pub fn encrypt_symmetric(
        keys: &crate::locked::Keys,
        plaintext: &[u8],
    ) -> Result<Self> {
        let iv = random_iv();

        let cipher = cbc::Encryptor::<aes::Aes256>::new(
            keys.enc_key().into(),
            iv.as_slice().into(),
        );
        let ciphertext =
            cipher.encrypt_padded_vec_mut::<block_padding::Pkcs7>(plaintext);

        let mut digest =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(keys.mac_key())
                .map_err(|source| Error::CreateHmac { source })?;
        digest.update(&iv);
        digest.update(&ciphertext);
        let mac = digest.finalize().into_bytes().as_slice().to_vec();

        Ok(Self::Symmetric {
            iv,
            ciphertext,
            mac,
        })
    }

    // Identifies the encrypted value whatever text it came as: the same IV
    // and ciphertext decrypt to the same plaintext.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut digest = sha2::Sha256::new();
        match self {
            Self::Symmetric { iv, ciphertext, .. } => {
                digest.update([2]);
                digest.update(iv);
                digest.update(ciphertext);
            }
            Self::Asymmetric { ciphertext } => {
                digest.update([4]);
                digest.update(ciphertext);
            }
        }
        digest.finalize().into()
    }

    pub fn decrypt_symmetric(
        &self,
        keys: &crate::locked::Keys,
        entry_key: Option<&crate::locked::Keys>,
    ) -> Result<Vec<u8>> {
        if let Self::Symmetric {
            iv,
            ciphertext,
            mac,
        } = self
        {
            let cipher = decrypt_common_symmetric(
                entry_key.unwrap_or(keys),
                iv,
                ciphertext,
                mac,
            )?;
            cipher
                .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
                .map_err(|source| Error::Decrypt { source })
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            })
        }
    }

    pub fn decrypt_locked_symmetric(
        &self,
        keys: &crate::locked::Keys,
    ) -> Result<crate::locked::Vec> {
        if let Self::Symmetric {
            iv,
            ciphertext,
            mac,
        } = self
        {
            let mut res = crate::locked::Vec::new();
            res.extend(ciphertext.iter().copied());
            let cipher = decrypt_common_symmetric(keys, iv, ciphertext, mac)?;
            cipher
                .decrypt_padded_mut::<block_padding::Pkcs7>(res.data_mut())
                .map_err(|source| Error::Decrypt { source })?;
            Ok(res)
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found an asymmetric cipherstring, expecting symmetric"
                        .to_string(),
            })
        }
    }

    pub fn decrypt_locked_asymmetric(
        &self,
        private_key: &crate::locked::PrivateKey,
    ) -> Result<crate::locked::Vec> {
        if let Self::Asymmetric { ciphertext } = self {
            let privkey_data = private_key.private_key();
            let privkey_data =
                pkcs7_unpad(privkey_data).ok_or(Error::Padding)?;
            let pkey = rsa::RsaPrivateKey::from_pkcs8_der(privkey_data)
                .map_err(|source| Error::RsaPkcs8 { source })?;
            let mut bytes = pkey
                .decrypt(rsa::Oaep::new::<sha1::Sha1>(), ciphertext)
                .map_err(|source| Error::Rsa { source })?;

            // XXX it'd be great if the rsa crate would let us decrypt
            // into a preallocated buffer directly to avoid the
            // intermediate vec that needs to be manually zeroized, etc
            let mut res = crate::locked::Vec::new();
            res.extend(bytes.iter().copied());
            bytes.zeroize();

            Ok(res)
        } else {
            Err(Error::InvalidCipherString {
                reason:
                    "found a symmetric cipherstring, expecting asymmetric"
                        .to_string(),
            })
        }
    }
}

fn decrypt_common_symmetric(
    keys: &crate::locked::Keys,
    iv: &[u8],
    ciphertext: &[u8],
    mac: &[u8],
) -> Result<cbc::Decryptor<aes::Aes256>> {
    let mut key = hmac::Hmac::<sha2::Sha256>::new_from_slice(keys.mac_key())
        .map_err(|source| Error::CreateHmac { source })?;
    key.update(iv);
    key.update(ciphertext);
    if key.verify(mac.into()).is_err() {
        return Err(Error::InvalidMac);
    }

    cbc::Decryptor::<aes::Aes256>::new_from_slices(keys.enc_key(), iv)
        .map_err(|source| Error::CreateBlockMode { source })
}

impl std::fmt::Display for CipherString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Symmetric {
                iv,
                ciphertext,
                mac,
            } => {
                let iv = crate::base64::encode(iv);
                let ciphertext = crate::base64::encode(ciphertext);
                let mac = crate::base64::encode(mac);
                write!(f, "2.{iv}|{ciphertext}|{mac}")
            }
            Self::Asymmetric { ciphertext } => {
                let ciphertext = crate::base64::encode(ciphertext);
                write!(f, "4.{ciphertext}")
            }
        }
    }
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0_u8; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut iv);
    iv
}

// XXX this should ideally just be block_padding::Pkcs7::unpad, but i can't
// figure out how to get the generic types to work out
fn pkcs7_unpad(b: &[u8]) -> Option<&[u8]> {
    if b.is_empty() {
        return None;
    }

    let padding_val = b[b.len() - 1];
    if padding_val == 0 {
        return None;
    }

    let padding_len = usize::from(padding_val);
    if padding_len > b.len() {
        return None;
    }

    for c in b.iter().copied().skip(b.len() - padding_len) {
        if c != padding_val {
            return None;
        }
    }

    Some(&b[..b.len() - padding_len])
}

#[test]
fn test_pkcs7_unpad() {
    let tests = [
        (&[][..], None),
        (&[0x01][..], Some(&[][..])),
        (&[0x02, 0x02][..], Some(&[][..])),
        (&[0x03, 0x03, 0x03][..], Some(&[][..])),
        (&[0x69, 0x01][..], Some(&[0x69][..])),
        (&[0x69, 0x02, 0x02][..], Some(&[0x69][..])),
        (&[0x69, 0x03, 0x03, 0x03][..], Some(&[0x69][..])),
        (&[0x02][..], None),
        (&[0x03][..], None),
        (&[0x69, 0x69, 0x03, 0x03][..], None),
        (&[0x00][..], None),
        (&[0x02, 0x00][..], None),
    ];
    for (input, expected) in tests {
        let got = pkcs7_unpad(input);
        assert_eq!(got, expected);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn keys() -> crate::locked::Keys {
        let mut keys = crate::locked::Vec::new();
        keys.extend((0..64).map(|i: u8| i.wrapping_mul(37)));
        crate::locked::Keys::new(keys)
    }

    #[test]
    fn a_symmetric_cipherstring_needs_its_mac() {
        let keys = keys();
        let encrypted = CipherString::encrypt_symmetric(&keys, b"hunter2")
            .unwrap()
            .to_string();
        let parsed = CipherString::new(&encrypted).unwrap();
        assert_eq!(
            parsed.decrypt_symmetric(&keys, None).unwrap(),
            b"hunter2"
        );

        let (without_mac, _) = encrypted.rsplit_once('|').unwrap();
        assert!(matches!(
            CipherString::new(without_mac),
            Err(Error::InvalidCipherString { .. })
        ));
        let (start, mac) = encrypted.rsplit_once('|').unwrap();
        let mut mac = crate::base64::decode(mac).unwrap();
        mac[0] ^= 1;
        let tampered = format!("{start}|{}", crate::base64::encode(&mac));
        assert!(matches!(
            CipherString::new(&tampered)
                .unwrap()
                .decrypt_symmetric(&keys, None),
            Err(Error::InvalidMac)
        ));
        for broken in ["2.", "2.a|b", "!.x", "2.AAAA|AAAA|AAAA"] {
            assert!(CipherString::new(broken).is_err(), "{broken}");
        }
    }

    #[test]
    fn fingerprints_ignore_the_text_and_the_mac() {
        let keys = keys();
        let encrypted =
            CipherString::encrypt_symmetric(&keys, b"hunter2").unwrap();
        let other =
            CipherString::encrypt_symmetric(&keys, b"hunter2").unwrap();
        assert_ne!(encrypted.fingerprint(), other.fingerprint());
        let CipherString::Symmetric { iv, ciphertext, .. } = &encrypted
        else {
            unreachable!();
        };
        let same = CipherString::Symmetric {
            iv: iv.clone(),
            ciphertext: ciphertext.clone(),
            mac: vec![0; 32],
        };
        assert_eq!(encrypted.fingerprint(), same.fingerprint());
    }
}
