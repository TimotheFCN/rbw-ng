// Which values need the master password again before the agent decrypts
// them.
//
// The agent decrypts single cipherstrings, without knowing the entry they
// come from, so it recognizes the protected ones by their fingerprint
// (CipherString::fingerprint): a value that doesn't decrypt without its
// MAC, and whose fingerprint doesn't change with the text it comes as.
//
// The entries' reprompt flags are neither encrypted nor authenticated, and
// the local copy of the vault is a file that any program of the user can
// change. So the agent takes them only from what it synced from the server
// itself, and from a local copy that carries the agent's MAC of them, which
// needs the vault key: an agent started later can then answer without
// syncing first. A local copy without a valid MAC makes the agent sync
// before it decrypts anything. The MAC is checked against the entries, so
// one that outlived a change of the flags vouches for nothing.

use hmac::Mac as _;

// fingerprint -> the id of the entry that keeps the value closed
pub type Protected = std::collections::HashMap<[u8; 32], String>;

pub fn protected(entries: &[rbw::db::Entry]) -> Protected {
    entries
        .iter()
        .filter(|entry| entry.master_password_reprompt())
        .flat_map(|entry| {
            entry.protected_values().into_iter().filter_map(|value| {
                // a value that doesn't parse can't be decrypted either
                let cipherstring =
                    rbw::cipherstring::CipherString::new(value).ok()?;
                Some((cipherstring.fingerprint(), entry.id.clone()))
            })
        })
        .collect()
}

pub fn mac(keys: &rbw::locked::Keys, protected: &Protected) -> String {
    rbw::base64::encode(digest(keys, protected).finalize().into_bytes())
}

pub fn verify(
    keys: &rbw::locked::Keys,
    protected: &Protected,
    mac: &str,
) -> bool {
    rbw::base64::decode(mac)
        .is_ok_and(|mac| digest(keys, protected).verify_slice(&mac).is_ok())
}

fn digest(
    keys: &rbw::locked::Keys,
    protected: &Protected,
) -> hmac::Hmac<sha2::Sha256> {
    // a key of its own, so that no other MAC the vault key makes, such as
    // the ones of the cipherstrings the agent encrypts, can pass for this one
    let mut key = [0; 32];
    hkdf::Hkdf::<sha2::Sha256>::from_prk(keys.mac_key())
        .expect("the MAC key is as long as a SHA-256 hash")
        .expand(b"rbw-ng master password reprompt", &mut key)
        .expect("32 bytes is a valid length for HKDF-SHA256");
    let mut digest = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key)
        .expect("HMAC takes keys of any length");
    let mut sorted: Vec<_> = protected.iter().collect();
    sorted.sort();
    for (fingerprint, id) in sorted {
        digest.update(fingerprint);
        digest.update(
            &u64::try_from(id.len()).unwrap_or(u64::MAX).to_be_bytes(),
        );
        digest.update(id.as_bytes());
    }
    digest
}

#[cfg(test)]
mod test {
    use super::*;

    fn keys(seed: u8) -> rbw::locked::Keys {
        let mut keys = rbw::locked::Vec::new();
        keys.extend((0..64).map(|i: u8| i.wrapping_mul(seed)));
        rbw::locked::Keys::new(keys)
    }

    fn encrypt(keys: &rbw::locked::Keys, text: &str) -> String {
        rbw::cipherstring::CipherString::encrypt_symmetric(
            keys,
            text.as_bytes(),
        )
        .unwrap()
        .to_string()
    }

    fn entry(
        keys: &rbw::locked::Keys,
        id: &str,
        data: rbw::db::EntryData,
    ) -> rbw::db::Entry {
        rbw::db::Entry {
            id: id.to_string(),
            org_id: None,
            folder: None,
            folder_id: None,
            name: encrypt(keys, id),
            data,
            fields: vec![rbw::db::Field {
                ty: Some(rbw::api::FieldType::Text),
                name: Some(encrypt(keys, "PIN")),
                value: Some(encrypt(keys, "1234")),
                linked_id: None,
            }],
            notes: Some(encrypt(keys, "notes")),
            history: vec![rbw::db::HistoryEntry {
                last_used_date: "2026-01-01T00:00:00Z".to_string(),
                password: encrypt(keys, "old"),
            }],
            key: None,
            master_password_reprompt: rbw::api::CipherRepromptType::Password,
            revision_date: None,
            favorite: false,
            archived: false,
            read_only: false,
        }
    }

    // One entry of each type, with every value set.
    fn entries(keys: &rbw::locked::Keys) -> Vec<rbw::db::Entry> {
        let value = |text: &str| Some(encrypt(keys, text));
        vec![
            entry(
                keys,
                "login",
                rbw::db::EntryData::Login {
                    username: value("username"),
                    password: value("password"),
                    totp: value("totp"),
                    uris: vec![rbw::db::Uri {
                        uri: encrypt(keys, "https://example.com"),
                        match_type: None,
                        uri_checksum: None,
                    }],
                },
            ),
            entry(
                keys,
                "card",
                rbw::db::EntryData::Card {
                    cardholder_name: value("cardholder"),
                    number: value("4111111111111111"),
                    brand: value("Visa"),
                    exp_month: value("09"),
                    exp_year: value("2029"),
                    code: value("123"),
                },
            ),
            entry(
                keys,
                "identity",
                rbw::db::EntryData::Identity {
                    title: value("title"),
                    first_name: value("first"),
                    middle_name: value("middle"),
                    last_name: value("last"),
                    address1: value("address1"),
                    address2: value("address2"),
                    address3: value("address3"),
                    city: value("city"),
                    state: value("state"),
                    postal_code: value("postal"),
                    country: value("country"),
                    phone: value("phone"),
                    email: value("email"),
                    ssn: value("ssn"),
                    license_number: value("license"),
                    passport_number: value("passport"),
                    username: value("identity username"),
                },
            ),
            entry(keys, "note", rbw::db::EntryData::SecureNote),
            entry(
                keys,
                "ssh",
                rbw::db::EntryData::SshKey {
                    private_key: value("private key"),
                    public_key: value("public key"),
                    fingerprint: value("fingerprint"),
                },
            ),
        ]
    }

    fn plaintexts(
        keys: &rbw::locked::Keys,
        values: &[&str],
    ) -> std::collections::BTreeSet<String> {
        values
            .iter()
            .map(|value| {
                let decrypted = rbw::cipherstring::CipherString::new(value)
                    .unwrap()
                    .decrypt_symmetric(keys, None)
                    .unwrap();
                String::from_utf8(decrypted).unwrap()
            })
            .collect()
    }

    #[test]
    fn everything_but_what_a_list_shows_is_protected() {
        let keys = keys(37);
        let entries = entries(&keys);
        for (entry, listed) in entries.iter().zip([
            vec!["login", "username", "https://example.com"],
            vec!["card", "Visa"],
            vec!["identity", "title", "first", "middle", "last"],
            vec!["note"],
            vec!["ssh", "public key", "fingerprint"],
        ]) {
            let protected = plaintexts(&keys, &entry.protected_values());
            for common in ["notes", "PIN", "1234", "old"] {
                assert!(protected.contains(common), "{}: {common}", entry.id);
            }
            for listed in listed {
                assert!(
                    !protected.contains(listed),
                    "{}: {listed}",
                    entry.id
                );
            }
        }
        let all: Vec<_> = plaintexts(
            &keys,
            &entries
                .iter()
                .flat_map(rbw::db::Entry::protected_values)
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .collect();
        for secret in [
            "password",
            "totp",
            "cardholder",
            "4111111111111111",
            "09",
            "2029",
            "123",
            "address1",
            "phone",
            "email",
            "ssn",
            "passport",
            "identity username",
            "private key",
        ] {
            assert!(all.iter().any(|value| value == secret), "{secret}");
        }
    }

    #[test]
    fn the_mac_vouches_for_the_flags_with_the_vault_key() {
        let keys = keys(37);
        let mut entries = entries(&keys);
        let protected = protected(&entries);
        let mac = mac(&keys, &protected);
        assert!(verify(&keys, &protected, &mac));
        assert!(verify(&keys, &super::protected(&entries), &mac));

        // a local copy edited to turn the reprompt off
        entries[0].master_password_reprompt =
            rbw::api::CipherRepromptType::None;
        assert!(!verify(&keys, &super::protected(&entries), &mac));
        // or to move a protected value into another entry
        let mut moved = self::entries(&keys);
        moved[3].notes = moved[0].notes.take();
        assert!(!verify(&keys, &super::protected(&moved), &mac));

        assert!(!verify(&self::keys(41), &protected, &mac));
        assert!(!verify(&keys, &protected, "not base64!"));
    }
}
