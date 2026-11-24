// rbw item: entries as JSON in Bitwarden's item format, the format of the
// official CLI and of Bitwarden's JSON export, for programs that drive rbw.
// Entries are found by id only, never by name. See docs/scripting.md.

use anyhow::Context as _;
use serde_json::{json, Value};

const LOGIN: u8 = 1;
const SECURE_NOTE: u8 = 2;
const CARD: u8 = 3;
const IDENTITY: u8 = 4;
const SSH_KEY: u8 = 5;

// Opens one cipherstring of an entry. The JSON is built twice with the same
// entry: once to collect every cipherstring it needs, then with the
// plaintexts, so the whole list takes one request to the agent.
type Open<'a> =
    dyn FnMut(&rbw::db::Entry, Option<&str>) -> Option<String> + 'a;

fn type_id(data: &rbw::db::EntryData) -> u8 {
    match data {
        rbw::db::EntryData::Login { .. } => LOGIN,
        rbw::db::EntryData::SecureNote => SECURE_NOTE,
        rbw::db::EntryData::Card { .. } => CARD,
        rbw::db::EntryData::Identity { .. } => IDENTITY,
        rbw::db::EntryData::SshKey { .. } => SSH_KEY,
    }
}

// Without secrets: no password, code, notes, custom fields or history,
// and a login says whether it has a code in hasTotp.
fn item_json(
    entry: &rbw::db::Entry,
    secrets: bool,
    open: &mut Open,
) -> Value {
    let mut item = json!({
        "object": "item",
        "id": entry.id,
        "organizationId": entry.org_id,
        "folderId": entry.folder_id,
        "type": type_id(&entry.data),
        "reprompt": u8::from(entry.master_password_reprompt()),
        "name": open(entry, Some(&entry.name)),
        "favorite": entry.favorite,
        "revisionDate": entry.revision_date,
        "deletedDate": null,
    });
    if secrets {
        item["notes"] = json!(open(entry, entry.notes.as_deref()));
        item["fields"] = entry
            .fields
            .iter()
            .map(|field| {
                json!({
                    "name": open(entry, field.name.as_deref()),
                    "value": open(entry, field.value.as_deref()),
                    "type": field.ty,
                    "linkedId": field.linked_id,
                })
            })
            .collect();
        item["passwordHistory"] = entry
            .history
            .iter()
            .map(|history| {
                json!({
                    "lastUsedDate": history.last_used_date,
                    "password": open(entry, Some(&history.password)),
                })
            })
            .collect();
    }
    match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            let uris: Vec<_> = uris
                .iter()
                .map(|uri| {
                    json!({
                        "match": uri.match_type,
                        "uri": open(entry, Some(&uri.uri)),
                    })
                })
                .collect();
            let mut login = json!({
                "username": open(entry, username.as_deref()),
                "uris": uris,
                "hasTotp": totp.is_some(),
            });
            if secrets {
                login["password"] = json!(open(entry, password.as_deref()));
                login["totp"] = json!(open(entry, totp.as_deref()));
            }
            item["login"] = login;
        }
        rbw::db::EntryData::SecureNote => {
            item["secureNote"] = json!({ "type": 0 });
        }
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } if secrets => {
            item["card"] = json!({
                "cardholderName": open(entry, cardholder_name.as_deref()),
                "brand": open(entry, brand.as_deref()),
                "number": open(entry, number.as_deref()),
                "expMonth": open(entry, exp_month.as_deref()),
                "expYear": open(entry, exp_year.as_deref()),
                "code": open(entry, code.as_deref()),
            });
        }
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } if secrets => {
            item["identity"] = json!({
                "title": open(entry, title.as_deref()),
                "firstName": open(entry, first_name.as_deref()),
                "middleName": open(entry, middle_name.as_deref()),
                "lastName": open(entry, last_name.as_deref()),
                "address1": open(entry, address1.as_deref()),
                "address2": open(entry, address2.as_deref()),
                "address3": open(entry, address3.as_deref()),
                "city": open(entry, city.as_deref()),
                "state": open(entry, state.as_deref()),
                "postalCode": open(entry, postal_code.as_deref()),
                "country": open(entry, country.as_deref()),
                "phone": open(entry, phone.as_deref()),
                "email": open(entry, email.as_deref()),
                "ssn": open(entry, ssn.as_deref()),
                "licenseNumber": open(entry, license_number.as_deref()),
                "passportNumber": open(entry, passport_number.as_deref()),
                "username": open(entry, username.as_deref()),
            });
        }
        rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } if secrets => {
            item["sshKey"] = json!({
                "privateKey": open(entry, private_key.as_deref()),
                "publicKey": open(entry, public_key.as_deref()),
                "keyFingerprint": open(entry, fingerprint.as_deref()),
            });
        }
        _ => {}
    }
    item
}

// The JSON of each entry, decrypted with one request to the agent.
fn items_json(
    entries: &[&rbw::db::Entry],
    secrets: bool,
) -> anyhow::Result<Vec<Value>> {
    let mut wanted = vec![];
    for entry in entries {
        item_json(entry, secrets, &mut |entry, cipherstring| {
            if let Some(cipherstring) = cipherstring {
                wanted.push(rbw::protocol::DecryptItem {
                    cipherstring: cipherstring.to_string(),
                    entry_key: entry.key.clone(),
                    org_id: entry.org_id.clone(),
                });
            }
            None
        });
    }
    let mut plaintexts = crate::actions::decrypt_many(wanted)?.into_iter();
    let mut failed = None;
    let items = entries
        .iter()
        .map(|entry| {
            item_json(entry, secrets, &mut |entry, cipherstring| {
                cipherstring?;
                match plaintexts.next()? {
                    Ok(plaintext) => Some(plaintext),
                    Err(error) => {
                        failed.get_or_insert_with(|| {
                            format!("failed to decrypt {}: {error}", entry.id)
                        });
                        None
                    }
                }
            })
        })
        .collect();
    if let Some(failed) = failed {
        anyhow::bail!(failed);
    }
    Ok(items)
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    serde_json::to_writer(std::io::stdout(), value)
        .context("failed to write the JSON")?;
    println!();
    Ok(())
}

fn find<'a>(
    db: &'a rbw::db::Db,
    id: &str,
) -> anyhow::Result<&'a rbw::db::Entry> {
    db.entries
        .iter()
        .find(|entry| entry.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| anyhow::anyhow!("not found"))
}

pub fn list(secrets: bool) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    // archived entries stay out of lists, as in the official clients
    let entries: Vec<_> =
        db.entries.iter().filter(|entry| !entry.archived).collect();
    print_json(&Value::Array(items_json(&entries, secrets)?))
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Field {
    Username,
    Password,
    // the current code
    Totp,
    Notes,
}

pub fn get(id: &str, field: Option<Field>) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    let Some(field) = field else {
        let item = items_json(&[entry], true)?.remove(0);
        return print_json(&item);
    };
    let (cipherstring, name) = match (&entry.data, field) {
        (rbw::db::EntryData::Login { username, .. }, Field::Username) => {
            (username.as_deref(), "username")
        }
        (rbw::db::EntryData::Login { password, .. }, Field::Password) => {
            (password.as_deref(), "password")
        }
        (rbw::db::EntryData::Login { totp, .. }, Field::Totp) => {
            (totp.as_deref(), "totp")
        }
        (_, Field::Notes) => (entry.notes.as_deref(), "notes"),
        (_, Field::Username) => (None, "username"),
        (_, Field::Password) => (None, "password"),
        (_, Field::Totp) => (None, "totp"),
    };
    let Some(cipherstring) = cipherstring else {
        anyhow::bail!("no {name} available");
    };
    let mut value =
        crate::actions::decrypt_many(vec![rbw::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry.key.clone(),
            org_id: entry.org_id.clone(),
        }])?
        .remove(0)
        .map_err(|error| anyhow::anyhow!("failed to decrypt: {error}"))?;
    if matches!(field, Field::Totp) {
        value = rbw::totp::current(&value)?.code;
    }
    println!("{value}");
    Ok(())
}

// An item as a program sends it, in Bitwarden's format. Other keys, such
// as object, id or collectionIds, are ignored.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ItemIn {
    #[serde(rename = "type")]
    ty: u8,
    id: Option<String>,
    name: String,
    notes: Option<String>,
    folder_id: Option<String>,
    organization_id: Option<String>,
    login: Option<LoginIn>,
    #[serde(default)]
    fields: Option<Vec<FieldIn>>,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LoginIn {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<UriIn>>,
    fido2_credentials: Option<Vec<Value>>,
}

#[derive(serde::Deserialize, Debug)]
struct UriIn {
    uri: Option<String>,
    #[serde(rename = "match")]
    match_type: Option<rbw::api::UriMatchType>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FieldIn {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    ty: rbw::api::FieldType,
    linked_id: Option<rbw::api::LinkedIdType>,
}

// The item on stdin: JSON, or base64 JSON as bw encode makes it.
fn read_item(input: &str) -> anyhow::Result<ItemIn> {
    let text = input.trim();
    let json = if text.starts_with('{') {
        text.to_string()
    } else {
        String::from_utf8(
            rbw::base64::decode(text)
                .context("the item on stdin isn't JSON or base64 JSON")?,
        )
        .context("the item on stdin isn't UTF-8")?
    };
    let item: ItemIn = serde_json::from_str(&json)
        .context("the item on stdin isn't a Bitwarden item")?;
    if item.organization_id.is_some() {
        anyhow::bail!("items in organizations aren't supported yet");
    }
    if item
        .login
        .as_ref()
        .and_then(|login| login.fido2_credentials.as_ref())
        .is_some_and(|credentials| !credentials.is_empty())
    {
        anyhow::bail!("passkeys aren't supported yet");
    }
    match item.ty {
        LOGIN | SECURE_NOTE => Ok(item),
        _ => anyhow::bail!("only logins and secure notes can be saved"),
    }
}

fn read_stdin_item() -> anyhow::Result<ItemIn> {
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
        .context("failed to read the item from stdin")?;
    read_item(&input)
}

// Encrypts a value for an entry; the official clients store an empty value
// as null.
fn encrypt(
    value: Option<&str>,
    entry: Option<&rbw::db::Entry>,
) -> anyhow::Result<Option<String>> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            crate::actions::encrypt(
                value,
                entry.and_then(|entry| entry.key.as_deref()),
                entry.and_then(|entry| entry.org_id.as_deref()),
            )
        })
        .transpose()
}

fn encrypt_fields(
    fields: &[FieldIn],
    entry: Option<&rbw::db::Entry>,
) -> anyhow::Result<Vec<rbw::db::Field>> {
    fields
        .iter()
        .map(|field| {
            Ok(rbw::db::Field {
                ty: Some(field.ty),
                name: encrypt(field.name.as_deref(), entry)?,
                value: encrypt(field.value.as_deref(), entry)?,
                linked_id: field.linked_id,
            })
        })
        .collect()
}

fn encrypt_uris(
    login: &LoginIn,
    entry: Option<&rbw::db::Entry>,
) -> anyhow::Result<Vec<rbw::db::Uri>> {
    login
        .uris
        .iter()
        .flatten()
        .filter_map(|uri| {
            let text = uri.uri.as_deref().filter(|text| !text.is_empty())?;
            Some(crate::commands::encrypt_uri(
                text,
                uri.match_type,
                entry.and_then(|entry| entry.key.as_deref()),
                entry.and_then(|entry| entry.org_id.as_deref()),
            ))
        })
        .collect()
}

// After a change: the item as the server saved it, from a fresh sync,
// without its secrets.
fn print_saved(id: &str) -> anyhow::Result<()> {
    crate::actions::sync()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    print_json(&items_json(&[entry], false)?.remove(0))
}

fn tokens(db: &rbw::db::Db) -> anyhow::Result<(String, String)> {
    let (Some(access_token), Some(refresh_token)) =
        (db.access_token.clone(), db.refresh_token.clone())
    else {
        anyhow::bail!("not logged in");
    };
    Ok((access_token, refresh_token))
}

pub fn create() -> anyhow::Result<()> {
    let item = read_stdin_item()?;
    crate::commands::unlock()?;
    let mut db = crate::commands::load_db()?;
    if db.user_id.is_none() {
        crate::actions::sync()
            .context("failed to sync user id before adding entry")?;
        db = crate::commands::load_db()?;
    }
    let user_id = crate::commands::user_id(&db)?.to_string();
    let (access_token, refresh_token) = tokens(&db)?;

    let name = crate::actions::encrypt(&item.name, None, None)?;
    let notes = encrypt(item.notes.as_deref(), None)?;
    let fields = encrypt_fields(item.fields.as_deref().unwrap_or(&[]), None)?;
    let data = if item.ty == LOGIN {
        let login = item.login.unwrap_or_default();
        rbw::db::EntryData::Login {
            username: encrypt(login.username.as_deref(), None)?,
            password: encrypt(login.password.as_deref(), None)?,
            totp: encrypt(login.totp.as_deref(), None)?,
            uris: encrypt_uris(&login, None)?,
        }
    } else {
        rbw::db::EntryData::SecureNote
    };
    let (_, saved) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &user_id,
        &name,
        &data,
        &fields,
        notes.as_deref(),
        item.folder_id.as_deref(),
    )?;
    print_saved(&saved.id)
}

pub fn edit(id: &str) -> anyhow::Result<()> {
    let item = read_stdin_item()?;
    if item
        .id
        .as_deref()
        .is_some_and(|given| !given.eq_ignore_ascii_case(id))
    {
        anyhow::bail!("the item on stdin has another id");
    }
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    if type_id(&entry.data) != item.ty {
        anyhow::bail!("an item's type can't change");
    }
    let user_id = crate::commands::user_id(&db)?.to_string();
    let (access_token, refresh_token) = tokens(&db)?;

    let name = crate::actions::encrypt(
        &item.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let notes = encrypt(item.notes.as_deref(), Some(entry))?;
    let fields =
        encrypt_fields(item.fields.as_deref().unwrap_or(&[]), Some(entry))?;
    let mut history = entry.history.clone();
    let data = match &entry.data {
        rbw::db::EntryData::Login {
            password: old_password,
            ..
        } => {
            let login = item.login.unwrap_or_default();
            let current = old_password
                .as_deref()
                .map(|cipherstring| {
                    crate::actions::decrypt_many(vec![
                        rbw::protocol::DecryptItem {
                            cipherstring: cipherstring.to_string(),
                            entry_key: entry.key.clone(),
                            org_id: entry.org_id.clone(),
                        },
                    ])
                    .map(|mut plaintexts| plaintexts.remove(0).ok())
                })
                .transpose()?
                .flatten();
            rbw::db::EntryData::Login {
                username: encrypt(login.username.as_deref(), Some(entry))?,
                password: crate::commands::edit_password(
                    entry,
                    old_password.as_deref(),
                    current.as_deref(),
                    login.password.as_deref(),
                    &mut history,
                )?,
                totp: encrypt(login.totp.as_deref(), Some(entry))?,
                uris: encrypt_uris(&login, Some(entry))?,
            }
        }
        _ => rbw::db::EntryData::SecureNote,
    };
    rbw::actions::edit(
        &access_token,
        &refresh_token,
        &user_id,
        &entry.id,
        entry.org_id.as_deref(),
        &name,
        &data,
        &fields,
        notes.as_deref(),
        item.folder_id.as_deref(),
        &history,
        entry.key.as_deref(),
        entry.revision_date.as_deref(),
    )?;
    print_saved(&entry.id)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn reads_items_as_json_or_base64() {
        let item = r#"{"type":1,"name":"GitHub","login":{"username":"me","uris":[{"uri":"https://github.com","match":null}]}}"#;
        let read = read_item(item).unwrap();
        assert_eq!(read.name, "GitHub");
        let encoded = rbw::base64::encode(item.as_bytes());
        assert_eq!(read_item(&encoded).unwrap().name, "GitHub");
        assert!(read_item("not json").is_err());
    }

    #[test]
    fn refuses_what_it_cant_save() {
        for item in [
            r#"{"type":3,"name":"Card"}"#,
            r#"{"type":1,"name":"x","organizationId":"org"}"#,
            r#"{"type":1,"name":"x","login":{"fido2Credentials":[{}]}}"#,
        ] {
            assert!(read_item(item).is_err(), "{item}");
        }
        assert!(read_item(
            r#"{"type":1,"name":"x","login":{"fido2Credentials":[]}}"#
        )
        .is_ok());
    }
}
