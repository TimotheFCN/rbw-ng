// rbw item and rbw folder: entries and folders as JSON in Bitwarden's
// format, the format of the official CLI and of Bitwarden's JSON export, for
// programs that drive rbw. They are found by id only, never by name. See
// docs/scripting.md.

use anyhow::Context as _;
use rbw::error::coded;
use rbw::protocol::ErrorCode;
use serde_json::{json, Value};

const LOGIN: u8 = 1;
const SECURE_NOTE: u8 = 2;
const CARD: u8 = 3;
const IDENTITY: u8 = 4;
const SSH_KEY: u8 = 5;

// Opens one cipherstring of an entry. collect_entry_cipherstrings lists
// every cipherstring the JSON of an entry needs, in the order item_json
// opens them, so that the whole list takes one request to the agent, and
// item_json then builds the JSON with the plaintexts.
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
        "edit": !entry.read_only,
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
        } => {
            let mut card = json!({ "brand": open(entry, brand.as_deref()) });
            if secrets {
                card["cardholderName"] =
                    json!(open(entry, cardholder_name.as_deref()));
                card["number"] = json!(open(entry, number.as_deref()));
                card["expMonth"] = json!(open(entry, exp_month.as_deref()));
                card["expYear"] = json!(open(entry, exp_year.as_deref()));
                card["code"] = json!(open(entry, code.as_deref()));
            }
            item["card"] = card;
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
        } => {
            let mut identity = json!({
                "title": open(entry, title.as_deref()),
                "firstName": open(entry, first_name.as_deref()),
                "middleName": open(entry, middle_name.as_deref()),
                "lastName": open(entry, last_name.as_deref()),
            });
            if secrets {
                for (key, value) in [
                    ("address1", address1),
                    ("address2", address2),
                    ("address3", address3),
                    ("city", city),
                    ("state", state),
                    ("postalCode", postal_code),
                    ("country", country),
                    ("phone", phone),
                    ("email", email),
                    ("ssn", ssn),
                    ("licenseNumber", license_number),
                    ("passportNumber", passport_number),
                    ("username", username),
                ] {
                    identity[key] = json!(open(entry, value.as_deref()));
                }
            }
            item["identity"] = identity;
        }
        rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            let mut key = json!({
                "publicKey": open(entry, public_key.as_deref()),
                "keyFingerprint": open(entry, fingerprint.as_deref()),
            });
            if secrets {
                key["privateKey"] =
                    json!(open(entry, private_key.as_deref()));
            }
            item["sshKey"] = key;
        }
    }
    item
}

// The cipherstrings that item_json opens for an entry, in the same order,
// without building any JSON. Keep the two in step: a test checks they are.
fn collect_entry_cipherstrings<'a>(
    entry: &'a rbw::db::Entry,
    secrets: bool,
    wanted: &mut Vec<&'a str>,
) {
    let mut push = |value: Option<&'a str>| wanted.extend(value);
    push(Some(&entry.name));
    if secrets {
        push(entry.notes.as_deref());
        for field in &entry.fields {
            push(field.name.as_deref());
            push(field.value.as_deref());
        }
        for history in &entry.history {
            push(Some(&history.password));
        }
    }
    match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            for uri in uris {
                push(Some(&uri.uri));
            }
            push(username.as_deref());
            if secrets {
                push(password.as_deref());
                push(totp.as_deref());
            }
        }
        rbw::db::EntryData::SecureNote => {}
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            push(brand.as_deref());
            if secrets {
                for value in
                    [cardholder_name, number, exp_month, exp_year, code]
                {
                    push(value.as_deref());
                }
            }
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
        } => {
            for value in [title, first_name, middle_name, last_name] {
                push(value.as_deref());
            }
            if secrets {
                for value in [
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
                ] {
                    push(value.as_deref());
                }
            }
        }
        rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            push(public_key.as_deref());
            push(fingerprint.as_deref());
            if secrets {
                push(private_key.as_deref());
            }
        }
    }
}

// The JSON of each entry, or why it couldn't be decrypted, with one request
// to the agent.
fn each_item_json(
    entries: &[&rbw::db::Entry],
    secrets: bool,
) -> anyhow::Result<Vec<anyhow::Result<Value>>> {
    let mut wanted = vec![];
    let mut cipherstrings = vec![];
    for entry in entries {
        cipherstrings.clear();
        collect_entry_cipherstrings(entry, secrets, &mut cipherstrings);
        wanted.extend(cipherstrings.iter().map(|cipherstring| {
            rbw::protocol::DecryptItem {
                cipherstring: (*cipherstring).to_string(),
                entry_key: entry.key.clone(),
                org_id: entry.org_id.clone(),
            }
        }));
    }
    let mut plaintexts = crate::actions::decrypt_many(wanted)?.into_iter();
    Ok(entries
        .iter()
        .map(|entry| {
            let mut failed = None;
            let item =
                item_json(entry, secrets, &mut |entry, cipherstring| {
                    cipherstring?;
                    match plaintexts.next()? {
                        Ok(plaintext) => Some(plaintext),
                        Err(error) => {
                            failed.get_or_insert_with(|| {
                                error.into_error().context(format!(
                                    "failed to decrypt {}",
                                    entry.id
                                ))
                            });
                            None
                        }
                    }
                });
            failed.map_or(Ok(item), Err)
        })
        .collect())
}

fn items_json(
    entries: &[&rbw::db::Entry],
    secrets: bool,
) -> anyhow::Result<Vec<Value>> {
    each_item_json(entries, secrets)?.into_iter().collect()
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    use std::io::Write as _;

    // a list can be large, and stdout itself writes each line apart
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer(&mut stdout, value)
        .context("failed to write the JSON")?;
    writeln!(stdout)
        .and_then(|()| stdout.flush())
        .context("failed to write the JSON")
}

fn find<'a>(
    db: &'a rbw::db::Db,
    id: &str,
) -> anyhow::Result<&'a rbw::db::Entry> {
    db.entries
        .iter()
        .find(|entry| entry.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| coded(ErrorCode::NotFound, "not found"))
}

// The kinds of entries, for rbw item list --type.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ItemType {
    Login,
    Note,
    Card,
    Identity,
    SshKey,
}

impl ItemType {
    const fn id(self) -> u8 {
        match self {
            Self::Login => LOGIN,
            Self::Note => SECURE_NOTE,
            Self::Card => CARD,
            Self::Identity => IDENTITY,
            Self::SshKey => SSH_KEY,
        }
    }
}

pub fn list(secrets: bool, ty: Option<ItemType>) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    // archived entries stay out of lists, as in the official clients, and
    // entries of other types aren't decrypted at all
    let entries: Vec<_> = db
        .entries
        .iter()
        .filter(|entry| {
            !entry.archived
                && ty.is_none_or(|ty| type_id(&entry.data) == ty.id())
        })
        .collect();
    let mut items = each_item_json(&entries, secrets)?;
    // entries that ask for the master password again and aren't open are
    // listed without their secrets
    let closed: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            item.as_ref().is_err_and(|error| {
                rbw::error::code(error) == ErrorCode::RepromptRequired
            })
        })
        .map(|(i, _)| i)
        .collect();
    if !closed.is_empty() {
        let without: Vec<_> = closed.iter().map(|&i| entries[i]).collect();
        for (i, item) in closed.into_iter().zip(items_json(&without, false)?)
        {
            items[i] = Ok(item);
        }
    }
    print_json(&Value::Array(
        items.into_iter().collect::<anyhow::Result<_>>()?,
    ))
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Field {
    Username,
    Password,
    // the current code
    Totp,
    Notes,
}

pub fn get(
    id: &str,
    field: Option<Field>,
    with_code: bool,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    let Some(field) = field else {
        let mut item = items_json(&[entry], true)?.remove(0);
        if with_code {
            add_code(&mut item);
        }
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
        return Err(coded(
            ErrorCode::NotFound,
            format!("no {name} available"),
        ));
    };
    let mut value =
        crate::actions::decrypt_many(vec![rbw::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry.key.clone(),
            org_id: entry.org_id.clone(),
        }])?
        .remove(0)
        .map_err(|error| error.into_error().context("failed to decrypt"))?;
    if matches!(field, Field::Totp) {
        value = rbw::totp::current(&value)?.code;
    }
    println!("{value}");
    Ok(())
}

// A login's current code as rbw item code prints it, in totpCode, from the
// secret the item already holds. An item without a secret, or with one that
// isn't a TOTP secret, gets none, and still prints.
fn add_code(item: &mut Value) {
    let Some(code) = item["login"]["totp"]
        .as_str()
        .and_then(|secret| rbw::totp::current(secret).ok())
    else {
        return;
    };
    item["totpCode"] = code_json(&code);
}

fn code_json(code: &rbw::totp::Code) -> Value {
    json!({
        "code": code.code,
        "period": code.period,
        "expiresAt": code.expires_at,
    })
}

// The current code of a login, with the time it stays valid, so that a
// program can count it down.
pub fn code(id: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    let rbw::db::EntryData::Login {
        totp: Some(totp), ..
    } = &entry.data
    else {
        return Err(coded(ErrorCode::NotFound, "no totp available"));
    };
    let secret =
        crate::actions::decrypt_many(vec![rbw::protocol::DecryptItem {
            cipherstring: totp.clone(),
            entry_key: entry.key.clone(),
            org_id: entry.org_id.clone(),
        }])?
        .remove(0)
        .map_err(|error| error.into_error().context("failed to decrypt"))?;
    print_json(&code_json(&rbw::totp::current(&secret)?))
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
    #[serde(default)]
    organization_id: OrganizationIn,
    // missing: unchanged by an edit
    favorite: Option<bool>,
    // what the program read: an edit fails if the entry changed since
    revision_date: Option<String>,
    login: Option<LoginIn>,
    card: Option<CardIn>,
    identity: Option<IdentityIn>,
    ssh_key: Option<SshKeyIn>,
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

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct CardIn {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct IdentityIn {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    phone: Option<String>,
    email: Option<String>,
    ssn: Option<String>,
    license_number: Option<String>,
    passport_number: Option<String>,
    username: Option<String>,
}

// Only the private key counts: the public key and the fingerprint are
// taken from it.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct SshKeyIn {
    private_key: Option<String>,
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

// The organizationId of an item on stdin. Missing, an edit keeps the
// entry's. Given, null or an id, it must be the entry's, as moving entries
// between organizations isn't supported.
#[derive(Debug, Default, PartialEq, Eq)]
enum OrganizationIn {
    #[default]
    Missing,
    Given(Option<String>),
}

impl<'de> serde::Deserialize<'de> for OrganizationIn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Self::Given)
    }
}

// The item on stdin: JSON, or base64 JSON as bw encode makes it. It holds
// secrets, so copies of it are wiped when dropped.
fn read_item(input: &str) -> anyhow::Result<ItemIn> {
    let text = input.trim();
    let json = zeroize::Zeroizing::new(if text.starts_with('{') {
        text.to_string()
    } else {
        let decoded = zeroize::Zeroizing::new(
            rbw::base64::decode(text)
                .context("the item on stdin isn't JSON or base64 JSON")?,
        );
        std::str::from_utf8(&decoded)
            .context("the item on stdin isn't UTF-8")?
            .to_string()
    });
    // serde's message can quote a value, such as a password given as a
    // number, so only say where the item went wrong
    let item: ItemIn = serde_json::from_str(&json).map_err(|e| {
        anyhow::anyhow!(
            "the item on stdin isn't a Bitwarden item: line {}, column {}",
            e.line(),
            e.column()
        )
    })?;
    if item
        .login
        .as_ref()
        .and_then(|login| login.fido2_credentials.as_ref())
        .is_some_and(|credentials| !credentials.is_empty())
    {
        return Err(coded(
            ErrorCode::Unsupported,
            "passkeys aren't supported yet",
        ));
    }
    match item.ty {
        LOGIN | SECURE_NOTE | CARD | IDENTITY | SSH_KEY => Ok(item),
        ty => Err(coded(
            ErrorCode::InvalidInput,
            format!("unknown item type {ty}"),
        )),
    }
}

fn read_stdin_item() -> anyhow::Result<ItemIn> {
    let mut input = zeroize::Zeroizing::new(String::new());
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
        .context("failed to read the item from stdin")?;
    read_item(&input).map_err(|e| match rbw::error::code(&e) {
        ErrorCode::Other => coded(ErrorCode::InvalidInput, format!("{e:#}")),
        _ => e,
    })
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

// The type's part of an item, encrypted for the entry it replaces, if any.
// A new password goes into the history.
fn encrypt_data(
    item: &ItemIn,
    entry: Option<&rbw::db::Entry>,
    history: &mut Vec<rbw::db::HistoryEntry>,
) -> anyhow::Result<rbw::db::EntryData> {
    let value = |value: Option<&str>| encrypt(value, entry);
    Ok(match item.ty {
        LOGIN => {
            let default = LoginIn::default();
            let login = item.login.as_ref().unwrap_or(&default);
            let password = match entry.map(|entry| (entry, &entry.data)) {
                Some((
                    entry,
                    rbw::db::EntryData::Login {
                        password: old_password,
                        ..
                    },
                )) => {
                    let current = old_password
                        .as_deref()
                        .map(|cipherstring| decrypt(entry, cipherstring))
                        .transpose()?
                        .flatten();
                    crate::commands::edit_password(
                        entry,
                        old_password.as_deref(),
                        current.as_deref(),
                        login.password.as_deref(),
                        history,
                    )?
                }
                _ => value(login.password.as_deref())?,
            };
            rbw::db::EntryData::Login {
                username: value(login.username.as_deref())?,
                password,
                totp: value(login.totp.as_deref())?,
                uris: encrypt_uris(login, entry)?,
            }
        }
        CARD => {
            let default = CardIn::default();
            let card = item.card.as_ref().unwrap_or(&default);
            rbw::db::EntryData::Card {
                cardholder_name: value(card.cardholder_name.as_deref())?,
                number: value(card.number.as_deref())?,
                brand: value(card.brand.as_deref())?,
                exp_month: value(card.exp_month.as_deref())?,
                exp_year: value(card.exp_year.as_deref())?,
                code: value(card.code.as_deref())?,
            }
        }
        IDENTITY => {
            let default = IdentityIn::default();
            let identity = item.identity.as_ref().unwrap_or(&default);
            rbw::db::EntryData::Identity {
                title: value(identity.title.as_deref())?,
                first_name: value(identity.first_name.as_deref())?,
                middle_name: value(identity.middle_name.as_deref())?,
                last_name: value(identity.last_name.as_deref())?,
                address1: value(identity.address1.as_deref())?,
                address2: value(identity.address2.as_deref())?,
                address3: value(identity.address3.as_deref())?,
                city: value(identity.city.as_deref())?,
                state: value(identity.state.as_deref())?,
                postal_code: value(identity.postal_code.as_deref())?,
                country: value(identity.country.as_deref())?,
                phone: value(identity.phone.as_deref())?,
                email: value(identity.email.as_deref())?,
                ssn: value(identity.ssn.as_deref())?,
                license_number: value(identity.license_number.as_deref())?,
                passport_number: value(identity.passport_number.as_deref())?,
                username: value(identity.username.as_deref())?,
            }
        }
        SSH_KEY => {
            let private_key = item
                .ssh_key
                .as_ref()
                .and_then(|key| key.private_key.as_deref())
                .unwrap_or_default();
            let (public_key, fingerprint) = ssh_public_key(private_key)?;
            rbw::db::EntryData::SshKey {
                private_key: value(Some(private_key))?,
                public_key: value(Some(&public_key))?,
                fingerprint: value(Some(&fingerprint))?,
            }
        }
        _ => rbw::db::EntryData::SecureNote,
    })
}

// The current value, or none when it can't be decrypted. An entry with
// master password reprompt must be open: without its password, an edit
// couldn't tell whether the password changed.
fn decrypt(
    entry: &rbw::db::Entry,
    cipherstring: &str,
) -> anyhow::Result<Option<String>> {
    match crate::actions::decrypt_many(vec![rbw::protocol::DecryptItem {
        cipherstring: cipherstring.to_string(),
        entry_key: entry.key.clone(),
        org_id: entry.org_id.clone(),
    }])?
    .remove(0)
    {
        Ok(plaintext) => Ok(Some(plaintext)),
        Err(error) if error.code == Some(ErrorCode::RepromptRequired) => {
            Err(error.into_error())
        }
        Err(_) => Ok(None),
    }
}

// An entry with master password reprompt must be open to be edited, as to
// be read, since an edit replaces the values it keeps closed. Decrypting
// one of them tells.
fn require_open(entry: &rbw::db::Entry) -> anyhow::Result<()> {
    match entry.protected_values().first() {
        Some(value) if entry.master_password_reprompt() => {
            decrypt(entry, value).map(drop)
        }
        _ => Ok(()),
    }
}

// The public key and SHA-256 fingerprint of an OpenSSH private key, as the
// official clients store them.
fn ssh_public_key(private_key: &str) -> anyhow::Result<(String, String)> {
    let invalid = |message: &str| coded(ErrorCode::InvalidInput, message);
    if private_key.trim().is_empty() {
        return Err(invalid("an SSH key needs its private key"));
    }
    let key = ssh_agent_lib::ssh_key::PrivateKey::from_openssh(private_key)
        .map_err(|_| {
        invalid("the private key isn't an OpenSSH private key")
    })?;
    if key.is_encrypted() {
        return Err(invalid(
            "the private key has a passphrase; the SSH agent needs it without",
        ));
    }
    let public = key.public_key();
    let public_key = public.to_openssh().map_err(|_| {
        invalid("the private key's public key can't be written")
    })?;
    let fingerprint = public
        .fingerprint(ssh_agent_lib::ssh_key::HashAlg::Sha256)
        .to_string();
    Ok((public_key, fingerprint))
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
        return Err(coded(ErrorCode::NotLoggedIn, "not logged in"));
    };
    Ok((access_token, refresh_token))
}

fn check_writable(entry: &rbw::db::Entry) -> anyhow::Result<()> {
    if entry.read_only {
        return Err(coded(
            ErrorCode::Forbidden,
            "the entry is in a collection this account can only read",
        ));
    }
    Ok(())
}

fn same_id(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (a, b) => a == b,
    }
}

pub fn create() -> anyhow::Result<()> {
    let item = read_stdin_item()?;
    if matches!(item.organization_id, OrganizationIn::Given(Some(_))) {
        return Err(coded(
            ErrorCode::Unsupported,
            "creating entries in organizations isn't supported yet",
        ));
    }
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
    let data = encrypt_data(&item, None, &mut vec![])?;
    let (_, saved) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &user_id,
        &name,
        &data,
        &fields,
        notes.as_deref(),
        item.folder_id.as_deref(),
        item.favorite.unwrap_or(false),
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
        return Err(coded(
            ErrorCode::InvalidInput,
            "the item on stdin has another id",
        ));
    }
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    check_writable(entry)?;
    require_open(entry)?;
    if matches!(
        &item.organization_id,
        OrganizationIn::Given(given)
            if !same_id(given.as_deref(), entry.org_id.as_deref())
    ) {
        return Err(coded(
            ErrorCode::Unsupported,
            "moving entries between organizations isn't supported yet",
        ));
    }
    if type_id(&entry.data) != item.ty {
        return Err(coded(
            ErrorCode::InvalidInput,
            "an item's type can't change",
        ));
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
    let data = encrypt_data(&item, Some(entry), &mut history)?;
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
        item.revision_date
            .as_deref()
            .or(entry.revision_date.as_deref()),
        item.favorite,
    )?;
    print_saved(&entry.id)
}

pub fn delete(id: &str) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    check_writable(entry)?;
    // as for an edit: the official clients ask for the master password
    // again before they delete such an entry
    require_open(entry)?;
    let (access_token, refresh_token) = tokens(&db)?;
    rbw::actions::trash(&access_token, &refresh_token, &entry.id)?;
    crate::actions::sync()
}

// Sets what belongs to the account rather than to the entry, its folder
// or favorite flag, without its secrets, so that it works for entries in
// read-only collections too.
fn save_partial(
    id: &str,
    change: impl FnOnce(&rbw::db::Db) -> anyhow::Result<rbw::api::PartialChange>,
) -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    let change = change(&db)?;
    let (access_token, refresh_token) = tokens(&db)?;
    rbw::actions::partial(&access_token, &refresh_token, &entry.id, &change)?;
    print_saved(&entry.id)
}

pub fn favorite(id: &str, favorite: bool) -> anyhow::Result<()> {
    save_partial(id, |_| Ok(rbw::api::PartialChange::Favorite(favorite)))
}

// Moves an entry into a folder, or out of any folder without one.
pub fn move_to(id: &str, folder: Option<&str>) -> anyhow::Result<()> {
    save_partial(id, |db| {
        let folder = folder
            .map(|folder| {
                db.folders
                    .iter()
                    .find(|known| known.id.eq_ignore_ascii_case(folder))
                    .map(|known| known.id.clone())
                    .ok_or_else(|| {
                        coded(ErrorCode::NotFound, "no such folder")
                    })
            })
            .transpose()?;
        Ok(rbw::api::PartialChange::Folder(folder))
    })
}

// Opens an entry that asks for the master password again, so that its
// secrets can be read for a while.
pub fn unlock(id: &str, password_stdin: bool) -> anyhow::Result<()> {
    let password = password_stdin
        .then(crate::scripting::password_from_stdin)
        .transpose()?;
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let entry = find(&db, id)?;
    crate::actions::unlock_entry(entry.id.clone(), password)
}

pub fn folder_list() -> anyhow::Result<()> {
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let names = crate::actions::decrypt_many(
        db.folders
            .iter()
            .map(|folder| rbw::protocol::DecryptItem {
                cipherstring: folder.name.clone(),
                entry_key: None,
                org_id: None,
            })
            .collect(),
    )?;
    let folders = db
        .folders
        .iter()
        .zip(names)
        .map(|(folder, name)| {
            let name = name.map_err(|error| {
                error
                    .into_error()
                    .context(format!("failed to decrypt {}", folder.id))
            })?;
            Ok(folder_json(&folder.id, &name))
        })
        .collect::<anyhow::Result<_>>()?;
    print_json(&Value::Array(folders))
}

pub fn folder_create(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        return Err(coded(ErrorCode::InvalidInput, "a folder needs a name"));
    }
    crate::commands::unlock()?;
    let db = crate::commands::load_db()?;
    let (access_token, refresh_token) = tokens(&db)?;
    let encrypted = crate::actions::encrypt(name, None, None)?;
    let (_, id) = rbw::actions::create_folder(
        &access_token,
        &refresh_token,
        &encrypted,
    )?;
    crate::actions::sync()?;
    print_json(&folder_json(&id, name))
}

fn folder_json(id: &str, name: &str) -> Value {
    json!({ "object": "folder", "id": id, "name": name })
}

#[cfg(test)]
mod test {
    use super::*;

    // An entry of each kind with every value set, each to a cipherstring of
    // its own, so that the order of the values shows.
    fn entries() -> Vec<rbw::db::Entry> {
        let mut n = 0;
        let mut next = || {
            n += 1;
            Some(format!("2.value{n}"))
        };
        let datas = [
            rbw::db::EntryData::Login {
                username: next(),
                password: next(),
                totp: next(),
                uris: (0..2)
                    .map(|_| rbw::db::Uri {
                        uri: next().unwrap(),
                        match_type: None,
                        uri_checksum: None,
                    })
                    .collect(),
            },
            rbw::db::EntryData::SecureNote,
            rbw::db::EntryData::Card {
                cardholder_name: next(),
                number: next(),
                brand: next(),
                exp_month: next(),
                exp_year: next(),
                code: next(),
            },
            rbw::db::EntryData::Identity {
                title: next(),
                first_name: next(),
                middle_name: next(),
                last_name: next(),
                address1: next(),
                address2: next(),
                address3: next(),
                city: next(),
                state: next(),
                postal_code: next(),
                country: next(),
                phone: next(),
                email: next(),
                ssn: next(),
                license_number: next(),
                passport_number: next(),
                username: next(),
            },
            rbw::db::EntryData::SshKey {
                private_key: next(),
                public_key: next(),
                fingerprint: next(),
            },
        ];
        datas
            .into_iter()
            .map(|data| rbw::db::Entry {
                id: "id".to_string(),
                org_id: None,
                folder: None,
                folder_id: None,
                name: next().unwrap(),
                data,
                fields: (0..2)
                    .map(|_| rbw::db::Field {
                        ty: None,
                        name: next(),
                        value: next(),
                        linked_id: None,
                    })
                    .collect(),
                notes: next(),
                history: (0..2)
                    .map(|_| rbw::db::HistoryEntry {
                        last_used_date: "2026-01-01T00:00:00Z".to_string(),
                        password: next().unwrap(),
                    })
                    .collect(),
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                revision_date: None,
                favorite: false,
                archived: false,
                read_only: false,
            })
            .collect()
    }

    #[test]
    fn collected_cipherstrings_follow_the_order_item_json_opens() {
        for mut entry in entries() {
            for secrets in [false, true] {
                let mut opened = vec![];
                item_json(&entry, secrets, &mut |_, cipherstring| {
                    opened.extend(cipherstring.map(str::to_string));
                    None
                });
                let mut collected = vec![];
                collect_entry_cipherstrings(&entry, secrets, &mut collected);
                // the name, at least
                assert_ne!(collected.len(), 0);
                assert_eq!(collected, opened, "{:?} {secrets}", entry.data);
            }
            // and with values missing
            entry.notes = None;
            entry.fields[0].name = None;
            let mut opened = vec![];
            item_json(&entry, true, &mut |_, cipherstring| {
                opened.extend(cipherstring.map(str::to_string));
                None
            });
            let mut collected = vec![];
            collect_entry_cipherstrings(&entry, true, &mut collected);
            assert_eq!(collected, opened);
        }
    }

    #[test]
    fn a_missing_organization_id_is_told_from_null() {
        let org = |item: &str| read_item(item).unwrap().organization_id;
        assert_eq!(org(r#"{"type":2,"name":"x"}"#), OrganizationIn::Missing);
        assert_eq!(
            org(r#"{"type":2,"name":"x","organizationId":null}"#),
            OrganizationIn::Given(None)
        );
        assert_eq!(
            org(r#"{"type":2,"name":"x","organizationId":"o1"}"#),
            OrganizationIn::Given(Some("o1".to_string()))
        );
    }

    #[test]
    fn with_code_adds_the_current_code_of_a_totp_secret() {
        let mut item = json!({"login": {"totp": "JBSWY3DPEHPK3PXP"}});
        add_code(&mut item);
        let code = &item["totpCode"];
        assert_eq!(code["code"].as_str().unwrap().len(), 6);
        assert_eq!(code["period"], 30);
        assert!(code["expiresAt"].as_u64().unwrap() > 0);

        for mut item in [
            json!({"login": {"totp": null}}),
            json!({"login": {"totp": "not a secret!"}}),
            json!({"secureNote": {"type": 0}}),
        ] {
            add_code(&mut item);
            assert!(item.get("totpCode").is_none(), "{item}");
        }
    }

    #[test]
    fn types_have_bitwardens_ids() {
        for (entry, ty) in entries().iter().zip([
            ItemType::Login,
            ItemType::Note,
            ItemType::Card,
            ItemType::Identity,
            ItemType::SshKey,
        ]) {
            assert_eq!(type_id(&entry.data), ty.id());
        }
    }

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
    fn errors_quote_no_value_of_the_item() {
        for item in [
            r#"{"type":"hunter2","name":"x"}"#,
            r#"{"type":1,"name":"x","login":{"password":["hunter2"]}}"#,
            r#"{"type":1,"name":"x","fields":[{"type":"hunter2"}]}"#,
        ] {
            let error = format!("{:#}", read_item(item).unwrap_err());
            assert!(!error.contains("hunter2"), "{error}");
            assert!(error.contains("line 1, column"), "{error}");
        }
    }

    #[test]
    fn refuses_what_it_cant_save() {
        for item in [
            r#"{"type":9,"name":"Unknown"}"#,
            r#"{"type":1,"name":"x","login":{"fido2Credentials":[{}]}}"#,
        ] {
            assert!(read_item(item).is_err(), "{item}");
        }
        assert!(read_item(
            r#"{"type":1,"name":"x","login":{"fido2Credentials":[]}}"#
        )
        .is_ok());
        for ty in [CARD, IDENTITY, SSH_KEY] {
            let item = format!(r#"{{"type":{ty},"name":"x"}}"#);
            assert!(read_item(&item).is_ok(), "{item}");
        }
    }

    #[test]
    fn ssh_keys_get_their_public_key_from_the_private_key() {
        let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC4DOVa+kn8HZu7XPoSipFq+oUfoZbqOgcTIHmhNyxV9gAAAJAVDmEWFQ5h
FgAAAAtzc2gtZWQyNTUxOQAAACC4DOVa+kn8HZu7XPoSipFq+oUfoZbqOgcTIHmhNyxV9g
AAAEDPhuqJUm+QNatlbazPhiaEyM0VmpB6TVIsEBBU6Xijx7gM5Vr6Sfwdm7tc+hKKkWr6
hR+hluo6BxMgeaE3LFX2AAAACHRlc3RAcmJ3AQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
        let (public_key, fingerprint) = ssh_public_key(private_key).unwrap();
        assert_eq!(
            public_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILgM5Vr6Sfwdm7tc+hKKkWr6hR+hluo6BxMgeaE3LFX2 test@rbw"
        );
        assert_eq!(
            fingerprint,
            "SHA256:82tRvuz0hLHtR5dkHl65L2UtySKaBT2BHA254wi5bkc"
        );
        for invalid in [
            "",
            "ssh-ed25519 AAAA",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            let error = ssh_public_key(invalid).unwrap_err();
            assert_eq!(rbw::error::code(&error), ErrorCode::InvalidInput);
        }
    }
}
