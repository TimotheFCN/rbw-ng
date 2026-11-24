# Driving rbw from other programs

A program can drive `rbw` the way it would drive Bitwarden's official CLI. It
can log in and unlock without a terminal, read and save entries as JSON in
Bitwarden's item format, and keep a session that unlocks the vault again
without the master password. Each call is a short-lived `rbw` process, but the
vault stays unlocked in `rbw-agent` between calls, so a call costs a request to
the agent instead of a key derivation or a fresh decryption of the vault.

`tools/scripting-check` runs everything below against a real server.

## Without a terminal

`RBW_NONINTERACTIVE=1` makes `rbw` fail instead of asking. Without it, `rbw`
opens pinentry, which a program can't answer.

| When | Code |
| --- | --- |
| The account isn't logged in | `not_logged_in` |
| The vault is locked and there is no session | `locked` |
| Anything else would ask | `input_required` |

## Errors

With `RBW_ERROR_FORMAT=json`, a command that fails prints its error on
stderr as one line of JSON, with a code that stays the same from one release
to the next, and exits with status 1:

```json
{"code":"locked","message":"rbw item list: the vault is locked"}
```

The message is for people and can change. Some codes carry more:

| Code | Meaning |
| --- | --- |
| `not_logged_in` | the profile isn't logged in, or the server no longer accepts its login |
| `locked` | the vault is locked |
| `input_required` | `rbw` would have to ask, and `RBW_NONINTERACTIVE` is set |
| `incorrect_password` | the master password (or API key) is wrong |
| `two_step_required` | the login needs a two-step code; `methods` lists the method ids |
| `two_step_code_sent` | the server emailed a two-step code |
| `new_device_code_required` | the login needs the code the server emailed to verify this device |
| `incorrect_code` | the two-step or new device code is wrong |
| `two_step_unsupported` | none of the account's two-step methods are supported |
| `session_invalid` | `RBW_SESSION` no longer unlocks the vault |
| `touch_id_canceled` | the person canceled Touch ID |
| `touch_id_unavailable` | Touch ID can't unlock the vault now |
| `not_found` | no entry or folder with this id, or the entry has no such field |
| `conflict` | the entry changed on the server since the last sync |
| `forbidden` | the server refused, for example an entry in a read-only collection |
| `unsupported` | `rbw` can't do this yet |
| `invalid_input` | the input or the arguments are wrong |
| `network` | the server can't be reached |
| `server` | the server answered with an error; `status` is its HTTP status, if any |
| `agent` | `rbw-agent` can't be started or reached |
| `other` | anything else |

Use a profile of your own (`RBW_PROFILE=myapp`) so that your program never
shares, or signs out, the account someone uses in a terminal. Each profile has
its own configuration, local vault and agent, so a program can keep several
accounts side by side by giving each one a profile.

## Logging in

Set the server and the account first:

```sh
rbw config set base_url https://vault.example.com   # unset for bitwarden.com
rbw config set email you@example.com
```

Then log in with the master password on stdin. The final line break is
dropped.

```sh
rbw login --password-stdin [--session] < password
```

When the server asks for more, the login fails with one of these errors:

| Code | Next step |
| --- | --- |
| `two_step_required` | ask for a code from one of the `methods`, then run `rbw login --password-stdin --method ID --code CODE` |
| `two_step_code_sent` | the answer to `--method 1 --code ""`: Bitwarden emailed the code |
| `new_device_code_required` | run `--code CODE` without `--method`, with the code Bitwarden emailed |
| `incorrect_password` | ask again |
| `incorrect_code` | ask for a new code |

The method ids are Bitwarden's: `0` authenticator app, `1` email, `3` YubiKey
OTP. A login that succeeds also unlocks.

bitwarden.com may refuse a password login from a device it doesn't know. Run
`rbw register --api-key-env` once first, with the account's personal API key
in `RBW_CLIENT_ID` and `RBW_CLIENT_SECRET`.

## Unlocking and sessions

```sh
rbw unlock --password-stdin [--session] < password
```

With `--session`, `login` and `unlock` print a session key on their last line
of output. Pass it back in `RBW_SESSION` to any later command: when the vault
is locked, `rbw` unlocks it with the session instead of asking. This works
even after the agent stopped, its lock timeout passed or the computer
restarted.

On a Mac with `touch_id_unlock` on, `rbw unlock --touch-id` unlocks with
Touch ID only. It fails with `touch_id_unavailable` when Touch ID can't
unlock, because the vault wasn't unlocked with the master password since the
agent started, and with `touch_id_canceled` when the person cancels.

A session works like `BW_SESSION`, but neither half opens the vault alone.
The agent encrypts the vault key with the random session key and keeps only
that encrypted copy, in the profile's data folder. Your program keeps the
session key, for example behind Touch ID. `RBW_SESSION` is only read while the
vault is locked.

A session ends when:

* `rbw lock` or `rbw purge` runs;
* a new `--session` replaces it;
* the master password changes.

After that, a command with the old key fails with `session_invalid`.

## Status

```sh
rbw status --json
```

```json
{"status":"unlocked","serverUrl":"https://vault.example.com","userEmail":"you@example.com","lastSync":"2026-11-24T09:41:07Z","touchId":false}
```

`status` is `unauthenticated`, `locked` or `unlocked`, and `serverUrl` is
`null` for bitwarden.com. `rbw status` never starts the agent; a stopped agent
means a locked vault.

`lastSync` is when the local copy of the vault last synced with the server,
also when the agent synced on its own; when it changes, the entries may have
changed. `touchId` says whether `rbw unlock --touch-id` can unlock the vault
now.

`rbw status --json` takes a few milliseconds, so a program can poll it every
second or two to notice when the vault locks, unlocks or syncs.

## Entries

`rbw item` reads and writes entries in Bitwarden's item format, the format of
`bw get item` and of Bitwarden's JSON export. It finds entries by id only,
never by name.

| Command | Prints |
| --- | --- |
| `rbw item list` | every entry, without secrets |
| `rbw item list --secrets` | every entry, with passwords, codes' secrets, notes, custom fields and password history |
| `rbw item get ID` | one entry, with its secrets |
| `rbw item get ID --field username\|password\|totp\|notes` | one value; for `totp`, the current code |
| `rbw item code ID` | the current code as `{"code":"123456","period":30,"expiresAt":1795000000}`, with `expiresAt` in Unix seconds |
| `rbw item create` | adds the entry on stdin and prints it as saved |
| `rbw item edit ID` | replaces the entry with the one on stdin and prints it as saved |
| `rbw item delete ID` | moves the entry to the trash, where the official clients can restore it |

Without secrets, an entry has no `notes`, `fields` or `passwordHistory`. A
login has its username and addresses, and `login.hasTotp`, which isn't part
of Bitwarden's format, says whether it has a code. A card has only its
`brand`, an identity its `title` and names, and an SSH key its `publicKey`
and `keyFingerprint`. Listing without secrets is also faster, since only
these values are decrypted.

`edit`, from Bitwarden's sync data, is `false` for an entry in a collection
that the account can only read: editing or deleting it fails with
`forbidden`.

Archived entries are left out of `rbw item list`. An unknown id, or a field
the entry doesn't have, fails with `not_found`.

`create` and `edit` take JSON or base64 JSON (what `bw encode` makes) on stdin.
They print the entry as the server saved it, without secrets. They save:

* logins, secure notes, cards, identities and SSH keys;
* the name, notes, folder and favorite flag;
* a login's username, password, TOTP secret and addresses with their match
  types;
* every value of a card and of an identity;
* an SSH key's private key, in OpenSSH format and without a passphrase. The
  public key and the fingerprint are taken from it;
* custom fields.

Other keys, such as `id`, `object` or `collectionIds`, are ignored. `edit`
replaces each of the values above, so send the whole entry: a missing password
removes it, except for `favorite`, which stays as it is when it is left out.
An edit that changes the password moves the old one into the history, as the
official clients do. It keeps what `rbw` doesn't save, such as passkeys and
attachments. If the entry changed on the server in the meantime, the edit
fails instead of overwriting the change.

Entries shared through an organization are read, edited and deleted like the
others; an edit keeps the entry's `organizationId`. These aren't supported
yet:

* creating an entry in an organization, or moving one into or out of it;
* saving passkeys (`login.fido2Credentials`).

## Folders

| Command | Prints |
| --- | --- |
| `rbw folder list` | every folder, also the empty ones |
| `rbw folder create NAME` | adds a folder and prints it |

A folder is `{"object":"folder","id":"...","name":"..."}`, as in Bitwarden's
format. An entry's `folderId` puts it in a folder.
