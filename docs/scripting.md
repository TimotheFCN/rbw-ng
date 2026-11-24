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

| When | The error contains |
| --- | --- |
| The account isn't logged in | `not logged in` |
| The vault is locked and there is no session | `the vault is locked` |
| Anything else would ask | `input required, but RBW_NONINTERACTIVE is set` |

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

| The error contains | Next step |
| --- | --- |
| `two-step login code required; methods: 0, 1, 3` | ask for a code from one of the methods listed, then run `rbw login --password-stdin --method ID --code CODE` |
| `two-step login code required; Bitwarden emailed it` | the answer to `--method 1` without a code: Bitwarden emailed the code |
| `new device verification code required` | run `--code CODE` without `--method`, with the code Bitwarden emailed |
| `incorrect master password` | ask again |
| `the two-step login code is incorrect` | ask for a new code |

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

A session works like `BW_SESSION`, but neither half opens the vault alone.
The agent encrypts the vault key with the random session key and keeps only
that encrypted copy, in the profile's data folder. Your program keeps the
session key, for example behind Touch ID. `RBW_SESSION` is only read while the
vault is locked.

A session ends when:

* `rbw lock` or `rbw purge` runs;
* a new `--session` replaces it;
* the master password changes.

After that, a command with the old key fails with `the session key is
invalid`.

## Status

```sh
rbw status --json
```

```json
{"status":"unlocked","serverUrl":"https://vault.example.com","userEmail":"you@example.com"}
```

`status` is `unauthenticated`, `locked` or `unlocked`, and `serverUrl` is
`null` for bitwarden.com. `rbw status` never starts the agent; a stopped agent
means a locked vault.

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
| `rbw item create` | adds the entry on stdin and prints it as saved |
| `rbw item edit ID` | replaces the entry with the one on stdin and prints it as saved |

Without secrets, an entry has no `login.password`, `login.totp`, `notes`,
`fields` or `passwordHistory`. `login.hasTotp`, which isn't part of
Bitwarden's format, says whether the login has a code. Listing without secrets
is also faster, since only names, usernames and addresses are decrypted.

Archived entries are left out of `rbw item list`. A missing field fails with
`no username available`, `no password available` or `no totp available`, and
an unknown id fails with `not found`.

`create` and `edit` take JSON or base64 JSON (what `bw encode` makes) on stdin.
They print the entry as the server saved it, without secrets. They save:

* logins and secure notes;
* the name, notes and folder;
* the username, password, TOTP secret and addresses with their match types;
* custom fields.

Other keys, such as `id`, `object` or `collectionIds`, are ignored. `edit`
replaces each of the values above, so send the whole entry: a missing password
removes it. An edit that changes the password moves the old one into the
history, as the official clients do. It keeps what `rbw` doesn't save, such as
passkeys, attachments and the favorite flag. If the entry changed on the
server in the meantime, the edit fails instead of overwriting the change.

These aren't supported yet:

* entries in organizations;
* saving passkeys (`login.fido2Credentials`);
* saving cards, identities and SSH keys.
