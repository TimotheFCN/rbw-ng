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
to the next, and exits with status 1. So do wrong arguments, with
`invalid_input`:

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
| `registration_required` | the server wants this device registered with the account's API key first |
| `incorrect_code` | the two-step or new device code is wrong |
| `two_step_unsupported` | none of the account's two-step methods are supported |
| `session_invalid` | `RBW_SESSION` no longer unlocks the vault |
| `touch_id_canceled` | the person canceled Touch ID |
| `touch_id_unavailable` | Touch ID can't unlock the vault now |
| `reprompt_required` | the entry asks for the master password again; open it with `rbw item unlock` |
| `not_found` | no entry or folder with this id, or the entry has no such field |
| `conflict` | the entry changed on the server since the last sync |
| `forbidden` | the server refused, for example an entry in a read-only collection |
| `unsupported` | `rbw` can't do this yet |
| `invalid_input` | the input or the arguments are wrong |
| `network` | the server can't be reached |
| `wrong_server` | the server's address leads to something that isn't a Bitwarden server, such as a web site or a wrong path |
| `server` | the server answered with an error; `status` is its HTTP status, if any |
| `agent` | `rbw-agent` can't be started or reached |
| `other` | anything else |

Use a profile of your own (`RBW_PROFILE=myapp`) so that your program never
shares, or signs out, the account someone uses in a terminal. Each profile has
its own configuration, local vault and agent, so a program can keep several
accounts side by side by giving each one a profile. A profile's name can't
contain `/`.

`rbw profiles --json` lists the profiles on this computer, as
`[{"profile":"work","userEmail":"you@example.com","serverUrl":null}]`, with a
`null` profile for the default one. `rbw purge --all` removes the profile
`RBW_PROFILE` selects: its local vault, its configuration, every other file
it keeps and its SSH agent service.

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
| `two_step_required` | ask for a code from one of the `methods`, then run `rbw login --password-stdin --method ID --code-env` with the code in `RBW_CODE` |
| `two_step_code_sent` | the answer to `--method 1 --code ""`: Bitwarden emailed the code |
| `new_device_code_required` | run `--code-env` without `--method`, with the code Bitwarden emailed in `RBW_CODE` |
| `registration_required` | run `rbw register --api-key-env` (see below), then log in again |
| `incorrect_password` | ask again |
| `incorrect_code` | ask for a new code |

The method ids are Bitwarden's: `0` authenticator app, `1` email, `3` YubiKey
OTP. A login that succeeds also unlocks. `--code CODE` works too, but every
user of the computer can see a program's arguments, and only the same user
its environment.

Bitwarden servers from before mid-2025 may refuse a password login from a
device they don't know by asking for a captcha, which `rbw` can't show: the
login fails with `registration_required`. Register the device once with the
account's personal API key, from the web vault's security settings:

```sh
RBW_CLIENT_ID=user.... RBW_CLIENT_SECRET=... rbw register --api-key-env
```

then log in again. A wrong key fails with `incorrect_password`. Current
servers ask for an emailed code instead (`new_device_code_required`), and
registering first works there too: the API key login makes the device known,
so the password login that follows needs no code.

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

## Settings

`rbw config show` prints the profile's settings as JSON, and
`rbw config set KEY VALUE` changes one. A change to `lock_timeout` (in
seconds), `sync_interval`, `pinentry`, `pinentry_timeout`, `touch_id_unlock`
or `ssh_confirm` applies to a running agent at once, without locking the
vault; any other change stops the agent.

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
| `rbw item unlock ID [--password-stdin]` | opens an entry that asks for the master password again (see below) |
| `rbw item create` | adds the entry on stdin and prints it as saved |
| `rbw item edit ID` | replaces the entry with the one on stdin and prints it as saved |
| `rbw item delete ID` | moves the entry to the trash, where the official clients can restore it |
| `rbw item favorite ID true\|false` | marks or unmarks the entry as a favorite and prints it as saved |
| `rbw item move ID [FOLDER_ID]` | moves the entry into a folder, or out of any folder without one, and prints it as saved |

Without secrets, an entry has no `notes`, `fields` or `passwordHistory`. A
login has its username and addresses, and `login.hasTotp`, which isn't part
of Bitwarden's format, says whether it has a code. A card has only its
`brand`, an identity its `title` and names, and an SSH key its `publicKey`
and `keyFingerprint`. Listing without secrets is also faster, since only
these values are decrypted.

`edit`, from Bitwarden's sync data, is `false` for an entry in a collection
that the account can only read: editing or deleting it fails with
`forbidden`.

The folder and the favorite flag belong to the account, not to the entry.
`rbw item favorite` and `rbw item move` change only them, with Bitwarden's
partial update: they don't decrypt or send the entry's secrets, and they work
on entries in read-only collections too. An unknown folder fails with
`not_found`.

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
attachments. If the entry changed on the server since the `revisionDate` of
the entry on stdin, as `rbw item get` printed it, the edit fails with
`conflict` instead of overwriting the change; without a `revisionDate`, it
fails if the entry changed since the last sync.

Entries shared through an organization are read, edited and deleted like the
others; an edit keeps the entry's `organizationId`. These aren't supported
yet:

* creating an entry in an organization, or moving one into or out of it;
* saving passkeys (`login.fido2Credentials`).

### Entries that ask for the master password again

An entry with Bitwarden's master password re-prompt has `"reprompt": 1`.
While the vault is unlocked, everything of it stays closed but its name and
what `rbw item list` shows: a login's username and addresses, a card's brand,
an identity's title and names, an SSH key's public key and fingerprint. Its
notes, custom fields and password history stay closed too. With
`RBW_NONINTERACTIVE`, reading a closed value fails with `reprompt_required`,
and `rbw item list --secrets` lists the entry as `rbw item list` does; in a
terminal, pinentry asks for the master password. Searches by name
(`rbw search`, `rbw get NAME`) don't look into its notes and fields.

Ask the person for the master password and pass it to
`rbw item unlock ID --password-stdin`. The agent checks that it opens the
vault that is unlocked, and fails with `incorrect_password` if it doesn't.
The entry is then open: its values read, and it can be edited, until it goes
unread for two minutes or the vault locks. Each read keeps it open, so a
program that shows the entry and refreshes its code every period keeps it
open while it is shown. This follows the official clients, which ask again
each time such an entry is opened and not while it stays open. Without
`--password-stdin`, `rbw item unlock` asks through pinentry, and a password
given to pinentry when a value is read opens the entry the same way.

Editing such an entry needs it open too, whatever its kind: otherwise `edit`
fails with `reprompt_required`.

The agent, not `rbw`, keeps these values closed: it decrypts none of them
without the master password, whatever program asks. It knows which entries
ask for it from the server, and from a local copy of the vault that carries
its MAC of them, which needs the vault key. A local copy that another
program edited makes the agent sync before it decrypts anything.

As in the official clients, the re-prompt is a safeguard against someone at
an unlocked computer, not more encryption: such an entry is encrypted with
the same key as the rest of the vault. A program that runs as the same user
can still:

* read every entry without the re-prompt, through the agent, while the
  vault is unlocked;
* read an entry while it is open;
* turn the re-prompt off on the server with the access token in the local
  copy of the vault, then have the agent sync. The change shows on the
  server and in the other clients;
* trick the person into typing the master password, for example with
  `rbw config set pinentry` or a prompt of its own.

## Folders

| Command | Prints |
| --- | --- |
| `rbw folder list` | every folder, also the empty ones |
| `rbw folder create NAME` | adds a folder and prints it |

A folder is `{"object":"folder","id":"...","name":"..."}`, as in Bitwarden's
format. An entry's `folderId` puts it in a folder.

## Icons

```sh
rbw icon github.com > github.png
```

prints a website's icon from the icon service of the profile's server:
`icons.bitwarden.net` for bitwarden.com, `icons.bitwarden.eu` for
bitwarden.eu, and `/icons` on a self-hosted server. It needs no login. The
image is what the service sends, usually a PNG or an ICO of a few kilobytes,
at most 1 MiB. The request carries the host name and nothing about the
account: no token and no Bitwarden headers, only the extra headers and client
certificate that reaching the server takes. A Vaultwarden server with an
external icon service redirects to it: `rbw` follows such a redirect only to
an `https` address that isn't on this computer or a private network, without
the extra headers and the certificate. It fails with `not_found` when the
service has no icon, or redirects anywhere else, and with `invalid_input`
for anything but a host name, and for `.onion` and `.i2p` sites, whose names
the official clients never send to the icon service.

The official clients show the icon of a login's first website, when it is
an `http` or `https` address or a bare host name with a dot. Cache the icons:
the service may fetch each one from the website.

## Passwords

`rbw generate LENGTH` prints a new password and needs no login. Each
character is drawn uniformly at random from upper-case letters, lower-case
letters, digits and the 32 ASCII symbols, unless options leave some of these
classes out:

| Option | Leaves out |
| --- | --- |
| `--no-uppercase` | upper-case letters |
| `--no-lowercase` | lower-case letters |
| `--no-numbers` | digits |
| `--no-symbols` | symbols |

`--only-numbers` keeps digits alone, and `--nonconfusables` keeps the 24
digits and lower-case letters that can't be mistaken for each other.

With `--each-class`, the password holds at least one character of each class
it is made of. `rbw` draws whole passwords until one does, so the password is
drawn uniformly from all the passwords of that length that hold every class:
none is likelier than another, and none is left out. Its randomness is the
logarithm of their count; with `n` characters in all, of which `n_i` in
class `i`, the count for a length `L` is, by inclusion-exclusion over the
classes left out:

```
sum over every set S of classes: (-1)^|S| * (n - sum of n_i for i in S)^L
```

For 20 characters of all four classes, that is 130.9 bits, 0.2 less than
without `--each-class`. A password shorter than its number of classes, or
without any class, fails with `invalid_input`.

`rbw generate WORDS --diceware` makes a passphrase of words drawn from the
EFF's long list of 7776 words, separated by spaces. `--separator TEXT` puts
`TEXT` between them instead, also nothing, `--capitalize` begins each word
with an upper-case letter, and `--include-number` puts a digit after one
word, which adds the choice of the word and of the digit:
`log2(10 * WORDS)` bits. No word of the list begins another, so a passphrase
reads back into its words whatever the separator, and holds all of that
randomness.

## SSH agent

`rbw ssh-agent install` and `rbw ssh-agent uninstall` need no terminal.
`rbw ssh-agent status --json` describes the setup of the profile:

```json
{"supported":true,"installed":true,"otherProfiles":[],"running":true,"socket":"/run/user/1000/rbw/ssh-agent-socket","ssh":{"agent":"rbw","socket":"/run/user/1000/rbw/ssh-agent-socket"}}
```

* `supported`: the system has launchd or systemd;
* `installed`: the profile's agent runs as a service;
* `otherProfiles`: the profiles whose service keeps this one from being
  installed (on Linux, where only one can set `SSH_AUTH_SOCK`), `null` for
  the default profile;
* `running`: the agent runs now. A service starts it when a program
  connects;
* `socket`: the socket that serves the profile's SSH keys;
* `ssh`: the agent `ssh` uses for a host without settings of its own:
  `agent` is `rbw` (this profile), `other`, `none` or `unknown`, with its
  `socket`.

The keys the agent serves are the vault's SSH key entries.
