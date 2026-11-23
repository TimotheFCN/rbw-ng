# Embedding rbw-ng

`rbw-agent --embedded` runs the agent for one application, such as a browser
or an editor that wants Bitwarden logins, over a private channel instead of
the agent socket. The application (the host) signs in, unlocks and fills
through the verbs below; the agent keeps the keys.

It is free to use: rbw-ng is MIT licensed, and nothing here is tied to one
application. A host whose plugins must speak a message format of its own
runs a small bridge that translates between that format and this one.

## Why an agent and not the `bw` command

- Secrets stay in the agent. The host gets the logins' names, usernames and
  addresses, and a password or code only for the login it is filling, only
  on a page the login's addresses match.
- No session key to keep, no master password in an environment variable, no
  error text to parse: sign-in is a conversation of typed messages.
- The agent keeps an encrypted copy of the vault, so reads work offline and
  answer in milliseconds, and it hears about changes from the server's
  websocket instead of polling.

## Running

```sh
rbw-agent --embedded [--accounts] [--fd N] [--dir PATH]
```

- The channel is stdin and stdout, or with `--fd` a stream socket the host
  passed as that descriptor. Messages are newline-delimited JSON, one object
  per line, at most 1 MB.
- `--dir` (an absolute path) holds the config, the encrypted vault copy and
  the device id, apart from the user's own rbw. Without it the agent uses
  rbw's usual folders for `RBW_PROFILE`.
- The agent stays in the foreground, logs to stderr (`RUST_LOG`), and exits
  when the host closes the channel. The vault locks with it.
- `--accounts` serves several accounts at once; see
  [Several accounts](#several-accounts).

## Messages

The agent starts with an event saying what it is:

```json
{"event": "ready", "data": {"protocol": 1, "provider": "bitwarden", "agent": "rbw-ng 1.19.0", "capabilities": {"totp": true, "save": true, "edit": true, "delete": true, "reveal": true, "generate": ["random", "letters", "numbers", "words"], "servers": [{"id": "bitwarden.com", "name": "bitwarden.com", "detail": "US cloud"}, {"id": "bitwarden.eu", "name": "bitwarden.eu", "detail": "EU cloud"}], "selfHosted": true, "hostKey": ["session", "persistent"], "passkeys": false}}}
```

A host refuses a `protocol` it doesn't know. The capabilities let a host
draw its screens without knowing the provider: `servers` are the choices for
`signIn`'s `server`, and `selfHosted` adds a field for an address of the
person's own.

Requests and answers:

```json
{"id": 12, "method": "fill", "params": {...}, "deadline": 5000}
{"id": 12, "result": {"values": {"password": "…"}}}
{"id": 13, "error": {"code": "locked", "message": "The vault is locked."}}
{"cancel": 12}
```

- `id` is an integer or a string of at most 64 bytes, echoed in the answer.
  Requests run concurrently; answers may come in any order.
- `deadline` (milliseconds, optional) bounds the work: past it the answer is
  a `failed` error.
- A cancelled request never gets an answer.

Events:

```json
{"event": "state", "data": {"state": "locked"}}
{"event": "changed", "data": {"syncedAt": 1732400000000}}
```

- `state` when the vault locks (timeout, `lock`, a server logout), unlocks or
  signs out.
- `changed` after a sync, so the host refreshes `items`.

## Errors


| Code | Meaning |
| --- | --- |
| `bad_request` | A missing or malformed parameter |
| `unknown_verb` | A verb this protocol version doesn't have |
| `signed_out` | No account: sign in first |
| `locked` | Signed in, locked: unlock first |
| `wrong_password` | The master password is wrong |
| `wrong_code` | The two-step or new-device code is wrong |
| `not_found` | No such item, or it has no such field |
| `origin_mismatch` | The item's addresses don't match the origin |
| `reprompt` | The item asks for the master password again (`masterPassword`) |
| `conflict` | The item changed since the revision given |
| `offline` | The server can't be reached |
| `server` | The server refused the request (too many attempts included); `message` says why |
| `failed` | Anything else; `message` says what |

`message` is plain English for logs and as a fallback. Hosts show their own
wording for the codes they know.


## Verbs

### `status`

```json
{} -> {"state": "unlocked", "account": "me@example.com", "server": "https://vault.bitwarden.eu", "syncedAt": 1732400000000, "hostKey": "persistent"}
```

`state` is `signedOut`, `locked` or `unlocked`. `hostKey` says which Touch ID
key the agent holds a wrapped vault key for: `session`, `persistent` or
`null`.

### `signIn`

```json
{"server": "bitwarden.eu", "email": "me@example.com", "password": "…", "method": "0", "code": "123456"}
```

- `server`: `bitwarden.com` (default), `bitwarden.eu`, or a self-hosted
  `https://` address.
- First call without `method` or `code`. The answer is one of:
  - `{"state": "unlocked"}`: signed in and unlocked; the agent syncs and sends
    `changed`.
  - `{"needs": "code", "methods": [{"id": "0", "name": "Authenticator app"}, {"id": "1", "name": "Email"}, {"id": "3", "name": "YubiKey OTP"}]}`:
    two-step login. Call again with the same fields plus `method` and `code`.
    Choosing `1` (email) without a `code` makes Bitwarden send the email and
    answers `{"needs": "code", "methods": [{"id": "1", ...}]}`.
  - `{"needs": "newDeviceCode", "email": "me@example.com"}`: Bitwarden emailed
    a code to approve this device. Call again with `code`.
- The agent keeps no password between calls: the host sends it each time and
  forgets it once the answer is `unlocked`.
- `wrapKey` (`session` or `persistent`), as for `unlock`.

### `unlock`

```json
{"password": "…", "wrapKey": "session"} -> {"state": "unlocked", "hostKey": "base64…"}
{"hostKey": "base64…"} -> {"state": "unlocked"}
```

With `password`, and `wrapKey` set, the agent also returns a new `hostKey`
(see [Touch ID](#touch-id)). With `hostKey` alone it unlocks without the
password, or answers `wrong_password` when the key no longer opens the vault
(a changed master password, a new key) and forgets its wrapped copy.

### `lock`, `signOut`, `sync`

`{}` in, `{"ok": true}` out. `signOut` deletes the encrypted copy and the
wrapped keys. `sync` answers once the sync is done.

### `configure`

```json
{"lockTimeout": 900} -> {"ok": true}
```

How long the vault stays unlocked without use, in seconds (60 to a week;
an hour until set). The host sends it at start and when the setting changes.

### `forgetHostKey`

```json
{"wrapKey": "persistent"} -> {"ok": true}
```

Forgets the wrapped vault key of that kind, or of both kinds without
`wrapKey`. The host sends it when the person turns the feature off.

### `items`

```json
{} -> {"items": [{"id": "6f0c…", "title": "GitHub", "username": "me", "uris": [{"uri": "https://github.com/login", "match": "domain"}], "hasTotp": true, "organization": false, "favorite": false, "reprompt": false, "revision": "2026-11-20T10:15:00.123Z"}]}
```

Logins only, without passwords, codes, notes or custom fields; `hasTotp` and
`hasNotes` say whether there are any. Deleted and archived items are left
out. `match` is `domain`, `host`, `startsWith`,
`exact`, `regex`, `never` or `null` (the account's default, `domain`).

### `match`

```json
{"origin": "https://github.com"} -> {"ids": ["6f0c…"]}
```

The items whose addresses match, with the same rules `fill` enforces.

### `fill`

```json
{"id": "6f0c…", "origin": "https://github.com", "fields": ["username", "password", "totp"]} -> {"values": {"username": "me", "password": "…", "totp": "123456"}}
```

- `origin` must be `https://`, or `http://` on `localhost`. The agent refuses
  with `origin_mismatch` unless one of the item's addresses matches it.
- `chosen: true` lets the person fill an item they picked themselves on a site
  it doesn't match ("fill anyway"). The host sends it only after an explicit
  choice that names the site. The page must still be `https://`.
- A `reprompt` item needs `masterPassword`; without it the answer is
  `reprompt`.
- A field the item doesn't have is left out; `not_found` only when none of the
  fields asked for is there.

### `totp`

```json
{"id": "6f0c…", "origin": "https://github.com"} -> {"code": "123456", "period": 30, "expiresAt": 1732400010000}
```

The current code, never the secret. Same origin rules as `fill`.

### `save`

```json
{"origin": "https://github.com", "title": "GitHub", "username": "me", "password": "…"} -> {"item": {...}}
{"title": "Mail", "username": "me", "password": "…", "uris": [{"uri": "https://mail.example.com", "match": "host"}], "notes": "…", "totp": "otpauth://…"} -> {"item": {...}}
```

Creates a login in the personal vault, syncs, and returns it as `items`
would. A save prompt after a sign-in sends the page's `origin`, which becomes
the login's address; a host's own "add" form sends `uris` instead. `title`
defaults to the first address's host. `password` is required; `username`,
`notes` and `totp` are optional.

### `update`

```json
{"id": "6f0c…", "revision": "2026-11-20T10:15:00.123Z", "title": "GitHub", "username": "me", "password": "…", "totp": "otpauth://…", "notes": null, "uris": [{"uri": "https://github.com", "match": null}]} -> {"item": {...}}
```

Changes only the fields given: `null` removes `username`, `totp` or `notes`,
and `uris` replaces the whole list. A login always keeps a `title` and a
`password`. The server refuses the change with `conflict` when the item
changed after `revision`, so an edit never overwrites a newer one. The old
password goes to the item's password history, as in Bitwarden's own apps.

### `delete`

```json
{"id": "6f0c…", "revision": "2026-11-20T10:15:00.123Z"} -> {"ok": true}
```

Moves the login to Bitwarden's trash, where Bitwarden's apps can restore it
for 30 days. `conflict` if it changed after `revision`.

### `reveal`

```json
{"id": "6f0c…", "fields": ["password", "totp", "notes"]} -> {"values": {"password": "…", "totp": "otpauth://…", "notes": "…"}}
```

A login's secrets for the host itself, such as a sheet where the person views
or edits the login, with no page involved. Unlike `fill` and `totp`, it gives
the code's secret, not a code. A `reprompt` item needs `masterPassword`. A
host should check the person (Touch ID) before it asks.

### `generate`

```json
{"kind": "random", "length": 20} -> {"password": "…"}
```

A new password: `random` (letters, digits and symbols, 8 to 128, default
20), `letters` (letters and digits), `numbers` (4 to 128, default 6) or
`words` (3 to 20 words, default 5). `random` and `letters` passwords have
at least a digit and a letter, and `random` ones a symbol. It needs no
signed in account.

## Several accounts

With `--accounts`, one host uses several Bitwarden accounts, for example one
per browser profile or workspace. Every request names its account:

```json
{"id": 12, "account": "work", "method": "fill", "params": {...}}
{"event": "state", "account": "work", "data": {"state": "locked"}}
```

- An account id is 1 to 64 letters, digits, `_` or `-`, chosen by the host. A
  request without one is refused with `bad_request`, and so is a request
  naming an account sent to an agent started without `--accounts`.
- Each account is an ordinary embedded agent in its own process
  (`rbw-agent --embedded --dir <root>/<account>`), started on the account's
  first request. One account's keys never share memory with another's, and
  each signs in, locks, syncs and keeps its host keys on its own.
- The root is `--dir`, or `accounts` in rbw's data folder. Signing out stops
  the account's agent and deletes its folder before the answer.
- Events carry the account they're about. If an account's agent stops, its
  waiting requests fail and a `state` event says it's `locked`; the next
  request starts it again.
- `{"id": 3, "method": "accounts"}`, without an account, lists the accounts
  that have a folder: `{"accounts": ["personal", "work"]}`. Their agents start
  only when a request names them, so listing costs nothing.
- `generate` works without an account too.
- `ready` says `"accounts": true` in its capabilities.

The agent started with `--accounts` holds no keys itself: it only starts the
account agents and passes messages between them and the host.

## Host keys (Touch ID)

An application may want to unlock without the master password, for example
behind Touch ID. The agent may run where it can't reach the system keychain or
biometrics (a browser plugin sandbox), and the vault key should never leave
it, so the two share the work:

1. After a password unlock with `wrapKey`, the agent makes a random 512-bit
   `hostKey` (an AES-256 key and an HMAC-SHA256 key, as Bitwarden uses),
   encrypts the vault key with it, keeps the encrypted copy and returns
   `hostKey` to the host.
2. The host keeps `hostKey`:
   - `session`: in memory, gone when the host quits. The agent keeps its
     encrypted copy in memory too.
   - `persistent` (opt in): somewhere that survives a restart, such as the
     macOS Keychain with `biometryCurrentSet` and this-device-only access.
     The agent keeps its encrypted copy in its data folder, which is useless
     without the host's half.
3. When the vault locks, the host checks the person (Touch ID) and sends
   `unlock {hostKey}`.

What persistent costs: anyone who can make the host release its key (for
Touch ID, holding the Mac and an enrolled finger) unlocks without the master
password, until the master password changes. Each wrap makes a new key, and
a changed account key retires the old copies.

## Security notes

- The channel is private: stdin and stdout of a process the host started, or
  a socket the host passed. The agent opens no socket of its own in this
  mode, runs no SSH agent, and never prompts with pinentry.
- Secrets leave the agent one login at a time, for a page its addresses
  match. The origin check limits what a bug in the host's fill logic can
  leak; it can't protect against a compromised host, which could name any
  origin.
- Matching follows the rbw command line: `domain` matches the stored host and
  its subdomains on the same scheme. Bitwarden's apps compare registrable
  domains, which matches more; rbw-ng stays with the narrower rule.
- `--dir` keeps the host's account, encrypted vault copy and device id apart
  from the user's own rbw.
- The agent never writes a secret to its log, and refuses to be traced
  (`PR_SET_DUMPABLE`, `PT_DENY_ATTACH`), as the regular agent does.

## Trying it

`tools/embedded-host-sim` plays a host against a real server and checks every
answer, over stdin and stdout and over a passed socket: sign-in with and
without two-step login, saves, fills, origin checks, edits with revision
checks, renames, address edits, the trash, codes, both host keys across a
restart, cancellation, two accounts and sign-out.

```sh
cargo build
docker run -d --name rbw-embedded-vw -p 127.0.0.1:18089:80 \
  -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest
tools/embedded-host-sim --server http://localhost:18089 --register
docker rm -f rbw-embedded-vw
```

`--register` creates throwaway accounts (it needs Python's `cryptography`
package); `--verbose` also prints the agent's events.
