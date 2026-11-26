use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    // the client restarts an agent that reports a different version, so
    // different releases must never map to the same number
    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000
        + unwrap(&u32::from_str_radix(patch, 10))
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    action: Action,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            action,
        }
    }

    pub fn into_parts(self) -> (Action, Environment) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
    "RBW_NONINTERACTIVE",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    pub fn from_process() -> Self {
        let env_vars = std::env::vars_os()
            .filter(|(var_name, _)| {
                (*ENVIRONMENT_VARIABLES_OS).contains(var_name)
            })
            .collect();
        Self::new(std::env::var_os("RBW_TTY"), env_vars)
    }

    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    // The same environment without a terminal, for prompts that must not
    // appear in one.
    #[must_use]
    pub fn without_tty(&self) -> Self {
        Self {
            tty: None,
            env_vars: self.env_vars.clone(),
        }
    }

    // Whether the caller set RBW_NONINTERACTIVE: a program that drives rbw
    // and can't answer a prompt.
    pub fn is_noninteractive(&self) -> bool {
        self.env_vars.iter().any(|(name, value)| {
            name.0 == "RBW_NONINTERACTIVE"
                && !value.0.is_empty()
                && value.0 != "0"
        })
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect()
    }
}

// A secret in a request, wiped from memory when dropped: the agent lives
// for long.
pub type Secret = zeroize::Zeroizing<String>;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Register,
    Unlock,
    CheckLock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    // decrypt a batch of cipherstrings with a single round trip; per-item
    // failures are reported per item instead of failing the whole batch
    DecryptMany {
        items: Vec<DecryptItem>,
    },
    Encrypt {
        plaintext: Secret,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    ClipboardStore {
        text: Secret,
    },
    // The same as Login, Register and Unlock, with the secrets from the
    // caller instead of pinentry, for programs that drive rbw. With
    // session, the answer is a session key (Response::Session) that
    // UnlockSession takes later.
    LoginWith {
        password: Secret,
        code: Option<LoginCode>,
        session: bool,
    },
    RegisterWith {
        client_id: String,
        client_secret: Secret,
    },
    UnlockWith {
        password: Secret,
        session: bool,
    },
    UnlockSession {
        session: Secret,
    },
    ForgetSession,
    // Unlock with Touch ID only, failing instead of asking for the master
    // password
    UnlockTouchId,
    // Let the protected values of an entry with master password reprompt
    // be decrypted for a while, once the master password checks out: the
    // one given, or the one pinentry asks for without it
    UnlockEntry {
        id: String,
        password: Option<Secret>,
    },
    // Answered with Response::Status
    Status,
    // Take over the settings that change only what the agent does, such as
    // the lock timeout, without locking
    ReloadConfig,
    // Serve SSH also at the socket of the macOS service, which rbw ssh-agent
    // install leaves unloaded until this agent stops
    ServeServiceSocket,
    Quit,
    Version,
}

// Why one value of a DecryptMany failed.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DecryptError {
    pub error: String,
    pub code: Option<ErrorCode>,
}

impl DecryptError {
    pub fn into_error(self) -> anyhow::Error {
        crate::error::coded(self.code.unwrap_or(ErrorCode::Other), self.error)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, Hash,
)]
pub struct DecryptItem {
    pub cipherstring: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
}

// A two-step login code. Without a method, it is the code Bitwarden emails
// to verify a new device.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct LoginCode {
    // Bitwarden's id: 0 authenticator app, 1 email, 3 YubiKey OTP
    pub method: Option<u8>,
    pub code: String,
}

// What went wrong, for programs that drive rbw: the "code" of the JSON
// error that RBW_ERROR_FORMAT=json prints. The codes are stable; a new kind
// of failure gets a new code.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ErrorCode {
    NotLoggedIn,
    Locked,
    // rbw would have to ask, and RBW_NONINTERACTIVE is set
    InputRequired,
    IncorrectPassword,
    // Bitwarden's ids of the methods the server offers, that rbw supports
    TwoStepRequired { methods: Vec<u8> },
    TwoStepCodeSent,
    NewDeviceCodeRequired,
    // the server wants the device registered with the account's personal
    // API key (rbw register) before it accepts the master password
    RegistrationRequired,
    IncorrectCode,
    TwoStepUnsupported,
    SessionInvalid,
    TouchIdCanceled,
    TouchIdUnavailable,
    // the entry asks for the master password again before its secrets are
    // shown, and wasn't unlocked with rbw item unlock
    RepromptRequired,
    // no such entry, folder or field
    NotFound,
    // the entry changed on the server since the last sync
    Conflict,
    // the server refused the change, for example a read-only collection
    Forbidden,
    // rbw can't do this yet
    Unsupported,
    InvalidInput,
    // the server can't be reached
    Network,
    // the server's address leads to something that isn't a Bitwarden
    // server, such as a web site or a wrong path
    WrongServer,
    // the server answered with an error
    Server { status: Option<u16> },
    // rbw-agent can't be started or reached
    Agent,
    Other,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error {
        error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<ErrorCode>,
    },
    // secrets in an answer are wiped from memory when dropped too; on the
    // wire they are plain strings, as before
    Decrypt {
        plaintext: Secret,
    },
    DecryptMany {
        plaintexts: Vec<Result<Secret, DecryptError>>,
    },
    Encrypt {
        cipherstring: String,
    },
    Version {
        version: u32,
    },
    Session {
        session: Secret,
    },
    Status {
        unlocked: bool,
        // Touch ID can unlock the locked vault now
        touch_id: bool,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn secrets_in_answers_are_plain_strings_on_the_wire() {
        let json = r#"{"type":"DecryptMany","plaintexts":[{"Ok":"hunter2"},{"Err":{"error":"no","code":{"code":"locked"}}}]}"#;
        let res: Response = serde_json::from_str(json).unwrap();
        let Response::DecryptMany { plaintexts } = &res else {
            panic!("{res:?}");
        };
        assert_eq!(plaintexts[0].as_ref().unwrap().as_str(), "hunter2");
        assert_eq!(serde_json::to_string(&res).unwrap(), json);

        let res = Response::Decrypt {
            plaintext: Secret::new("hunter2".to_string()),
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"type":"Decrypt","plaintext":"hunter2"}"#
        );
        let res = Response::Session {
            session: Secret::new("key".to_string()),
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"type":"Session","session":"key"}"#
        );
    }
}
