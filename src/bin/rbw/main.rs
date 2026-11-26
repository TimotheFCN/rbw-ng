use std::io::Write as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod items;
mod scripting;
mod service;
mod sock;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register {
        #[arg(
            long,
            help = "Read the API key from RBW_CLIENT_ID and \
                RBW_CLIENT_SECRET instead of asking"
        )]
        api_key_env: bool,
    },

    #[command(about = "Log in to the Bitwarden server")]
    Login {
        #[arg(
            long,
            help = "Read the master password from stdin instead of asking"
        )]
        password_stdin: bool,
        #[arg(
            long,
            value_name = "ID",
            help = "Two-step login method of --code: 0 authenticator app, \
                1 email, 3 YubiKey OTP. Without it, --code is the new \
                device verification code Bitwarden emails"
        )]
        method: Option<u8>,
        #[arg(long, help = "Two-step login or new device code")]
        code: Option<String>,
        #[arg(
            long,
            conflicts_with = "code",
            help = "Read the code of --code from RBW_CODE instead, out of \
                sight of other users of this computer"
        )]
        code_env: bool,
        #[arg(
            long,
            help = "Print a session key that unlocks the vault again \
                through RBW_SESSION"
        )]
        session: bool,
    },

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock {
        #[arg(
            long,
            help = "Read the master password from stdin instead of asking"
        )]
        password_stdin: bool,
        #[arg(
            long,
            help = "Unlock with Touch ID only, failing instead of asking \
                for the master password (macOS)"
        )]
        touch_id: bool,
        #[arg(
            long,
            help = "Print a session key that unlocks the vault again \
                through RBW_SESSION"
        )]
        session: bool,
    },

    #[command(
        about = "Show whether rbw is logged in and unlocked",
        long_about = "Show whether rbw is logged in and unlocked\n\n\
            Prints unauthenticated, locked or unlocked, or with --json an \
            object with status, serverUrl, userEmail, lastSync and touchId."
    )]
    Status {
        #[arg(long, help = "Display output as JSON")]
        json: bool,
    },

    #[command(
        about = "Read and save entries as JSON, for other programs",
        long_about = "Read and save entries as JSON, for other programs\n\n\
            Entries are in Bitwarden's item format, the format of the \
            official CLI, and are found by id only."
    )]
    Item {
        #[command(subcommand)]
        item: Item,
    },

    #[command(
        about = "List and create folders as JSON, for other programs",
        long_about = "List and create folders as JSON, for other programs\n\n\
            Folders are in Bitwarden's format, the format of the official \
            CLI."
    )]
    Folder {
        #[command(subcommand)]
        folder: Folder,
    },

    #[command(
        about = "Print a website's icon from the server's icon service",
        long_about = "Print a website's icon from the server's icon service\n\n\
            Writes the image the service sends to stdout, for programs that \
            show entries with their website's icon. It needs no login."
    )]
    Icon {
        #[arg(help = "The website's host name, such as github.com")]
        host: String,
    },

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[structopt(short, long, help = "List fields in this entry")]
        list_fields: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["user", "uri"],
            help = "Create a secure note instead of a login; the editor \
                    contents (or stdin) are stored as the note"
        )]
        secure_note: bool,
        #[arg(
            long,
            value_name = "NAME=VALUE",
            value_parser = parse_field,
            help = "Add a text custom field (may be repeated)",
            number_of_values = 1
        )]
        field: Vec<(String, String)>,
        #[arg(
            long,
            value_name = "NAME=VALUE",
            value_parser = parse_field,
            help = "Add a hidden custom field (may be repeated). The value \
                    ends up in shell history and is visible to other \
                    processes; `rbw edit --field NAME --create` reads it \
                    from stdin or the editor instead",
            number_of_values = 1
        )]
        hidden_field: Vec<(String, String)>,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.\n\n\
            A password is drawn from upper-case letters, lower-case \
            letters, digits and symbols, each character uniformly at \
            random, unless options leave some out. With --each-class, it \
            is drawn uniformly from the passwords that hold a character of \
            each of these classes.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("classes")
            .args(["no_uppercase", "no_lowercase", "no_numbers", "no_symbols"])
            .multiple(true),
        group = clap::ArgGroup::new("password-type")
            .args(["only_numbers", "nonconfusables", "diceware"])
            .conflicts_with("classes"),
        group = clap::ArgGroup::new("passphrase")
            .args(["separator", "capitalize", "include_number"])
            .multiple(true)
            .requires("diceware"),
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-uppercase",
            help = "Generate a password without upper-case letters"
        )]
        no_uppercase: bool,
        #[arg(
            long = "no-lowercase",
            help = "Generate a password without lower-case letters"
        )]
        no_lowercase: bool,
        #[arg(
            long = "no-numbers",
            help = "Generate a password without digits"
        )]
        no_numbers: bool,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long = "each-class",
            conflicts_with = "diceware",
            help = "Generate a password with at least one character of \
                each class it is made of: upper-case letters, lower-case \
                letters, digits and symbols (or, with --nonconfusables, \
                digits and letters)"
        )]
        each_class: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
        #[arg(
            long,
            value_name = "TEXT",
            help = "With --diceware, put this between the words instead \
                of a space"
        )]
        separator: Option<String>,
        #[arg(
            long,
            help = "With --diceware, begin each word with an upper-case \
                letter"
        )]
        capitalize: bool,
        #[arg(
            long = "include-number",
            help = "With --diceware, put a digit after one of the words"
        )]
        include_number: bool,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note.\n\n\
            With --field, only that field is edited: the entry name, \
            notes, a login's username, password, totp or uris (one per \
            line), or a custom field. When stdin is not a terminal, the \
            new value is read from it as is, without the trailing \
            newline; otherwise the editor opens with the current value."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short = 'f',
            long,
            help = "Edit a single field: name, notes, username, password, \
                    totp, uris or the name of a custom field"
        )]
        field: Option<String>,
        #[arg(
            long,
            requires = "field",
            help = "Add the custom field as a hidden field if the entry \
                    doesn't have it"
        )]
        create: bool,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge {
        #[arg(
            long,
            help = "Also remove the profile's configuration and every other \
                file it keeps, and its SSH agent service, so that the \
                profile is gone"
        )]
        all: bool,
    },

    #[command(
        about = "List the profiles on this computer",
        long_about = "List the profiles on this computer\n\n\
            Prints each profile's name, the RBW_PROFILE that selects it, and \
            its email, or with --json an array of objects with profile \
            (null for the default profile), userEmail and serverUrl. With \
            --status, each object also has status, lastSync and touchId, as \
            rbw status --json prints them."
    )]
    Profiles {
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(
            long,
            requires = "json",
            help = "Add each profile's status, as rbw status --json says it, \
                without starting any agent"
        )]
        status: bool,
    },

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "ssh-agent",
        about = "Run the agent as a login service that serves SSH keys to \
            every program"
    )]
    SshAgent {
        #[command(subcommand)]
        cmd: SshAgent,
    },

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },
}

#[derive(Debug, clap::Subcommand)]
enum Item {
    #[command(about = "List every entry, without secrets unless asked")]
    List {
        #[arg(
            long,
            help = "Include passwords, codes, notes, custom fields and \
                password history"
        )]
        secrets: bool,
        #[arg(
            long = "type",
            value_name = "TYPE",
            value_enum,
            help = "List only the entries of this type"
        )]
        ty: Option<items::ItemType>,
    },
    #[command(about = "Show one entry, or one of its fields")]
    Get {
        id: String,
        #[arg(long, value_enum, help = "Print only this field")]
        field: Option<items::Field>,
        #[arg(
            long,
            conflicts_with = "field",
            help = "Add a login's current code as totpCode, as rbw item code \
                prints it"
        )]
        with_code: bool,
    },
    #[command(
        about = "Show a login's current code, its period and when it \
            expires, as JSON"
    )]
    Code { id: String },
    #[command(about = "Add the entry on stdin, as JSON or base64 JSON")]
    Create,
    #[command(about = "Replace an entry with the one on stdin")]
    Edit { id: String },
    #[command(about = "Move an entry to the trash")]
    Delete { id: String },
    #[command(
        about = "Open an entry that asks for the master password again",
        long_about = "Open an entry that asks for the master password again\n\n\
            Its secrets can then be read without the master password until \
            it goes unread for two minutes, or the vault locks."
    )]
    Unlock {
        id: String,
        #[arg(long, help = "Read the master password from stdin")]
        password_stdin: bool,
    },
    #[command(
        about = "Mark or unmark an entry as a favorite, without its secrets"
    )]
    Favorite {
        id: String,
        #[arg(action = clap::ArgAction::Set)]
        favorite: bool,
    },
    #[command(
        about = "Move an entry into a folder, or out of folders without one"
    )]
    Move { id: String, folder: Option<String> },
}

#[derive(Debug, clap::Subcommand)]
enum Folder {
    #[command(about = "List every folder")]
    List,
    #[command(about = "Add a folder and print it")]
    Create { name: String },
}

impl Folder {
    const fn subcommand_name(&self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Create { .. } => "create",
        }
    }
}

impl Item {
    const fn subcommand_name(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Get { .. } => "get",
            Self::Code { .. } => "code",
            Self::Create => "create",
            Self::Edit { .. } => "edit",
            Self::Delete { .. } => "delete",
            Self::Unlock { .. } => "unlock",
            Self::Favorite { .. } => "favorite",
            Self::Move { .. } => "move",
        }
    }
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register { .. } => "register".to_string(),
            Self::Login { .. } => "login".to_string(),
            Self::Unlock { .. } => "unlock".to_string(),
            Self::Status { .. } => "status".to_string(),
            Self::Item { item } => format!("item {}", item.subcommand_name()),
            Self::Folder { folder } => {
                format!("folder {}", folder.subcommand_name())
            }
            Self::Icon { .. } => "icon".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock => "lock".to_string(),
            Self::Purge { .. } => "purge".to_string(),
            Self::Profiles { .. } => "profiles".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::SshAgent { cmd } => {
                format!("ssh-agent {}", cmd.subcommand_name())
            }
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
}

#[derive(Debug, clap::Parser)]
enum SshAgent {
    #[command(
        about = "Start the agent with the system's service manager (launchd \
            or systemd) and make it the SSH agent of the login session"
    )]
    Install,
    #[command(about = "Undo `rbw ssh-agent install`")]
    Uninstall,
    #[command(
        about = "Show whether the agent runs as a service and serves the \
            session's SSH_AUTH_SOCK"
    )]
    Status {
        #[arg(long, help = "Display output as JSON")]
        json: bool,
    },
    #[command(about = "Print the path of the agent's SSH socket")]
    Socket,
}

impl SshAgent {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Status { .. } => "status",
            Self::Socket => "socket",
        }
        .to_string()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

// the name ends at the first '=', so values can contain '=' but names can't
fn parse_field(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .ok_or_else(|| {
            "expected NAME=VALUE with a non-empty NAME".to_string()
        })
}

// RBW_ERROR_FORMAT=json prints errors as JSON with a code, for programs
// that drive rbw. See docs/scripting.md.
fn json_errors() -> bool {
    std::env::var_os("RBW_ERROR_FORMAT")
        .is_some_and(|format| format == "json")
}

fn print_json_error(code: rbw::protocol::ErrorCode, message: &str) {
    let mut error = serde_json::to_value(code).unwrap_or_default();
    error["message"] = message.into();
    eprintln!("{error}");
}

fn main() {
    let opt = Opt::try_parse().unwrap_or_else(|e| {
        // --help and --version print on stdout and succeed
        if json_errors() && e.use_stderr() {
            let message = match e.kind() {
                clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    "rbw: a command is missing".to_string()
                }
                // the error's lines, without the usage that follows them
                _ => e
                    .to_string()
                    .lines()
                    .take_while(|line| !line.is_empty())
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_start_matches("error: ")
                    .to_string(),
            };
            print_json_error(rbw::protocol::ErrorCode::InvalidInput, &message);
            std::process::exit(1);
        }
        e.exit()
    });

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = opt.subcommand_name();
    let res = rbw::dirs::check_profile()
        .map_err(anyhow::Error::from)
        .and_then(|()| run(opt))
        .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        if json_errors() {
            print_json_error(rbw::error::code(&e), &format!("{e:#}"));
        } else {
            eprintln!("{e:#}");
        }
        std::process::exit(1);
    }
}

fn run(opt: Opt) -> anyhow::Result<()> {
    match opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
        },
        Opt::Register { api_key_env } => scripting::register(api_key_env),
        Opt::Login {
            password_stdin,
            method,
            code,
            code_env,
            session,
        } => {
            scripting::login(password_stdin, method, code, code_env, session)
        }
        Opt::Unlock {
            password_stdin,
            session,
            touch_id,
        } => scripting::unlock(password_stdin, session, touch_id),
        Opt::Status { json } => scripting::status(json),
        Opt::Item { item } => match item {
            Item::List { secrets, ty } => items::list(secrets, ty),
            Item::Get {
                id,
                field,
                with_code,
            } => items::get(&id, field, with_code),
            Item::Code { id } => items::code(&id),
            Item::Create => items::create(),
            Item::Edit { id } => items::edit(&id),
            Item::Delete { id } => items::delete(&id),
            Item::Unlock { id, password_stdin } => {
                items::unlock(&id, password_stdin)
            }
            Item::Favorite { id, favorite } => items::favorite(&id, favorite),
            Item::Move { id, folder } => {
                items::move_to(&id, folder.as_deref())
            }
        },
        Opt::Folder { folder } => match folder {
            Folder::List => items::folder_list(),
            Folder::Create { name } => items::folder_create(&name),
        },
        Opt::Icon { host } => scripting::icon(&host),
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::List { fields, raw } => commands::list(&fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
        } => commands::get(
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
        ),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => commands::search(&term, &fields, folder.as_deref(), raw),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
            secure_note,
            field,
            hidden_field,
        } => commands::add(
            &name,
            user.as_deref(),
            &uri.iter()
                // XXX not sure what the ui for specifying the match type
                // should be
                .map(|uri| (uri.clone(), None))
                .collect::<Vec<_>>(),
            folder.as_deref(),
            secure_note,
            &field
                .into_iter()
                .map(|(name, value)| (name, value, rbw::api::FieldType::Text))
                .chain(hidden_field.into_iter().map(|(name, value)| {
                    (name, value, rbw::api::FieldType::Hidden)
                }))
                .collect::<Vec<_>>(),
        ),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_uppercase,
            no_lowercase,
            no_numbers,
            no_symbols,
            only_numbers,
            nonconfusables,
            each_class,
            diceware,
            separator,
            capitalize,
            include_number,
        } => {
            let options = if diceware {
                rbw::pwgen::Options::Passphrase(rbw::pwgen::Passphrase {
                    words: len,
                    separator: separator.unwrap_or_else(|| " ".to_string()),
                    capitalize,
                    number: include_number,
                })
            } else {
                let characters = if nonconfusables {
                    rbw::pwgen::Characters::NonConfusables
                } else {
                    rbw::pwgen::Characters::Classes {
                        uppercase: !no_uppercase && !only_numbers,
                        lowercase: !no_lowercase && !only_numbers,
                        numbers: !no_numbers,
                        symbols: !no_symbols && !only_numbers,
                    }
                };
                rbw::pwgen::Options::Password(rbw::pwgen::Password {
                    length: len,
                    characters,
                    each_class,
                })
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                &options,
            )
        }
        Opt::Edit {
            find_args,
            field,
            create,
        } => commands::edit(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            create,
            find_args.ignorecase,
        ),
        Opt::Remove { find_args } => commands::remove(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::History { find_args } => commands::history(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Lock => commands::lock(),
        Opt::Purge { all } => commands::purge(all),
        Opt::Profiles { json, status } => commands::profiles(json, status),
        Opt::StopAgent => commands::stop_agent(),
        Opt::SshAgent { cmd } => match cmd {
            SshAgent::Install => commands::ssh_agent_install(),
            SshAgent::Uninstall => service::uninstall(),
            SshAgent::Status { json } => service::status(json),
            SshAgent::Socket => {
                service::socket();
                Ok(())
            }
        },
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cli_definition() {
        Opt::command().debug_assert();
    }

    #[test]
    fn test_parse_field() {
        assert_eq!(
            parse_field("name=value"),
            Ok(("name".to_string(), "value".to_string()))
        );
        assert_eq!(
            parse_field("name=a=b"),
            Ok(("name".to_string(), "a=b".to_string()))
        );
        assert_eq!(
            parse_field("name="),
            Ok(("name".to_string(), String::new()))
        );
        assert!(parse_field("name").is_err());
        assert!(parse_field("=value").is_err());
        assert!(parse_field("").is_err());
    }

    #[test]
    fn test_add_and_edit_args() {
        let Ok(Opt::Add {
            field,
            hidden_field,
            secure_note,
            ..
        }) = Opt::try_parse_from([
            "rbw",
            "add",
            "entry",
            "--secure-note",
            "--field",
            "a=1",
            "--hidden-field",
            "b=2",
            "--field",
            "c=3",
        ])
        else {
            panic!("failed to parse");
        };
        assert!(secure_note);
        assert_eq!(
            field,
            [
                ("a".to_string(), "1".to_string()),
                ("c".to_string(), "3".to_string())
            ]
        );
        assert_eq!(hidden_field, [("b".to_string(), "2".to_string())]);

        let Ok(Opt::Edit { field, create, .. }) = Opt::try_parse_from([
            "rbw", "edit", "entry", "-f", "password", "--create",
        ]) else {
            panic!("failed to parse");
        };
        assert_eq!(field.as_deref(), Some("password"));
        assert!(create);

        for args in [
            &["rbw", "edit", "entry", "--create"][..],
            &["rbw", "add", "entry", "user", "--secure-note"][..],
            &["rbw", "add", "entry", "--secure-note", "--uri", "x"][..],
            &["rbw", "add", "entry", "--field", "novalue"][..],
        ] {
            assert!(Opt::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn generate_options_combine_where_they_make_sense() {
        for args in [
            &["rbw", "generate", "12", "--no-numbers", "--no-symbols"][..],
            &["rbw", "generate", "12", "--no-uppercase", "--each-class"][..],
            &["rbw", "generate", "12", "--nonconfusables", "--each-class"][..],
            &["rbw", "generate", "12", "--only-numbers"][..],
            &[
                "rbw",
                "generate",
                "5",
                "--diceware",
                "--separator",
                "-",
                "--capitalize",
                "--include-number",
            ][..],
        ] {
            assert!(Opt::try_parse_from(args).is_ok(), "{args:?}");
        }
        for args in [
            &["rbw", "generate", "12", "--only-numbers", "--no-symbols"][..],
            &["rbw", "generate", "12", "--nonconfusables", "--no-numbers"][..],
            &["rbw", "generate", "12", "--diceware", "--no-symbols"][..],
            &["rbw", "generate", "12", "--diceware", "--each-class"][..],
            &["rbw", "generate", "12", "--diceware", "--only-numbers"][..],
            &["rbw", "generate", "12", "--separator", "-"][..],
            &["rbw", "generate", "12", "--capitalize"][..],
            &["rbw", "generate", "12", "--include-number"][..],
        ] {
            assert!(Opt::try_parse_from(args).is_err(), "{args:?}");
        }
    }
}
