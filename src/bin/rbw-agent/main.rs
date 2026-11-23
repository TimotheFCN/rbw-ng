use anyhow::Context as _;

mod actions;
mod agent;
#[cfg(target_os = "macos")]
mod biometric;
mod daemon;
mod debugger;
mod embedded;
mod notifications;
mod peer;
#[cfg(target_os = "macos")]
mod presence;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

type SharedState = std::sync::Arc<tokio::sync::Mutex<crate::state::State>>;

// The agent's state, and the lock and sync timers' channels. The embedded
// mode runs no Touch ID helper, SSH agent or clipboard: the host has its own.
fn new_state(
    config: &rbw::config::Config,
    embedded: bool,
) -> (
    SharedState,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let timeout_duration =
        std::time::Duration::from_secs(config.lock_timeout);
    let sync_timeout_duration =
        std::time::Duration::from_secs(config.sync_interval);
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
    if sync_timeout_duration > std::time::Duration::ZERO {
        sync_timeout.set(sync_timeout_duration);
    }
    let notifications_handler = crate::notifications::Handler::new();
    let state =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::state::State {
            priv_key: None,
            org_keys: None,
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            unlock_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(target_os = "macos")]
            touch_id_unlock: !embedded && config.touch_id_unlock,
            ssh_confirm: !embedded && config.confirms_ssh_signatures(),
            #[cfg(target_os = "macos")]
            biometric_unlock: None,
            last_environment: rbw::protocol::Environment::from_process(),
            #[cfg(feature = "clipboard")]
            // the host handles the clipboard, and may run the agent where
            // there is none (a sandbox)
            clipboard: if embedded {
                None
            } else {
                arboard::Clipboard::new()
                    .inspect_err(|e| {
                        log::warn!("couldn't create clipboard context: {e}");
                    })
                    .ok()
            },
        }));

    (state, timer_r, sync_timer_r)
}

// rbw-agent --embedded: serves one application over a private channel, in
// the foreground, until the application closes the channel.
async fn embedded_main(
    options: crate::embedded::Options,
) -> anyhow::Result<()> {
    // the first start has no config yet: the host signs in through the agent
    let config = if let Ok(config) = rbw::config::Config::load() {
        config
    } else {
        let config = rbw::config::Config::default();
        config.save()?;
        config
    };
    let (state, timer_r, sync_timer_r) = new_state(&config, true);
    crate::embedded::run(&options, state, timer_r, sync_timer_r).await
}

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = rbw::config::Config::load()?;
    let (state, timer_r, sync_timer_r) = new_state(&config, false);

    let agent =
        crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::try_join!(agent.run(listener), ssh_agent.run())?;

    Ok(())
}

fn real_main() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if std::env::args().nth(1).as_deref()
        == Some(crate::presence::HELPER_ARGUMENT)
    {
        crate::presence::helper_main();
    }

    #[cfg(target_os = "macos")]
    if std::env::args().nth(1).as_deref()
        == Some(crate::biometric::HELPER_ARGUMENT)
    {
        // Do not acknowledge the helper or accept vault key material until
        // both debugger attachment and core dumps have been disabled.
        debugger::disable_tracing()
            .context("failed to secure biometric helper")?;
        return crate::biometric::helper_main();
    }

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(crate::embedded::ARGUMENT) {
        let options = crate::embedded::options(&args[2..])?;
        if let Err(e) = debugger::disable_tracing() {
            log::warn!("{e}");
        }
        let runtime =
            tokio::runtime::Runtime::new().context("failed to start")?;
        if options.accounts {
            return runtime.block_on(crate::embedded::run_accounts(&options));
        }
        if let Some(dir) = &options.dir {
            rbw::dirs::set_base_dir(dir.clone())?;
        }
        rbw::dirs::make_all()?;
        return runtime.block_on(embedded_main(options));
    }

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    rbw::dirs::make_all()?;

    let startup_ack =
        daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) = tokio_main(startup_ack).await {
            // this unwrap is fine because it's the only real option here
            w.send(e).unwrap();
        }
    });

    if let Ok(e) = r.recv() {
        return Err(e);
    }

    Ok(())
}

fn main() {
    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
