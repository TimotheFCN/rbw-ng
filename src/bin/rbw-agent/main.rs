use anyhow::Context as _;

mod actions;
mod activation;
mod agent;
#[cfg(target_os = "macos")]
mod biometric;
mod daemon;
mod debugger;
mod notifications;
mod peer;
#[cfg(target_os = "macos")]
mod presence;
mod scripted;
mod session;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
    sockets: crate::activation::Sockets,
) -> anyhow::Result<()> {
    let listener = match sockets.control {
        Some(listener) => tokio::net::UnixListener::from_std(listener)?,
        None => crate::sock::listen()?,
    };

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = rbw::config::Config::load()?;
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
            master_password_reprompt: std::collections::HashMap::new(),
            master_password_reprompt_initialized: false,
            unlocked_entries: std::collections::HashMap::new(),
            unlock_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(target_os = "macos")]
            touch_id_unlock: config.touch_id_unlock,
            ssh_confirm: config.confirms_ssh_signatures(),
            #[cfg(target_os = "macos")]
            biometric_unlock: None,
            last_environment: rbw::protocol::Environment::from_process(),
            #[cfg(feature = "clipboard")]
            clipboard: arboard::Clipboard::new()
                .inspect_err(|e| {
                    log::warn!("couldn't create clipboard context: {e}");
                })
                .ok(),
        }));

    let agent =
        crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::try_join!(agent.run(listener), ssh_agent.run(sockets.ssh))?;

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

    let mode = daemon::Mode::from_args();
    // before any thread starts
    let sockets = if mode == daemon::Mode::Service {
        crate::activation::take()?
    } else {
        crate::activation::Sockets::default()
    };

    if mode != daemon::Mode::Service && crate::sock::answers() {
        // the code rbw takes for an agent that already runs
        eprintln!(
            "an agent already answers on {}",
            rbw::dirs::socket_file().display()
        );
        std::process::exit(23);
    }

    rbw::dirs::make_all()?;

    let startup_ack =
        daemon::daemonize(mode).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) = tokio_main(startup_ack, sockets).await {
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
