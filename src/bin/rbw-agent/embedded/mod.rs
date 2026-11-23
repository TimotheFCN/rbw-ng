// rbw-agent --embedded: the agent serving one application that embeds it,
// such as a browser's password manager, over a private channel instead of
// the agent socket. With --accounts it serves several accounts, each in an
// agent of its own (accounts.rs). See docs/embedding.md.

use futures_util::StreamExt as _;
use serde_json::{json, Value};

mod accounts;
mod framing;
mod hostkey;
mod transport;
mod verbs;

pub const ARGUMENT: &str = "--embedded";

const PROTOCOL: u64 = 1;

const USAGE: &str =
    "usage: rbw-agent --embedded [--accounts] [--fd N] [--dir PATH]";

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub source: transport::Source,
    // with accounts, the folder that holds one folder per account
    pub dir: Option<std::path::PathBuf>,
    pub accounts: bool,
}

// The arguments after --embedded.
pub fn options(args: &[String]) -> anyhow::Result<Options> {
    let mut fd = None;
    let mut dir = None;
    let mut accounts = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next().ok_or_else(|| {
                anyhow::anyhow!("{arg} needs a value\n{USAGE}")
            })
        };
        match arg.as_str() {
            "--fd" => {
                fd = Some(value()?.parse::<i32>().map_err(|_| {
                    anyhow::anyhow!("--fd needs a descriptor number\n{USAGE}")
                })?);
            }
            "--dir" => dir = Some(std::path::PathBuf::from(value()?)),
            "--accounts" => accounts = true,
            _ => {
                return Err(anyhow::anyhow!("unknown option {arg}\n{USAGE}"))
            }
        }
    }
    if let Some(dir) = &dir {
        if !dir.is_absolute() {
            return Err(anyhow::anyhow!("--dir needs an absolute path"));
        }
    }
    Ok(Options {
        source: fd.map_or(transport::Source::Stdio, transport::Source::Fd),
        dir,
        accounts,
    })
}

fn ready(accounts: bool) -> Value {
    json!({
        "protocol": PROTOCOL,
        "provider": "bitwarden",
        "agent": format!("rbw-ng {}", env!("CARGO_PKG_VERSION")),
        "capabilities": {
            "totp": true,
            "save": true,
            "edit": true,
            "delete": true,
            "reveal": true,
            "generate": ["random", "letters", "numbers", "words"],
            "servers": [
                { "id": "bitwarden.com", "name": "bitwarden.com", "detail": "US cloud" },
                { "id": "bitwarden.eu", "name": "bitwarden.eu", "detail": "EU cloud" },
            ],
            "selfHosted": true,
            "hostKey": ["session", "persistent"],
            "passkeys": false,
            "accounts": accounts,
        },
    })
}

// rbw-agent --embedded --accounts: the router, which needs neither the
// agent's state nor rbw's folders, only where the accounts live.
pub async fn run_accounts(options: &Options) -> anyhow::Result<()> {
    let root = options.dir.clone().unwrap_or_else(rbw::dirs::accounts_dir);
    accounts::run(options, root).await
}

type Running = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<String, tokio::task::AbortHandle>,
    >,
>;

pub async fn run(
    options: &Options,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    enum Event {
        Message(anyhow::Result<Option<Value>>),
        Timeout,
        Sync,
        Logout,
    }

    let (mut reader, writer) = transport::open(options.source)?;
    log::info!("rbw-ng {} serving the host", env!("CARGO_PKG_VERSION"));
    let out = verbs::Out::new(writer);
    out.send(&framing::start(&ready(false)));

    let ctx = verbs::Ctx {
        state: state.clone(),
        out,
        host: std::sync::Arc::default(),
        writes: std::sync::Arc::default(),
    };

    let notifications =
        state.lock().await.notifications_handler.get_channel().await;

    // the reader runs on its own, so a slow verb never holds up a cancel
    let (messages_w, messages_r) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let message = reader.next().await;
            let done = !matches!(message, Ok(Some(_)));
            if messages_w.send(message).is_err() || done {
                break;
            }
        }
    });

    let mut events = futures_util::stream::select_all([
        tokio_stream::wrappers::UnboundedReceiverStream::new(messages_r)
            .map(Event::Message)
            .boxed(),
        tokio_stream::wrappers::UnboundedReceiverStream::new(timer_r)
            .map(|()| Event::Timeout)
            .boxed(),
        tokio_stream::wrappers::UnboundedReceiverStream::new(sync_timer_r)
            .map(|()| Event::Sync)
            .boxed(),
        tokio_stream::wrappers::UnboundedReceiverStream::new(notifications)
            .map(|message| match message {
                crate::notifications::Message::Sync => Event::Sync,
                crate::notifications::Message::Logout => Event::Logout,
            })
            .boxed(),
    ]);

    let running: Running = std::sync::Arc::default();

    while let Some(event) = events.next().await {
        match event {
            Event::Message(Ok(Some(message))) => {
                handle_message(&ctx, &running, &message);
            }
            Event::Message(Ok(None)) => {
                log::info!("the host closed the channel");
                break;
            }
            Event::Message(Err(e)) => return Err(e),
            Event::Timeout => ctx.lock().await,
            Event::Logout => {
                state.lock().await.clear_all();
                ctx.event("state", &json!({ "state": "locked" }));
            }
            Event::Sync => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    // fails while signed out, which is fine
                    if let Err(e) = ctx.sync().await {
                        log::info!("sync failed: {}", e.message);
                    }
                });
                state.lock().await.set_sync_timeout();
            }
        }
    }

    // the vault locks with the channel: nothing can ask for it any more
    state.lock().await.clear_all();
    Ok(())
}

fn handle_message(ctx: &verbs::Ctx, running: &Running, message: &Value) {
    let (id, verb, params, deadline) = match framing::read(message) {
        framing::Incoming::Request {
            id,
            account: Some(_),
            ..
        } => {
            ctx.out.send(&framing::answer(
                &id,
                Err(json!({
                    "code": "bad_request",
                    "message": "This agent serves one account: start it \
                                with --accounts to serve several.",
                })),
            ));
            return;
        }
        framing::Incoming::Request {
            id,
            verb,
            params,
            deadline,
            account: None,
        } => (id, verb, params, deadline),
        framing::Incoming::Cancel(id) => {
            let cancelled = running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id.to_string());
            if let Some(task) = cancelled {
                task.abort();
            }
            return;
        }
        framing::Incoming::Refuse(reply) => {
            log::info!("refused a message that isn't a request");
            ctx.out.send(&reply);
            return;
        }
        framing::Incoming::Ignore => return,
    };

    log::debug!("{verb} requested ({id})");
    let key = id.to_string();
    let task_ctx = ctx.clone();
    let task_running = running.clone();
    let task_key = key.clone();
    // the task waits for its own entry, so a quick answer can't clear it
    // before it is recorded
    let (recorded_w, recorded_r) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = recorded_r.await;
        let work = verbs::dispatch(&task_ctx, &verb, &params);
        let answer = match deadline {
            Some(deadline) => tokio::time::timeout(deadline, work)
                .await
                .unwrap_or_else(|_| {
                    Err(verbs::VaultError {
                        code: "failed",
                        message: "The request ran past its deadline."
                            .to_string(),
                    })
                }),
            None => work.await,
        };
        let still_wanted = task_running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&task_key)
            .is_some();
        if !still_wanted {
            return;
        }
        let answer = answer.map_err(|error| {
            log::info!("{verb} failed: {}", error.message);
            error.to_json()
        });
        if answer.is_ok() {
            log::debug!("{verb} answered");
        }
        task_ctx.out.send(&framing::answer(&id, answer));
    });
    let replaced = running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, task.abort_handle());
    if let Some(replaced) = replaced {
        // the host reused an id that is still running: the newer one wins
        replaced.abort();
    }
    let _ = recorded_w.send(());
}

#[cfg(test)]
mod test {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn option_parsing() {
        assert_eq!(
            options(&[]).unwrap(),
            Options {
                source: transport::Source::Stdio,
                dir: None,
                accounts: false,
            }
        );
        assert!(options(&args(&["--accounts"])).unwrap().accounts);
        let parsed =
            options(&args(&["--fd", "5", "--dir", "/tmp/x"])).unwrap();
        assert_eq!(parsed.source, transport::Source::Fd(5));
        assert_eq!(parsed.dir, Some(std::path::PathBuf::from("/tmp/x")));
        assert!(options(&args(&["--dir", "relative"])).is_err());
        assert!(options(&args(&["--fd"])).is_err());
        assert!(options(&args(&["--framing", "native"])).is_err());
        assert!(options(&args(&["--bogus"])).is_err());
    }
}
