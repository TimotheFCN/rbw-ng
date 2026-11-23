// rbw-agent --embedded --accounts: one host, several accounts. Each account
// is an ordinary embedded agent (rbw-agent --embedded --dir <root>/<id>) in
// its own process, so one account's keys never share memory with another's,
// and each locks, syncs and signs out on its own. This process holds no keys:
// it starts the account agents, routes the host's requests to them, and
// passes their answers and events back, tagged with their account.

use anyhow::Context as _;
use serde_json::{json, Value};

use super::{framing, transport};

enum Event {
    Host(anyhow::Result<Option<Value>>),
    // a message from an account's agent, or None once it stopped
    Account {
        account: String,
        generation: u64,
        message: Option<Value>,
    },
}

struct Agent {
    writer: transport::Writer,
    process: tokio::process::Child,
    // tells a restarted agent's messages from its predecessor's
    generation: u64,
}

struct Pending {
    host_id: Value,
    account: String,
    verb: String,
}

struct Router {
    root: std::path::PathBuf,
    host: transport::Writer,
    events: tokio::sync::mpsc::UnboundedSender<Event>,
    agents: std::collections::HashMap<String, Agent>,
    // requests waiting for an account agent's answer, by the id it was sent
    // with
    pending: std::collections::HashMap<u64, Pending>,
    next_id: u64,
    next_generation: u64,
}

pub async fn run(
    options: &super::Options,
    root: std::path::PathBuf,
) -> anyhow::Result<()> {
    let (mut host_reader, host) = transport::open(options.source)?;
    host.send(&framing::start(&super::ready(true)));
    log::info!(
        "rbw-ng {} serving the host's accounts in {}",
        env!("CARGO_PKG_VERSION"),
        root.display(),
    );

    let (events, mut incoming) = tokio::sync::mpsc::unbounded_channel();
    let host_events = events.clone();
    tokio::spawn(async move {
        loop {
            let message = host_reader.next().await;
            let done = !matches!(message, Ok(Some(_)));
            if host_events.send(Event::Host(message)).is_err() || done {
                break;
            }
        }
    });

    let mut router = Router {
        root,
        host,
        events,
        agents: std::collections::HashMap::new(),
        pending: std::collections::HashMap::new(),
        next_id: 0,
        next_generation: 0,
    };
    while let Some(event) = incoming.recv().await {
        match event {
            Event::Host(Ok(Some(message))) => router.handle_host(&message),
            Event::Host(Ok(None)) => {
                log::info!("the host closed the channel");
                break;
            }
            Event::Host(Err(e)) => return Err(e),
            Event::Account {
                account,
                generation,
                message: Some(message),
            } => router.handle_agent(&account, generation, &message).await,
            Event::Account {
                account,
                generation,
                message: None,
            } => router.agent_stopped(&account, generation),
        }
    }
    router.stop_all().await;
    Ok(())
}

impl Router {
    fn refuse(&self, id: &Value, code: &str, message: &str) {
        self.host.send(&framing::answer(
            id,
            Err(json!({ "code": code, "message": message })),
        ));
    }

    fn handle_host(&mut self, message: &Value) {
        match framing::read(message) {
            framing::Incoming::Request {
                id,
                verb,
                params,
                deadline,
                account,
            } => {
                let Some(account) = account else {
                    // the verbs that need no account
                    let answer = match verb.as_str() {
                        "accounts" => Some(self.list()),
                        "generate" => Some(
                            super::verbs::generate(&params)
                                .map_err(|e| e.to_json()),
                        ),
                        _ => None,
                    };
                    if let Some(answer) = answer {
                        return self.host.send(&framing::answer(&id, answer));
                    }
                    return self.refuse(
                        &id,
                        "bad_request",
                        "This agent serves several accounts: name one with \
                         account.",
                    );
                };
                if let Err(e) = self.agent(&account) {
                    log::warn!("couldn't start {account}'s agent: {e:#}");
                    return self.refuse(
                        &id,
                        "failed",
                        "The account's agent couldn't start.",
                    );
                }
                self.next_id += 1;
                let mut request = json!({
                    "id": self.next_id,
                    "method": verb,
                    "params": params,
                });
                if let Some(deadline) = deadline {
                    request["deadline"] =
                        json!(u64::try_from(deadline.as_millis())
                            .unwrap_or(u64::MAX));
                }
                log::debug!("{verb} for {account}");
                self.pending.insert(
                    self.next_id,
                    Pending {
                        host_id: id,
                        account: account.clone(),
                        verb,
                    },
                );
                if let Some(agent) = self.agents.get(&account) {
                    agent.writer.send(&request);
                }
            }
            framing::Incoming::Cancel(id) => {
                let found = self
                    .pending
                    .iter()
                    .find(|(_, pending)| pending.host_id == id)
                    .map(|(child_id, _)| *child_id);
                if let Some(child_id) = found {
                    if let Some(pending) = self.pending.remove(&child_id) {
                        if let Some(agent) = self.agents.get(&pending.account)
                        {
                            agent.writer.send(&json!({ "cancel": child_id }));
                        }
                    }
                }
            }
            framing::Incoming::Refuse(reply) => self.host.send(&reply),
            framing::Incoming::Ignore => {}
        }
    }

    // The accounts that have a folder: signed in, or started and not yet
    // signed out. Their agents start only when asked something.
    fn list(&self) -> Result<Value, Value> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!({ "accounts": [] }))
            }
            Err(e) => {
                log::warn!("failed to list the accounts: {e}");
                return Err(json!({
                    "code": "failed",
                    "message": "The accounts folder can't be read.",
                }));
            }
        };
        let mut accounts: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| framing::valid_account(name))
            .collect();
        accounts.sort();
        Ok(json!({ "accounts": accounts }))
    }

    // The account's agent, started on first use.
    fn agent(&mut self, account: &str) -> anyhow::Result<&Agent> {
        if !self.agents.contains_key(account) {
            let agent = self.start(account)?;
            self.agents.insert(account.to_string(), agent);
        }
        self.agents
            .get(account)
            .context("the account's agent is gone")
    }

    fn start(&mut self, account: &str) -> anyhow::Result<Agent> {
        use std::os::unix::fs::DirBuilderExt as _;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .context("failed to create the accounts folder")?;
        let mut process = tokio::process::Command::new(
            std::env::current_exe().context("failed to find rbw-agent")?,
        )
        .arg(super::ARGUMENT)
        .arg("--dir")
        .arg(self.root.join(account))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start the account's agent")?;
        let (Some(stdin), Some(stdout)) =
            (process.stdin.take(), process.stdout.take())
        else {
            return Err(anyhow::anyhow!("the account's agent has no pipes"));
        };
        let (mut reader, writer) =
            transport::streams(Box::new(stdout), Box::new(stdin));

        self.next_generation += 1;
        let generation = self.next_generation;
        let events = self.events.clone();
        let name = account.to_string();
        tokio::spawn(async move {
            loop {
                let message = reader.next().await.ok().flatten();
                let stopped = message.is_none();
                let sent = events.send(Event::Account {
                    account: name.clone(),
                    generation,
                    message,
                });
                if sent.is_err() || stopped {
                    break;
                }
            }
        });
        log::info!("started the agent for {account}");
        Ok(Agent {
            writer,
            process,
            generation,
        })
    }

    async fn handle_agent(
        &mut self,
        account: &str,
        generation: u64,
        message: &Value,
    ) {
        if self.agents.get(account).map(|agent| agent.generation)
            != Some(generation)
        {
            return;
        }
        if let Some(event) = message.get("event").and_then(Value::as_str) {
            // each agent says it's ready; the host heard it from the router
            if event != "ready" {
                let data =
                    message.get("data").cloned().unwrap_or(Value::Null);
                self.host.send(&framing::event(event, &data, Some(account)));
            }
            return;
        }
        let Some(pending) = message
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| self.pending.remove(&id))
        else {
            // cancelled, or not an answer
            return;
        };
        let answer = message.get("error").map_or_else(
            || Ok(message.get("result").cloned().unwrap_or(Value::Null)),
            |error| Err(error.clone()),
        );
        // a sign-out is answered once the account is gone, so the host
        // never sees it half removed
        if pending.verb == "signOut" && answer.is_ok() {
            self.forget(account).await;
        }
        self.host.send(&framing::answer(&pending.host_id, answer));
    }

    // After a sign-out: the account's agent stops and its folder goes, so
    // nothing of it stays behind.
    async fn forget(&mut self, account: &str) {
        if let Some(agent) = self.agents.remove(account) {
            stop(agent).await;
        }
        self.fail_pending(account, "The account signed out.");
        if let Err(e) = std::fs::remove_dir_all(self.root.join(account)) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("failed to delete {account}'s folder: {e}");
            }
        }
        log::info!("forgot {account}");
    }

    fn agent_stopped(&mut self, account: &str, generation: u64) {
        if self.agents.get(account).map(|agent| agent.generation)
            != Some(generation)
        {
            return;
        }
        log::warn!("{account}'s agent stopped");
        self.agents.remove(account);
        self.fail_pending(account, "The account's agent stopped.");
        // the vault was in that process: it is locked now, and the next
        // request starts a new agent
        self.host.send(&framing::event(
            "state",
            &json!({ "state": "locked" }),
            Some(account),
        ));
    }

    fn fail_pending(&mut self, account: &str, message: &str) {
        let failed: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.account == account)
            .map(|(id, _)| *id)
            .collect();
        for id in failed {
            if let Some(pending) = self.pending.remove(&id) {
                self.refuse(&pending.host_id, "failed", message);
            }
        }
    }

    async fn stop_all(&mut self) {
        for (_, agent) in self.agents.drain() {
            stop(agent).await;
        }
    }
}

// Closing its channel stops an agent; it is killed if it doesn't go.
async fn stop(agent: Agent) {
    let Agent {
        writer,
        mut process,
        ..
    } = agent;
    drop(writer);
    let stopped = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        process.wait(),
    )
    .await;
    if stopped.is_err() {
        let _ = process.kill().await;
    }
}
