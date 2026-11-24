use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

// How the agent runs: as a daemon that `rbw` starts, in the foreground
// (--no-daemonize), or started by the service manager (--service).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Daemon,
    Foreground,
    Service,
}

impl Mode {
    pub fn from_args() -> Self {
        match std::env::args().nth(1).as_deref() {
            Some("--no-daemonize") => Self::Foreground,
            Some("--service") => Self::Service,
            _ => Self::Daemon,
        }
    }
}

// How long a service agent waits for the agent it replaces to exit.
const TAKE_OVER_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

pub fn daemonize(mode: Mode) -> anyhow::Result<Option<StartupAck>> {
    if mode != Mode::Daemon {
        let pidfile = lock_pid_file(mode == Mode::Service)?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);
        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    let daemonize = daemonize::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonize::Outcome::Parent(_) => {
            drop(w);
            let mut buf = [0; 1];
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            rustix::io::read(&r, &mut buf).unwrap();
            drop(r);
            std::process::exit(0);
        }
        daemonize::Outcome::Child(res) => res,
    };

    drop(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            // XXX super gross, but daemonize removed the ability to match
            // on specific error types for some reason?
            if e.to_string().contains("unable to lock pid file") {
                // this means that there is already an agent running, so
                // return a special exit code to allow the cli to detect
                // this case and not error out
                std::process::exit(23);
            }
            panic!("failed to daemonize: {e}");
        }
    }

    Ok(Some(StartupAck { writer: w }))
}

// Locks the pid file and writes this process's pid in it. The service
// agent replaces an agent that `rbw` started before the service existed:
// otherwise launchd or systemd would keep trying to start it, and the
// service's sockets would go unanswered.
fn lock_pid_file(take_over: bool) -> anyhow::Result<std::fs::File> {
    let mut pidfile = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(rbw::dirs::pid_file())
        .context("failed to open pid file")?;
    if let Err(e) = try_lock(&pidfile) {
        if !take_over || e != rustix::io::Errno::WOULDBLOCK {
            return Err(e).context("failed to lock pid file");
        }
        stop_running_agent(&mut pidfile)?;
    }
    pidfile.set_len(0).context("failed to write pid file")?;
    std::io::Seek::rewind(&mut pidfile)
        .context("failed to write pid file")?;
    writeln!(pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    Ok(pidfile)
}

fn try_lock(pidfile: &std::fs::File) -> rustix::io::Result<()> {
    rustix::fs::flock(
        pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
}

// Asks the agent that holds the pid file lock to exit, and waits for the
// lock. Only a process named rbw-agent is signalled: the pid comes from a
// file, and a wrong one must not stop anything else. Another holder, such
// as `rbw ssh-agent status` checking for an agent, lets go by itself.
fn stop_running_agent(pidfile: &mut std::fs::File) -> anyhow::Result<()> {
    let mut contents = String::new();
    std::io::Read::read_to_string(pidfile, &mut contents)
        .context("failed to read pid file")?;
    let agent = contents
        .trim()
        .parse::<i32>()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .filter(|pid| pid.as_raw_nonzero().get() > 1)
        .filter(|pid| *pid != rustix::process::getpid())
        .filter(|pid| {
            crate::peer::process_name(pid.as_raw_nonzero().get()).as_deref()
                == Some("rbw-agent")
        });
    if let Some(pid) = agent {
        log::info!(
            "stopping the agent already running (pid {}) to take its place",
            pid.as_raw_nonzero()
        );
        match rustix::process::kill_process(
            pid,
            rustix::process::Signal::TERM,
        ) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(e) => {
                return Err(e).context("failed to stop the running agent");
            }
        }
    }
    let deadline = std::time::Instant::now() + TAKE_OVER_TIMEOUT;
    loop {
        match try_lock(pidfile) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(e).context(
                    "failed to lock pid file: another agent still holds it",
                );
            }
        }
    }
}
