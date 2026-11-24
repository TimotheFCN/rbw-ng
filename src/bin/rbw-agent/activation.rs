// Sockets that the service manager opened for the agent (rbw-agent
// --service): systemd's socket units, or the Sockets entry of the launchd
// job. Either way the manager keeps the sockets open while the agent is not
// running, and starts the agent when a program connects.
//
// The agent binds the usual paths itself for whatever it was not given.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use anyhow::Context as _;

#[derive(Default)]
pub struct Sockets {
    // The socket rbw talks to.
    pub control: Option<std::os::unix::net::UnixListener>,
    // Sockets that serve SSH keys.
    pub ssh: Vec<std::os::unix::net::UnixListener>,
}

// Must run before any thread starts: on systemd it clears the variables
// that describe the sockets, so programs the agent starts don't see them.
pub fn take() -> anyhow::Result<Sockets> {
    #[cfg(target_os = "macos")]
    return launchd();
    #[cfg(not(target_os = "macos"))]
    return systemd();
}

// The launchd job names its socket "Listeners", as Apple's ssh-agent job
// does, and has launchd put its path in SSH_AUTH_SOCK for the whole login
// session.
#[cfg(target_os = "macos")]
fn launchd() -> anyhow::Result<Sockets> {
    unsafe extern "C" {
        // From <launch.h>, in libSystem.
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }

    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count: libc::size_t = 0;
    // SAFETY: the name is a NUL terminated string, and the two out
    // pointers point to valid locals.
    let error = unsafe {
        launch_activate_socket(
            c"Listeners".as_ptr(),
            &raw mut fds,
            &raw mut count,
        )
    };
    match error {
        0 => {}
        // not started by launchd, or by a job without that socket
        libc::ESRCH | libc::ENOENT => return Ok(Sockets::default()),
        error => {
            return Err(std::io::Error::from_raw_os_error(error))
                .context("failed to get the sockets from launchd");
        }
    }
    let raw: Vec<libc::c_int> = if fds.is_null() {
        vec![]
    } else {
        // SAFETY: on success launchd returns an array of count descriptors,
        // allocated with malloc, which the caller frees.
        let raw = unsafe { std::slice::from_raw_parts(fds, count) }.to_vec();
        unsafe { libc::free(fds.cast()) };
        raw
    };
    let mut sockets = Sockets::default();
    for fd in raw {
        // SAFETY: launchd gave this process the descriptor, and nothing
        // else in it owns or closes it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        sockets.ssh.push(listener(fd)?);
    }
    Ok(sockets)
}

// systemd's socket activation protocol: descriptors from 3 on, counted in
// LISTEN_FDS for the process in LISTEN_PID, and named by the socket units'
// FileDescriptorName ("control" or "ssh") in LISTEN_FDNAMES.
#[cfg(not(target_os = "macos"))]
fn systemd() -> anyhow::Result<Sockets> {
    const FIRST_FD: libc::c_int = 3;

    let pid = std::env::var("LISTEN_PID").ok();
    let count = std::env::var("LISTEN_FDS").ok();
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(var);
    }

    let (Some(pid), Some(count)) = (pid, count) else {
        return Ok(Sockets::default());
    };
    if pid.parse::<u32>().ok() != Some(std::process::id()) {
        // meant for another process
        return Ok(Sockets::default());
    }
    let count: libc::c_int =
        count.parse().context("LISTEN_FDS is not a number")?;
    let names: Vec<&str> = names.split(':').collect();

    let mut sockets = Sockets::default();
    for i in 0..count {
        let fd =
            FIRST_FD.checked_add(i).context("LISTEN_FDS is too large")?;
        // SAFETY: systemd passed this descriptor to the process, and nothing
        // else in it owns or closes it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let listener = listener(fd)?;
        let index = usize::try_from(i).context("LISTEN_FDS is too large")?;
        match names.get(index).copied() {
            Some("control") if sockets.control.is_none() => {
                sockets.control = Some(listener);
            }
            Some("ssh") => sockets.ssh.push(listener),
            name => anyhow::bail!(
                "systemd passed an unexpected socket ({})",
                name.unwrap_or("unnamed")
            ),
        }
    }
    Ok(sockets)
}

// Checks that a passed descriptor is a listening Unix stream socket, and
// keeps it from programs the agent starts.
fn listener(fd: OwnedFd) -> anyhow::Result<std::os::unix::net::UnixListener> {
    let raw = fd.as_raw_fd();
    if rustix::net::sockopt::socket_type(&fd)
        .with_context(|| format!("descriptor {raw} is not a socket"))?
        != rustix::net::SocketType::STREAM
    {
        anyhow::bail!("descriptor {raw} is not a stream socket");
    }
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)
        .with_context(|| format!("failed to set up descriptor {raw}"))?;
    let listener = std::os::unix::net::UnixListener::from(fd);
    // fails unless it is a Unix socket
    listener
        .local_addr()
        .with_context(|| format!("descriptor {raw} is not a Unix socket"))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("failed to set up descriptor {raw}"))?;
    Ok(listener)
}
