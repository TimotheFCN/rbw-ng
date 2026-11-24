use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<std::result::Result<rbw::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line).map_err(|e| {
            format!("failed to parse message '{}': {e}", quote_start(&line))
        }))
    }
}

// a request can be megabytes long (a batch decryption of a large vault), and
// the error that quotes it goes to the agent log and back to the client, so
// only quote the start of it
fn quote_start(line: &str) -> std::borrow::Cow<'_, str> {
    const MAX_LEN: usize = 200;
    let line = line.trim_end();
    if line.len() <= MAX_LEN {
        return line.into();
    }
    let mut end = MAX_LEN;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes)", &line[..end], line.len()).into()
}

// Whether an agent answers on rbw's socket: one that runs, or the one that
// systemd starts for its socket unit. Binding the socket again would cut it
// off from rbw.
pub fn answers() -> bool {
    use std::io::{BufRead as _, Write as _};

    let Ok(mut sock) =
        std::os::unix::net::UnixStream::connect(rbw::dirs::socket_file())
    else {
        return false;
    };
    let timeout = Some(std::time::Duration::from_secs(5));
    if sock.set_read_timeout(timeout).is_err()
        || sock.set_write_timeout(timeout).is_err()
    {
        return false;
    }
    let request = rbw::protocol::Request::new(
        rbw::protocol::Environment::from_process(),
        rbw::protocol::Action::Version,
    );
    let Ok(mut line) = serde_json::to_string(&request) else {
        return false;
    };
    line.push('\n');
    if sock.write_all(line.as_bytes()).is_err() {
        return false;
    }
    let mut reply = String::new();
    std::io::BufReader::new(sock)
        .read_line(&mut reply)
        .is_ok_and(|len| len > 0)
}

pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::quote_start;

    #[test]
    fn short_requests_are_quoted_whole() {
        assert_eq!(
            quote_start("{\"type\":\"Nope\"}\n"),
            "{\"type\":\"Nope\"}"
        );
    }

    #[test]
    fn long_requests_are_cut_on_a_char_boundary() {
        let line = format!("{}{}", "a".repeat(199), "é".repeat(1000));
        let quoted = quote_start(&line);
        assert!(quoted.starts_with(&"a".repeat(199)));
        assert!(quoted.ends_with(&format!("... ({} bytes)", line.len())));
        assert!(quoted.len() < 250);
    }
}
