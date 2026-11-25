use anyhow::Context as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error, .. } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        // answers carry decrypted secrets
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(res).context("failed to serialize message")?,
        );
        sock.write_all(&json)
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
        let line = read_line(sock)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_slice(&line).map_err(|e| unparsable(&line, &e)))
    }
}

// Reads a request, the one line a client sends, into memory that is wiped
// once it is parsed: requests carry master passwords and secrets. The
// buffer grows by hand, so that a move leaves no copy behind.
async fn read_line(
    sock: &mut tokio::net::UnixStream,
) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut line = zeroize::Zeroizing::new(Vec::with_capacity(4096));
    let mut chunk = zeroize::Zeroizing::new([0; 4096]);
    loop {
        let read = sock.read(&mut chunk[..]).await?;
        if read == 0 {
            return Ok(line);
        }
        let end = chunk[..read].iter().position(|&byte| byte == b'\n');
        let take = end.map_or(read, |end| end + 1);
        if line.len() + take > line.capacity() {
            let mut larger = zeroize::Zeroizing::new(Vec::with_capacity(
                (line.len() + take).max(line.capacity() * 2),
            ));
            larger.extend_from_slice(&line);
            line = larger;
        }
        line.extend_from_slice(&chunk[..take]);
        if end.is_some() {
            return Ok(line);
        }
    }
}

// Why a request can't be read, without quoting it: requests carry master
// passwords and secrets, and the error goes to the agent's log. The action's
// type is enough to see that a client is newer than the agent.
fn unparsable(line: &[u8], error: &serde_json::Error) -> String {
    #[derive(serde::Deserialize)]
    struct Request {
        action: Action,
    }
    #[derive(serde::Deserialize)]
    struct Action {
        #[serde(rename = "type")]
        ty: String,
    }
    let action = serde_json::from_slice::<Request>(line)
        .ok()
        .map(|request| request.action.ty)
        .filter(|ty| {
            ty.len() <= 32 && ty.bytes().all(|b| b.is_ascii_alphanumeric())
        });
    let request = action.map_or_else(
        || "a request".to_string(),
        |action| format!("a request for {action}"),
    );
    format!("failed to parse {request} at column {}", error.column())
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
    use super::{read_line, unparsable};

    #[tokio::test]
    async fn requests_are_read_to_their_line_break() {
        use tokio::io::AsyncWriteExt as _;

        let long = "x".repeat(10_000);
        for (sent, read) in [
            ("{}\nignored".to_string(), "{}\n".to_string()),
            (format!("{long}\n"), format!("{long}\n")),
            ("no line break".to_string(), "no line break".to_string()),
        ] {
            let (mut client, mut agent) =
                tokio::net::UnixStream::pair().unwrap();
            // A socket holds little, 8 KB on macOS: the client writes
            // while the agent reads, as rbw does.
            let write = async move {
                client.write_all(sent.as_bytes()).await.unwrap();
                drop(client);
            };
            let (line, ()) = tokio::join!(read_line(&mut agent), write);
            assert_eq!(*line.unwrap(), read.as_bytes());
        }
    }

    fn error(line: &str) -> String {
        let error = serde_json::from_str::<rbw::protocol::Request>(line)
            .expect_err(line);
        unparsable(line.as_bytes(), &error)
    }

    #[test]
    fn requests_that_cant_be_read_are_named_not_quoted() {
        let password = "hunter2-master-password";
        for line in [
            format!(
                r#"{{"action":{{"type":"UnlockLater","password":"{password}"}}}}"#
            ),
            format!(
                r#"{{"action":{{"type":"UnlockWith","password":{password}}}}}"#
            ),
            format!(
                r#"{{"action":{{"type":"UnlockWith","password":["{password}"],"session":false}}}}"#
            ),
            format!(r#"{{"action":{{"type":"{password} x"}}}}"#),
            format!(r#"{{"action":"{password}"}}"#),
            password.to_string(),
        ] {
            let message = error(&line);
            assert!(!message.contains("hunter2"), "{message}");
        }
        assert_eq!(
            error(r#"{"action":{"type":"UnlockLater","password":"x"}}"#),
            "failed to parse a request for UnlockLater at column 31"
        );
    }
}
