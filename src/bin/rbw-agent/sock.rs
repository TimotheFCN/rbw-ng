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
        Ok(serde_json::from_str(&line).map_err(|e| unparsable(&line, &e)))
    }
}

// Why a request can't be read, without quoting it: requests carry master
// passwords and secrets, and the error goes to the agent's log. The action's
// type is enough to see that a client is newer than the agent.
fn unparsable(line: &str, error: &serde_json::Error) -> String {
    #[derive(serde::Deserialize)]
    struct Request {
        action: Action,
    }
    #[derive(serde::Deserialize)]
    struct Action {
        #[serde(rename = "type")]
        ty: String,
    }
    let action = serde_json::from_str::<Request>(line)
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
    use super::unparsable;

    fn error(line: &str) -> String {
        let error = serde_json::from_str::<rbw::protocol::Request>(line)
            .expect_err(line);
        unparsable(line, &error)
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
