// Where the embedding application's messages come from: newline-delimited
// JSON on stdin and stdout, or on a socket descriptor the application
// passed to the agent.

use anyhow::Context as _;
use tokio::io::{
    AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _,
};

// A longer line can only come from a broken host.
const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Stdio,
    // a stream socket the application passed to this process
    Fd(i32),
}

pub type BoxedRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
pub type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

pub struct Reader {
    reader: tokio::io::BufReader<BoxedRead>,
}

impl Reader {
    // The next message, or None once the application closed the channel.
    pub async fn next(
        &mut self,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        loop {
            let mut line = Vec::new();
            let read = (&mut self.reader)
                .take(u64::try_from(MAX_LINE + 1).unwrap_or(u64::MAX))
                .read_until(b'\n', &mut line)
                .await
                .context("failed to read from the host")?;
            if read == 0 {
                return Ok(None);
            }
            if line.len() > MAX_LINE {
                return Err(anyhow::anyhow!(
                    "a message from the host was longer than {MAX_LINE} \
                     bytes"
                ));
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice(&line) {
                Ok(message) => return Ok(Some(message)),
                // a line we can't read is the host's mistake, not a reason
                // to drop the unlocked vault
                Err(e) => log::warn!("ignoring a message from the host: {e}"),
            }
        }
    }
}

// Sends lines to the host. Clones share one writer, so lines never
// interleave.
#[derive(Clone)]
pub struct Writer {
    lines: tokio::sync::mpsc::UnboundedSender<String>,
}

impl Writer {
    pub fn send(&self, message: &serde_json::Value) {
        // the receiver only goes away when the process is exiting
        let _ = self.lines.send(message.to_string());
    }
}

pub fn open(source: Source) -> anyhow::Result<(Reader, Writer)> {
    Ok(match source {
        Source::Stdio => streams(
            Box::new(tokio::io::stdin()),
            Box::new(tokio::io::stdout()),
        ),
        Source::Fd(fd) => {
            let (read, write) = socket_from_fd(fd)?.into_split();
            streams(Box::new(read), Box::new(write))
        }
    })
}

// The same channel over any pair of streams, such as a child agent's pipes.
pub fn streams(read: BoxedRead, write: BoxedWrite) -> (Reader, Writer) {
    let (lines, mut queued) =
        tokio::sync::mpsc::unbounded_channel::<String>();
    let mut write = write;
    tokio::spawn(async move {
        while let Some(mut line) = queued.recv().await {
            line.push('\n');
            let written = async {
                write.write_all(line.as_bytes()).await?;
                write.flush().await
            };
            if let Err(e) = written.await {
                log::warn!("failed to write to the host: {e}");
                break;
            }
        }
    });

    (
        Reader {
            reader: tokio::io::BufReader::new(read),
        },
        Writer { lines },
    )
}

fn socket_from_fd(fd: i32) -> anyhow::Result<tokio::net::UnixStream> {
    // not 0, 1 or 2: those are stdio
    if fd < 3 {
        return Err(anyhow::anyhow!(
            "the channel descriptor must be 3 or more, not {fd}"
        ));
    }
    let socket_type = rustix::net::sockopt::socket_type(
        // SAFETY: fd is only borrowed for this call, and is checked to be a
        // socket before anything takes ownership of it.
        unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) },
    )
    .context("the channel descriptor isn't an open socket")?;
    if socket_type != rustix::net::SocketType::STREAM {
        return Err(anyhow::anyhow!(
            "the channel descriptor isn't a stream socket"
        ));
    }
    // SAFETY: the host hands this descriptor to the process for the channel
    // alone, it was just checked to be a stream socket, and nothing else in
    // this process uses it, so taking ownership of it is sound.
    let stream = unsafe {
        <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(
            fd,
        )
    };
    stream
        .set_nonblocking(true)
        .context("failed to set up the channel")?;
    // keep the channel out of any program this process starts
    rustix::io::fcntl_setfd(&stream, rustix::io::FdFlags::CLOEXEC)
        .context("failed to set up the channel")?;
    tokio::net::UnixStream::from_std(stream)
        .context("failed to set up the channel")
}
