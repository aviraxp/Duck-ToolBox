//! Bounded exchange files and disposable child-process ownership for device adapters.
use crate::error::DeviceRkpError;
use anyhow::{Context, Result};
use std::{
    fs,
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn run(command: &mut Command, timeout: Duration) -> Result<ExitStatus> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach_from_terminal(command);
    let child = command
        .spawn()
        .map_err(|error| DeviceRkpError::Transport(format!("start device worker: {error}")))?;
    Worker(child).wait(timeout)
}

/// Puts the child in its own session, so a Ctrl-C aimed at the CLI (or anything else
/// signalling the process group) cannot interrupt the vendor call halfway through. The
/// null stdio above leaves the new session with nothing open on the terminal.
///
/// There is no safe API for `setsid` between fork and exec.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn detach_from_terminal(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: `setsid` is async-signal-safe and one of the few calls documented as safe
    // between fork and exec. A failure aborts the child before it touches vendor code.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub(crate) fn detach_from_terminal(_command: &mut Command) {}

/// Read one regular exchange file through the same descriptor used for its size
/// check. The read itself is bounded too, even if the file grows after metadata().
pub(crate) fn read_exchange_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(DeviceRkpError::InvalidResponse(format!(
            "{} must be a regular file of at most {limit} bytes",
            path.display()
        ))
        .into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() > limit {
        return Err(DeviceRkpError::InvalidResponse(
            "worker exchange file grew beyond its limit".into(),
        )
        .into());
    }
    Ok(bytes)
}

pub(crate) struct Worker(pub(crate) Child);

impl Worker {
    pub(crate) fn wait(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.0.try_wait().map_err(|error| {
                DeviceRkpError::Transport(format!("wait for the KeyMint worker: {error}"))
            })? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(DeviceRkpError::Timeout.into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
