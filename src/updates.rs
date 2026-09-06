//! Bounded local protocol for the native, signed package updater.
//! The HTTP process never executes a privileged command. Root starts the host
//! controller only after the existing package/runtime parity guard succeeds.
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod host;
pub use host::run_host;

pub(crate) const SOCKET: &str = "/run/vaultlink-update-control/control.sock";
const MAX_MESSAGE: usize = 8192;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Check {},
    Install { version: String },
    Automatic { enabled: bool },
}

impl Operation {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Install { version } => version_parts(version).is_some(),
            _ => true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Status {},
    Submit {
        request_id: String,
        action: Operation,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    pub available: bool,
    pub installed: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub checked_at: Option<i64>,
    pub automatic: bool,
    pub phase: String,
    pub request_id: Option<String>,
    pub operation: Option<Operation>,
    pub error: Option<String>,
}

impl Status {
    pub(crate) fn disconnected() -> Self {
        Self {
            installed: env!("CARGO_PKG_VERSION").into(),
            phase: "unavailable".into(),
            ..Self::default()
        }
    }
    fn busy(&self) -> bool {
        matches!(self.phase.as_str(), "queued" | "running")
    }
    fn refresh_installed(&mut self, installed: String) {
        self.installed = installed;
        // A timer or CLI installation can overtake the GUI's last check.
        if self
            .latest
            .as_deref()
            .and_then(version_parts)
            .zip(version_parts(&self.installed))
            .is_none_or(|(latest, installed)| latest <= installed)
        {
            self.update_available = false;
        }
    }
}

pub(crate) fn version_parts(value: &str) -> Option<[u64; 3]> {
    if value.len() > 40 {
        return None;
    }
    let parts = value
        .split('.')
        .map(|p| {
            if p.is_empty()
                || p.len() > 1 && p.starts_with('0')
                || !p.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            p.parse::<u64>().ok()
        })
        .collect::<Option<Vec<_>>>()?;
    parts.try_into().ok()
}

pub(crate) async fn exchange(request: &Request) -> io::Result<Status> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = tokio::net::UnixStream::connect(SOCKET).await?;
        if stream.peer_cred()?.uid() != 0 {
            return Err(io::Error::other("untrusted update controller"));
        }
        let mut bytes = serde_json::to_vec(request)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let mut line = Vec::new();
        use tokio::io::AsyncReadExt;
        BufReader::new(stream)
            .take((MAX_MESSAGE + 1) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if line.len() > MAX_MESSAGE || !line.ends_with(b"\n") {
            return Err(io::Error::other("invalid update response"));
        }
        serde_json::from_slice(&line).map_err(Into::into)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "update controller timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_installation_clears_an_obsolete_update_offer() {
        for installed in ["0.7.1", "0.7.2"] {
            let mut state = Status {
                latest: Some("0.7.1".into()),
                update_available: true,
                ..Status::default()
            };
            state.refresh_installed(installed.into());
            assert!(!state.update_available);
            assert_eq!(state.installed, installed);
        }
    }
    #[test]
    fn privileged_protocol_rejects_arguments_and_nonstable_versions() {
        for value in [
            "",
            "../0.7.0",
            "0.7",
            "0.7.0-rc1",
            "00.7.0",
            "0.7.0\n",
            "0.7.0;id",
            "0.7.0.1",
        ] {
            assert!(version_parts(value).is_none(), "{value}");
        }
        assert_eq!(version_parts("0.7.10"), Some([0, 7, 10]));
        for value in [
            r#"{"command":"shell","args":"id"}"#,
            r#"{"command":"status","path":"/etc/shadow"}"#,
            r#"{"operation":"install","version":"0.7.0","url":"https://evil.invalid"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(value).is_err());
        }
    }
}
