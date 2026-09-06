use super::{version_parts, Operation, Request, Status, MAX_MESSAGE, SOCKET};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

const DIRECTORY: &str = "/var/lib/vaultlink-update-control";
const JOB: &str = "vaultlink-gui-update.service";

fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(failure("unsafe update state directory"));
    }
    Ok(())
}

fn open_private(path: &Path, create: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(failure("unsafe update state file"));
    }
    Ok(file)
}

fn lock() -> io::Result<File> {
    private_directory(Path::new(DIRECTORY))?;
    let file = open_private(&Path::new(DIRECTORY).join("control.lock"), true)?;
    file.lock()?;
    Ok(file)
}

fn load() -> io::Result<Status> {
    let file = match open_private(&Path::new(DIRECTORY).join("status.json"), false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Status {
                available: true,
                phase: "idle".into(),
                ..Status::default()
            })
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_MESSAGE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(failure("update state too large"));
    }
    serde_json::from_slice(&bytes).map_err(Into::into)
}

fn save(state: &Status) -> io::Result<()> {
    let mut stage = tempfile::NamedTempFile::new_in(DIRECTORY)?;
    stage
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    stage.write_all(&serde_json::to_vec(state)?)?;
    stage.as_file().sync_all()?;
    stage
        .persist(Path::new(DIRECTORY).join("status.json"))
        .map_err(|e| e.error)?;
    File::open(DIRECTORY)?.sync_all()
}

async fn output(program: &str, args: &[&str]) -> io::Result<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| failure("host command timed out"))??;
    if !result.status.success() || result.stdout.len() > MAX_MESSAGE {
        return Err(failure("host command failed"));
    }
    String::from_utf8(result.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| failure("invalid host output"))
}

async fn installed_version() -> io::Result<String> {
    let version = output("/opt/vaultlink/vaultlink", &["--version"]).await?;
    version_parts(&version).ok_or_else(|| failure("invalid installed version"))?;
    Ok(version)
}

fn automatic_config() -> io::Result<bool> {
    let path = Path::new("/etc/vaultlink/update.conf");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4096
    {
        return Err(failure("unsafe update configuration"));
    }
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    parse_automatic_config(&value)
}

fn parse_automatic_config(value: &str) -> io::Result<bool> {
    let lines: Vec<_> = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let [line] = lines.as_slice() else {
        return Err(failure("unsupported update configuration"));
    };
    match line
        .split_once('=')
        .map(|(key, value)| (key.trim(), value.trim()))
    {
        Some(("auto_install", "true")) => Ok(true),
        Some(("auto_install", "false")) => Ok(false),
        _ => Err(failure("unsupported update configuration")),
    }
}

async fn status() -> io::Result<Status> {
    let guard = lock()?;
    let mut state = load()?;
    state.installed = installed_version().await?;
    state.automatic = automatic_config()?
        && output(
            "/usr/bin/systemctl",
            &["is-enabled", "vaultlink-update.timer"],
        )
        .await
        .is_ok()
        && output(
            "/usr/bin/systemctl",
            &["is-active", "vaultlink-update.timer"],
        )
        .await
        .is_ok();
    if state.busy() {
        let active = output(
            "/usr/bin/systemctl",
            &["show", "--property=ActiveState", "--value", JOB],
        )
        .await
        .unwrap_or_default();
        if !matches!(
            active.as_str(),
            "active" | "activating" | "reloading" | "deactivating"
        ) {
            state.phase = "failed".into();
            state.error = Some("interrupted".into());
            save(&state)?;
        }
    }
    drop(guard);
    Ok(state)
}

fn validate_submission(
    state: &Status,
    request_id: &str,
    action: &Operation,
    at: i64,
) -> Result<(), &'static str> {
    if !(16..=64).contains(&request_id.len())
        || !request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || !action.valid()
    {
        return Err("invalid_request");
    }
    if state.busy() {
        return Err("busy");
    }
    if let Operation::Install { version } = action {
        if !state.update_available
            || state.latest.as_ref() != Some(version)
            || state.checked_at.is_none_or(|t| at < t || at - t > 3600)
            || version_parts(version) <= version_parts(&state.installed)
        {
            return Err("check_required");
        }
    }
    Ok(())
}

async fn submit(request_id: String, action: Operation) -> io::Result<Status> {
    // Refresh interrupted jobs before admitting a new request.
    let _ = status().await?;
    let guard = lock()?;
    let mut state = load()?;
    state.installed = installed_version().await?;
    if state.request_id.as_ref() == Some(&request_id) {
        if state.operation.as_ref() != Some(&action) {
            return Err(failure("request identifier reused"));
        }
        return Ok(state);
    }
    if let Err(code) = validate_submission(&state, &request_id, &action, now()) {
        let mut response = state.clone();
        response.error = Some(code.into());
        return Ok(response);
    }
    state.request_id = Some(request_id);
    state.operation = Some(action);
    state.phase = "queued".into();
    state.error = None;
    save(&state)?;
    // A fixed, independent systemd job survives stopping/restarting the web app.
    // No URL, executable, unit name, environment or extra argv comes from HTTP.
    let result = output("/usr/bin/systemd-run", &[
        "--quiet", "--collect", "--unit=vaultlink-gui-update", "--service-type=exec",
        "--property=User=root", "--property=Group=root", "--property=UMask=0077",
        "--property=RuntimeMaxSec=120min", "--property=TimeoutStopSec=30min",
        "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
        "--property=ProtectHome=yes", "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
        "--property=RestrictNamespaces=yes", "--property=LockPersonality=yes",
        "--property=CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETGID CAP_SETUID",
        "--property=AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETGID CAP_SETUID",
        "/opt/vaultlink/vaultlink", "update-job",
    ]).await;
    if result.is_err() {
        state.phase = "failed".into();
        state.error = Some("start_failed".into());
        save(&state)?;
    }
    drop(guard);
    Ok(state)
}

async fn serve() -> io::Result<()> {
    private_directory(Path::new(DIRECTORY))?;
    let uid: u32 = output("/usr/bin/id", &["-u", "vaultlink"])
        .await?
        .parse()
        .map_err(|_| failure("invalid service identity"))?;
    if uid == 0 {
        return Err(failure("invalid service identity"));
    }
    let parent = Path::new(SOCKET)
        .parent()
        .ok_or_else(|| failure("socket path"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(failure("unsafe socket directory"));
    }
    // The controller's systemd RuntimeDirectory is recreated on each start.
    let listener = tokio::net::UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660))?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != uid {
            continue;
        }
        let response = tokio::time::timeout(Duration::from_secs(15), async {
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(
                Duration::from_secs(2),
                BufReader::new(&mut stream)
                    .take((MAX_MESSAGE + 1) as u64)
                    .read_until(b'\n', &mut bytes),
            )
            .await;
            if !matches!(read, Ok(Ok(_))) || bytes.len() > MAX_MESSAGE || !bytes.ends_with(b"\n") {
                return Err(failure("invalid controller request"));
            }
            let request: Request = serde_json::from_slice(&bytes)?;
            match request {
                Request::Status {} => status().await,
                Request::Submit { request_id, action } => submit(request_id, action).await,
            }
        })
        .await;
        let result = match response {
            Ok(Ok(state)) => state,
            _ => Status {
                error: Some("host_error".into()),
                ..Status::disconnected()
            },
        };
        let mut bytes = serde_json::to_vec(&result)?;
        bytes.push(b'\n');
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
    }
}

async fn updater(action: &Operation) -> io::Result<String> {
    let name = if matches!(action, Operation::Check {}) {
        "check"
    } else {
        "install"
    };
    let mut command = Command::new("/usr/bin/timeout");
    command
        .args([
            "--signal=TERM",
            "--kill-after=30m",
            "90m",
            "/usr/sbin/vaultlink-update",
            name,
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if let Operation::Install { version } = action {
        command.env("VAULTLINK_EXPECTED_VERSION", version);
    }
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("missing updater output"))?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = stdout.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        if bytes.len() + count <= 65536 {
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
    if !child.wait().await?.success() {
        return Err(failure("signed updater failed"));
    }
    String::from_utf8(bytes).map_err(|_| failure("invalid updater output"))
}

fn parse_check(value: &str) -> io::Result<(String, bool)> {
    let latest: Vec<_> = value
        .lines()
        .filter_map(|l| l.strip_prefix("latest_version="))
        .collect();
    let available: Vec<_> = value
        .lines()
        .filter_map(|l| l.strip_prefix("update_available="))
        .collect();
    match (latest.as_slice(), available.as_slice()) {
        ([version], [available @ ("true" | "false")]) if version_parts(version).is_some() => {
            Ok(((*version).into(), *available == "true"))
        }
        _ => Err(failure("invalid signed updater check result")),
    }
}

async fn set_automatic(enabled: bool) -> io::Result<()> {
    // Use the same flock as the native updater so its configuration snapshot
    // cannot change halfway through an installation or rollback.
    let lock_directory = Path::new("/run/vaultlink-locks");
    let runtime = fs::symlink_metadata("/run")?;
    if !runtime.is_dir()
        || runtime.uid() != 0
        || runtime.gid() != 0
        || runtime.mode() & 0o777 != 0o755
    {
        return Err(failure("unsafe runtime directory"));
    }
    match fs::DirBuilder::new().mode(0o700).create(lock_directory) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    private_directory(lock_directory)?;
    let update_lock = open_private(&lock_directory.join("update.lock"), true)?;
    if fs::symlink_metadata(lock_directory)?.gid() != 0 || update_lock.metadata()?.gid() != 0 {
        return Err(failure("unsafe native update lock ownership"));
    }
    update_lock
        .try_lock()
        .map_err(|_| failure("native updater is busy"))?;
    automatic_config()?;
    let directory = Path::new("/etc/vaultlink");
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(failure("unsafe configuration directory"));
    }
    let previous = match fs::read(directory.join("update.conf")) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let was_enabled = output(
        "/usr/bin/systemctl",
        &["is-enabled", "vaultlink-update.timer"],
    )
    .await
    .is_ok();
    let was_active = output(
        "/usr/bin/systemctl",
        &["is-active", "vaultlink-update.timer"],
    )
    .await
    .is_ok();
    let write = |bytes: &[u8]| -> io::Result<()> {
        let mut stage = tempfile::NamedTempFile::new_in(directory)?;
        rustix::fs::fchown(stage.as_file(), None, Some(rustix::process::Gid::ROOT))?;
        stage
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        stage.write_all(bytes)?;
        stage.as_file().sync_all()?;
        stage
            .persist(directory.join("update.conf"))
            .map_err(|e| e.error)?;
        File::open(directory)?.sync_all()
    };
    // The signed updater serializes package mutation. Its auto mode rechecks
    // this flag before beginning installation; disabling it does not kill jobs.
    write(format!("auto_install={enabled}\n").as_bytes())?;
    if output(
        "/usr/bin/systemctl",
        &[
            if enabled { "enable" } else { "disable" },
            "--now",
            "vaultlink-update.timer",
        ],
    )
    .await
    .is_err()
    {
        if let Some(bytes) = previous {
            write(&bytes)?;
        } else {
            fs::remove_file(directory.join("update.conf"))?;
            File::open(directory)?.sync_all()?;
        }
        let _ = output(
            "/usr/bin/systemctl",
            &[
                if was_enabled { "enable" } else { "disable" },
                "vaultlink-update.timer",
            ],
        )
        .await;
        let _ = output(
            "/usr/bin/systemctl",
            &[
                if was_active { "start" } else { "stop" },
                "vaultlink-update.timer",
            ],
        )
        .await;
        return Err(failure("could not update timer"));
    }
    Ok(())
}

async fn job() -> io::Result<()> {
    private_directory(Path::new(DIRECTORY))?;
    let job_lock = open_private(&Path::new(DIRECTORY).join("job.lock"), true)?;
    job_lock
        .try_lock()
        .map_err(|_| failure("update job already running"))?;
    let mut state = {
        let _guard = lock()?;
        let mut state = load()?;
        if state.phase != "queued" {
            return Err(failure("no queued update job"));
        }
        state.phase = "running".into();
        save(&state)?;
        state
    };
    let action = state
        .operation
        .clone()
        .ok_or_else(|| failure("missing operation"))?;
    let result: io::Result<()> = async {
        match &action {
            Operation::Check {} => {
                let (latest, available) = parse_check(&updater(&action).await?)?;
                state.latest = Some(latest);
                state.update_available = available;
                state.checked_at = Some(now());
            }
            Operation::Install { version } => {
                updater(&action).await?;
                if installed_version().await? != *version {
                    return Err(failure("installed version mismatch"));
                }
                state.update_available = false;
            }
            Operation::Automatic { enabled } => set_automatic(*enabled).await?,
        }
        Ok(())
    }
    .await;
    let _guard = lock()?;
    state.phase = if result.is_ok() { "complete" } else { "failed" }.into();
    state.error = result.as_ref().err().map(|_| "operation_failed".into());
    state.installed = installed_version().await.unwrap_or_default();
    state.automatic = automatic_config().unwrap_or(false);
    save(&state)?;
    result
}

pub async fn run_host(mode: &str) -> io::Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(failure("update host requires root"));
    }
    match mode {
        "update-control" => serve().await,
        "update-job" => job().await,
        _ => Err(failure("invalid host mode")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_configuration_matches_the_signed_updater_grammar() {
        assert!(parse_automatic_config("# comment\n auto_install = true \n").unwrap());
        assert!(!parse_automatic_config("auto_install=false\n").unwrap());
        for value in [
            "",
            "auto_install=true\nauto_install=false",
            "auto_install=yes",
            "auto_install=true\ncommand=id",
        ] {
            assert!(parse_automatic_config(value).is_err());
        }
    }
    #[test]
    fn installation_requires_fresh_matching_check_and_strictly_newer_version() {
        let mut state = Status {
            installed: "0.7.0".into(),
            latest: Some("0.7.1".into()),
            checked_at: Some(100),
            update_available: true,
            phase: "complete".into(),
            ..Status::default()
        };
        let request = Operation::Install {
            version: "0.7.1".into(),
        };
        assert!(validate_submission(&state, "0123456789abcdef", &request, 101).is_ok());
        assert_eq!(
            validate_submission(&state, "0123456789abcdef", &request, 3701),
            Err("check_required")
        );
        state.latest = Some("0.7.2".into());
        assert_eq!(
            validate_submission(&state, "0123456789abcdef", &request, 101),
            Err("check_required")
        );
        state.phase = "running".into();
        assert_eq!(
            validate_submission(&state, "0123456789abcdef", &request, 101),
            Err("busy")
        );
    }
    #[test]
    fn duplicate_or_malformed_updater_output_is_rejected() {
        assert_eq!(
            parse_check("installed_version=0.7.0\nlatest_version=0.7.1\nupdate_available=true\n")
                .unwrap(),
            ("0.7.1".into(), true)
        );
        for output in [
            "latest_version=0.7.1\nlatest_version=0.7.2\nupdate_available=true",
            "latest_version=0.7.1-rc1\nupdate_available=true",
            "latest_version=0.7.1\nupdate_available=yes",
        ] {
            assert!(parse_check(output).is_err());
        }
    }
}
