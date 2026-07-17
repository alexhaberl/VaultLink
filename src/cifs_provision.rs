use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::storage_mount;

pub const MOUNT_POINT: &str = "/mnt/storage";
pub const ROOT_MOUNT_PATH: &str = MOUNT_POINT;
pub const INTERNAL_DIRECTORY: &str = "/mnt/storage/.vaultlink-internal";
const CREDENTIAL_PATH: &str = "/etc/vaultlink/smb-credentials";
const MOUNT_UNIT_PATH: &str = "/etc/systemd/system/mnt-storage.mount";
const MOUNT_UNIT_NAME: &str = "mnt-storage.mount";
const SERVICE_DROP_IN_DIRECTORY: &str = "/etc/systemd/system/vaultlink.service.d";
const SERVICE_DROP_IN_PATH: &str = "/etc/systemd/system/vaultlink.service.d/external-storage.conf";

#[derive(Debug, Error)]
#[error("{0}")]
pub struct CifsProvisionError(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CifsProvisionOptions {
    pub source: String,
    pub username: String,
    pub domain: Option<String>,
}

impl CifsProvisionOptions {
    pub fn parse(args: &[String]) -> Result<Self, CifsProvisionError> {
        if args.get(1).map(String::as_str) != Some("provision-cifs") {
            return Err(error(
                "provision-cifs parser requires the provision-cifs command",
            ));
        }
        let mut source = None;
        let mut username = None;
        let mut domain = None;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            let target = match option {
                "--source" => &mut source,
                "--username" => &mut username,
                "--domain" => &mut domain,
                unknown if unknown.starts_with('-') => {
                    return Err(error(format!("unknown provision-cifs option: {unknown}")))
                }
                positional => {
                    return Err(error(format!(
                        "unexpected provision-cifs positional argument: {positional}"
                    )))
                }
            };
            let value = args
                .get(index + 1)
                .ok_or_else(|| error(format!("{option} requires one non-option value")))?;
            if value.is_empty() || value.starts_with('-') {
                return Err(error(format!("{option} requires one non-option value")));
            }
            if target.replace(value.clone()).is_some() {
                return Err(error(format!("{option} may only be provided once")));
            }
            index += 2;
        }
        let options = Self {
            source: source.ok_or_else(|| error("provision-cifs requires --source"))?,
            username: username.ok_or_else(|| error("provision-cifs requires --username"))?,
            domain,
        };
        options.validate()?;
        Ok(options)
    }

    fn validate(&self) -> Result<(), CifsProvisionError> {
        validate_unc_source(&self.source)?;
        validate_credential_value("SMB username", &self.username)?;
        if let Some(domain) = self.domain.as_deref() {
            validate_credential_value("SMB domain", domain)?;
        }
        Ok(())
    }
}

pub fn run(options: &CifsProvisionOptions) -> Result<(), CifsProvisionError> {
    options.validate()?;
    let identity = preflight()?;
    let password = Zeroizing::new(rpassword::prompt_password("SMB password: ").map_err(
        |cause| {
            error(format!(
                "cannot read SMB password from the terminal: {cause}"
            ))
        },
    )?);
    validate_password(password.as_str())?;
    provision(options, password.as_str(), identity)?;
    println!(
        "CIFS mount provisioned and active.\n\
         Mount source: {}\n\
         Mount point: {MOUNT_POINT}\n\
         VaultLink root: {ROOT_MOUNT_PATH}\n\
         VaultLink internal directory: {INTERNAL_DIRECTORY}\n\
         Return to the local browser setup and refresh the detected SMB mounts.\n\
         Server-side SMB ACL verification remains mandatory before completing setup.",
        options.source
    );
    Ok(())
}

fn preflight() -> Result<(u32, u32), CifsProvisionError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(error(
            "provision-cifs must run as root (use sudo); the browser setup must remain unprivileged",
        ));
    }
    if !Path::new("/sbin/mount.cifs").is_file() && !Path::new("/usr/sbin/mount.cifs").is_file() {
        return Err(error(
            "mount.cifs is missing; install the cifs-utils package first",
        ));
    }
    let identity = vaultlink_service_identity()?;
    let installed_service = Command::new("/usr/bin/systemctl")
        .args(["cat", "vaultlink.service"])
        .output()
        .map_err(|cause| error(format!("cannot inspect vaultlink.service: {cause}")))?;
    if !installed_service.status.success() {
        return Err(error(
            "vaultlink.service is not installed; install the shipped service unit before provisioning storage",
        ));
    }
    let vaultlink_status = Command::new("/usr/bin/systemctl")
        .args(["--quiet", "is-active", "vaultlink.service"])
        .status()
        .map_err(|cause| error(format!("cannot query vaultlink.service: {cause}")))?;
    if vaultlink_status.success() {
        return Err(error(
            "vaultlink.service is active; stop it before provisioning or changing its storage mount",
        ));
    }
    if let Some(active) = storage_mount::active_mount_at(Path::new(MOUNT_POINT))
        .map_err(|cause| error(cause.to_string()))?
    {
        return Err(error(format!(
            "{MOUNT_POINT} is already an active {} mount from {:?}; use setup discovery instead of overwriting it",
            active.filesystem_type, active.source
        )));
    }
    for path in [CREDENTIAL_PATH, MOUNT_UNIT_PATH, SERVICE_DROP_IN_PATH] {
        if Path::new(path).exists() {
            return Err(error(format!(
                "refusing to overwrite existing provisioning file {path}"
            )));
        }
    }
    Ok(identity)
}

fn provision(
    options: &CifsProvisionOptions,
    password: &str,
    (uid, gid): (u32, u32),
) -> Result<(), CifsProvisionError> {
    ensure_root_directory(Path::new("/etc/vaultlink"), 0o750)?;
    ensure_root_directory(Path::new(SERVICE_DROP_IN_DIRECTORY), 0o755)?;
    ensure_root_directory(Path::new(MOUNT_POINT), 0o755)?;

    let credential_body = credential_file(options, password);
    let mount_unit = render_mount_unit(&options.source, uid, gid);
    let drop_in = render_service_drop_in();
    let mut created_files = Vec::new();
    let result = (|| {
        write_new_file(
            Path::new(CREDENTIAL_PATH),
            credential_body.as_bytes(),
            0o600,
        )?;
        created_files.push(PathBuf::from(CREDENTIAL_PATH));
        write_new_file(Path::new(MOUNT_UNIT_PATH), mount_unit.as_bytes(), 0o644)?;
        created_files.push(PathBuf::from(MOUNT_UNIT_PATH));
        write_new_file(Path::new(SERVICE_DROP_IN_PATH), drop_in.as_bytes(), 0o644)?;
        created_files.push(PathBuf::from(SERVICE_DROP_IN_PATH));

        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["enable", MOUNT_UNIT_NAME])?;
        run_systemctl(&["start", MOUNT_UNIT_NAME])?;
        verify_active_mount(&options.source)?;
        verify_preprovisioned_layout()?;
        Ok(())
    })();
    if let Err(cause) = result {
        rollback(&created_files);
        return Err(cause);
    }
    Ok(())
}

fn validate_unc_source(source: &str) -> Result<(), CifsProvisionError> {
    let Some(rest) = source.strip_prefix("//") else {
        return Err(error("SMB source must use //server/share syntax"));
    };
    let mut components = rest.split('/');
    let server = components.next().unwrap_or_default();
    let share = components.next().unwrap_or_default();
    if server.is_empty() || share.is_empty() || components.next().is_some() {
        return Err(error(
            "SMB source must name exactly one server and one share: //server/share",
        ));
    }
    for (name, value) in [("server", server), ("share", share)] {
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'$'))
        {
            return Err(error(format!(
                "SMB {name} contains unsupported characters; use letters, digits, dot, underscore, hyphen, or dollar"
            )));
        }
    }
    Ok(())
}

fn validate_credential_value(name: &str, value: &str) -> Result<(), CifsProvisionError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n' | b'='))
    {
        return Err(error(format!(
            "{name} must be non-empty and must not contain NUL, a line break, or '='"
        )));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), CifsProvisionError> {
    if password.is_empty()
        || password
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(error(
            "SMB password must be non-empty and must not contain NUL or a line break",
        ));
    }
    Ok(())
}

fn credential_file(options: &CifsProvisionOptions, password: &str) -> Zeroizing<String> {
    let mut body = Zeroizing::new(format!(
        "username={}\npassword={}\n",
        options.username, password
    ));
    if let Some(domain) = options.domain.as_deref() {
        body.push_str("domain=");
        body.push_str(domain);
        body.push('\n');
    }
    body
}

fn render_mount_unit(source: &str, uid: u32, gid: u32) -> String {
    format!(
        "[Unit]\n\
         Description=External SMB storage for VaultLink\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         Before=vaultlink.service\n\n\
         [Mount]\n\
         What={source}\n\
         Where={MOUNT_POINT}\n\
         Type=cifs\n\
         Options=_netdev,credentials={CREDENTIAL_PATH},vers=3.1.1,sign,seal,cache=strict,serverino,nosuid,nodev,noexec,uid={uid},gid={gid},file_mode=0600,dir_mode=0700\n\
         TimeoutSec=30s\n\n\
         [Install]\n\
         WantedBy=remote-fs.target\n"
    )
}

fn render_service_drop_in() -> &'static str {
    "[Unit]\nRequiresMountsFor=/mnt/storage\nAfter=remote-fs.target\n"
}

fn ensure_root_directory(path: &Path, mode: u32) -> Result<(), CifsProvisionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(error(format!(
                    "{} must be a real directory, not a symlink or another file type",
                    path.display()
                )));
            }
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(error(format!(
                    "{} must be owned by root and not writable by group or other users",
                    path.display()
                )));
            }
        }
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|cause| {
                error(format!(
                    "cannot create directory {}: {cause}",
                    path.display()
                ))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|cause| {
                error(format!(
                    "cannot set permissions on directory {}: {cause}",
                    path.display()
                ))
            })?;
            sync_parent(path)?;
        }
        Err(cause) => {
            return Err(error(format!(
                "cannot inspect directory {}: {cause}",
                path.display()
            )))
        }
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), CifsProvisionError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|cause| error(format!("cannot create {}: {cause}", path.display())))?;
    let persisted = file
        .write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|cause| error(format!("cannot persist {}: {cause}", path.display())))
        .and_then(|_| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|cause| {
                error(format!(
                    "cannot set permissions on {}: {cause}",
                    path.display()
                ))
            })
        })
        .and_then(|_| sync_parent(path));
    if let Err(cause) = persisted {
        drop(file);
        let _ = fs::remove_file(path);
        let _ = sync_parent(path);
        return Err(cause);
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), CifsProvisionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|cause| {
            error(format!(
                "cannot sync parent directory {}: {cause}",
                parent.display()
            ))
        })
}

fn vaultlink_service_identity() -> Result<(u32, u32), CifsProvisionError> {
    let output = Command::new("/usr/bin/id")
        .arg("vaultlink")
        .output()
        .map_err(|cause| {
            error(format!(
                "cannot resolve vaultlink service identity: {cause}"
            ))
        })?;
    if !output.status.success() {
        return Err(command_error("id", &["vaultlink"], &output));
    }
    let output = String::from_utf8_lossy(&output.stdout);
    let parse = |prefix: &str| {
        output
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix(prefix))
            .and_then(|value| {
                value
                    .split_once('(')
                    .map_or(Some(value), |(number, _)| Some(number))
            })
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| error("id returned an invalid numeric vaultlink service identity"))
    };
    Ok((parse("uid=")?, parse("gid=")?))
}

fn run_systemctl(arguments: &[&str]) -> Result<(), CifsProvisionError> {
    let output = Command::new("/usr/bin/systemctl")
        .args(arguments)
        .output()
        .map_err(|cause| error(format!("cannot run systemctl: {cause}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error("systemctl", arguments, &output))
    }
}

fn command_error(program: &str, arguments: &[&str], output: &Output) -> CifsProvisionError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    error(format!(
        "{program} {} failed with status {}: {}",
        arguments.join(" "),
        output.status,
        stderr.trim()
    ))
}

fn verify_active_mount(expected_source: &str) -> Result<(), CifsProvisionError> {
    let active = storage_mount::active_mount_at(Path::new(MOUNT_POINT))
        .map_err(|cause| error(cause.to_string()))?
        .ok_or_else(|| error(format!("{MOUNT_POINT} is not active after systemd start")))?;
    if !matches!(active.filesystem_type.as_str(), "cifs" | "smb3")
        || active.source != expected_source
        || !active.read_write
    {
        return Err(error(format!(
            "mounted identity does not match the requested read-write CIFS source: type {:?}, source {:?}",
            active.filesystem_type, active.source
        )));
    }
    let detected =
        storage_mount::discover_supported_mounts().map_err(|cause| error(cause.to_string()))?;
    if !detected
        .iter()
        .any(|mount| mount.mount_point == Path::new(MOUNT_POINT) && mount.source == expected_source)
    {
        return Err(error(
            "the active CIFS mount is missing one or more mandatory security options",
        ));
    }
    Ok(())
}

fn verify_preprovisioned_layout() -> Result<(), CifsProvisionError> {
    for path in [
        INTERNAL_DIRECTORY,
        "/mnt/storage/.vaultlink-internal/uploads",
        "/mnt/storage/.vaultlink-internal/tombstones",
    ] {
        let metadata = fs::symlink_metadata(path).map_err(|cause| {
            error(format!(
                "required server-side provisioned directory {path} is unavailable: {cause}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(error(format!(
                "required server-side provisioned path {path} must be a real directory"
            )));
        }
    }
    Ok(())
}

fn rollback(created_files: &[PathBuf]) {
    let _ = Command::new("/usr/bin/systemctl")
        .args(["stop", MOUNT_UNIT_NAME])
        .status();
    let _ = Command::new("/usr/bin/systemctl")
        .args(["disable", MOUNT_UNIT_NAME])
        .status();
    for path in created_files.iter().rev() {
        let _ = fs::remove_file(path);
        let _ = path
            .parent()
            .and_then(|parent| fs::File::open(parent).ok())
            .and_then(|directory| directory.sync_all().ok());
    }
    let _ = Command::new("/usr/bin/systemctl")
        .arg("daemon-reload")
        .status();
}

fn error(message: impl Into<String>) -> CifsProvisionError {
    CifsProvisionError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parser_accepts_only_the_narrow_non_secret_interface() {
        let parsed = CifsProvisionOptions::parse(&args(&[
            "vaultlink",
            "provision-cifs",
            "--source",
            "//fileserver.example/vaultlink$",
            "--username",
            "vaultlink-service",
            "--domain",
            "EXAMPLE",
        ]))
        .unwrap();
        assert_eq!(parsed.source, "//fileserver.example/vaultlink$");
        assert_eq!(parsed.username, "vaultlink-service");
        assert_eq!(parsed.domain.as_deref(), Some("EXAMPLE"));
        assert!(CifsProvisionOptions::parse(&args(&[
            "vaultlink",
            "provision-cifs",
            "--password",
            "secret"
        ]))
        .is_err());
    }

    #[test]
    fn unc_and_credential_values_reject_injection_and_subpaths() {
        for source in [
            "server/share",
            "//server",
            "//server/share/subdir",
            "//server/share%0aOptions=rw",
            "//server/share name",
        ] {
            assert!(validate_unc_source(source).is_err(), "accepted {source:?}");
        }
        assert!(validate_unc_source("//server.example/share-name$").is_ok());
        assert!(validate_credential_value("username", "admin\npassword=bad").is_err());
        assert!(validate_password("secret\rnext").is_err());
    }

    #[test]
    fn generated_unit_fixes_every_audited_cifs_option() {
        assert_eq!(ROOT_MOUNT_PATH, MOUNT_POINT);
        let unit = render_mount_unit("//server/share", 123, 456);
        for required in [
            "Type=cifs",
            "vers=3.1.1",
            "sign",
            "seal",
            "cache=strict",
            "serverino",
            "nosuid",
            "nodev",
            "noexec",
            "uid=123",
            "gid=456",
            "file_mode=0600",
            "dir_mode=0700",
        ] {
            assert!(unit.contains(required), "unit omitted {required}");
        }
        assert!(!unit.contains("password"));
        assert_eq!(
            render_service_drop_in(),
            include_str!("../deploy/vaultlink-external-storage.conf")
                .split_once("[Unit]")
                .map(|(_, body)| format!("[Unit]{body}"))
                .unwrap()
        );
    }

    #[test]
    fn credential_body_is_line_based_without_echoing_into_the_unit() {
        let options = CifsProvisionOptions {
            source: "//server/share".into(),
            username: "vaultlink-service".into(),
            domain: Some("EXAMPLE".into()),
        };
        let body = credential_file(&options, "correct horse battery staple");
        assert_eq!(
            body.as_str(),
            "username=vaultlink-service\npassword=correct horse battery staple\ndomain=EXAMPLE\n"
        );
    }
}
