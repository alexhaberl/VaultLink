/// Own the bootstrap processes until setup explicitly requests the service.
/// The public bootstrap listener must be gone before authenticated proxy
/// transports or the configured application listener start accepting traffic.
async fn run_container_setup(
    config_path: &std::path::Path,
    listen: std::net::SocketAddr,
) -> io::Result<bool> {
    if !listen.ip().is_loopback() {
        return Err(io::Error::other(
            "Container setup must use a loopback address",
        ));
    }
    let executable = env::current_exe()?;
    let child = || {
        let mut command = tokio::process::Command::new(&executable);
        command
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null());
        command
    };
    let mut health = child().arg("health-bootstrap").spawn()?;
    let mut proxy = child()
        .arg("container-proxy")
        .arg("--listen")
        .arg(env::var("VAULTLINK_CONTAINER_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into()))
        .arg("--setup-upstream")
        .arg(listen.to_string())
        .arg("--config")
        .arg(config_path)
        .spawn()?;
    let mut setup = child()
        .arg("setup-once")
        .arg("--config")
        .arg(config_path)
        .arg("--listen")
        .arg(listen.to_string())
        .spawn()?;
    let result = tokio::select! {
        status = setup.wait() => status.and_then(|status| {
            if status.success() {
                Ok(true)
            } else {
                Err(io::Error::other("Container setup failed"))
            }
        }),
        _ = proxy.wait() => Err(io::Error::other("Container bootstrap proxy stopped")),
        _ = health.wait() => Err(io::Error::other("Container bootstrap health listener stopped")),
        _ = shutdown_signal() => Ok(false),
    };
    // kill() also waits for exit; dropping handles alone would leave a window
    // where the public bootstrap listener overlaps the normal service.
    for process in [&mut setup, &mut proxy, &mut health] {
        if process.try_wait()?.is_none() {
            process.kill().await?;
        }
    }
    result
}
