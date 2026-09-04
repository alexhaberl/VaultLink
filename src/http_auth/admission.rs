pub async fn with_audit_client_ip<F>(client_ip: Option<IpAddr>, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_AUDIT_CLIENT_IP.scope(client_ip, future).await
}

pub fn current_audit_client_ip() -> Option<IpAddr> {
    REQUEST_AUDIT_CLIENT_IP
        .try_with(|client_ip| *client_ip)
        .ok()
        .flatten()
}

pub fn enabled_audit_client_ip(state: &(impl Borrow<AppState> + ?Sized)) -> Option<String> {
    runtime_settings(state)
        .audit_client_ip_enabled
        .then(current_audit_client_ip)
        .flatten()
        .map(|ip| ip.to_string())
}

pub fn current_client_limit_key() -> IpAddr {
    crate::proxy::client_limit_key(
        current_audit_client_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )
}

/// Shared web/API admission for administrator password login.
pub fn admin_login_attempt_admitted(
    state: &(impl Borrow<AppState> + ?Sized),
    username: &str,
) -> bool {
    let state = borrowed_app_state(state);
    state
        .admin_login_limiter()
        .check_and_record_attempt(username, current_client_limit_key())
}
