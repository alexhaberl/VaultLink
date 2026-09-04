fn validate_admin_username(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !auth::valid_admin_username(username) {
        return Err("username must contain 3-64 safe ASCII characters".into());
    }
    Ok(())
}
fn prompt_new_admin_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let password = Zeroizing::new(rpassword::prompt_password("New admin password: ")?);
    validate_admin_password(password.as_str())?;
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if password.as_str() != confirmation.as_str() {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

fn validate_admin_password(password: &str) -> Result<(), &'static str> {
    if !auth::valid_admin_password(password) {
        return Err("password must contain between 14 and 256 characters");
    }
    Ok(())
}
