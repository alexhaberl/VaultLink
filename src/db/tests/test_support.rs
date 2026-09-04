use super::*;

static SQLITE_BUSY_WAIT_SIGNAL: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
    std::sync::Mutex::new(None);

fn signal_sqlite_busy_wait(_attempt: i32) -> bool {
    if let Some(sender) = SQLITE_BUSY_WAIT_SIGNAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        let _ = sender.send(());
    }
    std::thread::sleep(std::time::Duration::from_millis(1));
    true
}
