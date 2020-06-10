#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unexpected format in /proc/self/mounts")]
    InvalidProcMounts,

    #[error("Systemd not found in standard locations")]
    NoSystemdFound,

    #[error("Systemd is not running")]
    NotRunning,
}
