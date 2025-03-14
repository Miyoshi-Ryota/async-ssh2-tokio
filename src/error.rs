use std::io;

/// This is the `thiserror` error for all crate errors.
///
/// Most ssh related error is wrapped in the `SshError` variant,
/// giving access to the underlying [`russh::Error`] type.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Keyboard-interactive authentication failed")]
    KeyboardInteractiveAuthFailed,
    #[error("No keyboard-interactive response for prompt: {0}")]
    KeyboardInteractiveNoResponseForPrompt(String),
    #[error("Key authentication failed")]
    KeyAuthFailed,
    #[error("Unable to load key, bad format or passphrase: {0}")]
    KeyInvalid(russh::keys::Error),
    #[error("Password authentication failed")]
    PasswordWrong,
    #[error("Invalid address was provided: {0}")]
    AddressInvalid(io::Error),
    #[error("The executed command didn't send an exit code")]
    CommandDidntExit,
    #[error("Server check failed")]
    ServerCheckFailed,
    #[error("Ssh error occured: {0}")]
    SshError(#[from] russh::Error),
    #[error("Send error")]
    SendError(#[from] russh::SendError),
    #[error("Agent auth error")]
    AgentAuthError(#[from] russh::AgentAuthError),
    #[error("SFTP error occured: {0}")]
    SftpError(#[from] russh_sftp::client::error::Error),
    #[error("I/O error")]
    IoError(#[from] io::Error),
}
