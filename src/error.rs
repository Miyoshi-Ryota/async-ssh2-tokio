use std::io;

use russh;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AsyncSsh2Error {
    #[error("Authentification failed")]
    PasswordWrong,
    #[error("Invalid address was provided")]
    AddressInvalid(#[from] io::Error),
    #[error("Client not connected, call Client::connect first")]
    NotConnected,
    #[error("Other error occured")]
    OtherError(#[from] russh::Error),
}
