use russh;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AsyncSsh2Error {
    #[error("password is wrong")]
    PasswordWrong,
    #[error("address '{0}' is wrong")]
    AddressWrong(String),
    #[error("Other Error Happen")]
    OtherError(#[from] russh::Error),
}
