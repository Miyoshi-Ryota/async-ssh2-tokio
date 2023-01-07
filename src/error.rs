use std::io;

use russh;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AsyncSsh2Error {
    #[error("password is wrong")]
    PasswordWrong,
    #[error("Invalid address was provided")]
    AddressInvalid(#[from] io::Error),
    #[error("Other Error Happen")]
    OtherError(#[from] russh::Error),
}
