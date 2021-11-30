use thiserror::Error;
use thrussh;

#[derive(Error, Debug)]
pub enum AsyncSsh2Error {
    #[error("password is wrong")]
    PasswordWrong,
    #[error("Other Error Happen")]
    OtherError(#[from] thrussh::Error),
}
