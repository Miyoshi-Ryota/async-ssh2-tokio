//! This library, async-ssh2-tokio, is a asynchronous and super-easy-to-use high level ssh client library for rust.
//! This library is powered by thrussh.
//!
//! # Features
//! * ssh host by password
//! * execute command to remote host
//!
//! # Install
//! ```ignore
//! [dependencies]
//! tokio = "1"
//! async-ssh2-tokio = "0.1"
//! ```
//! # Example
//! ```
//! use async_ssh2_tokio::client::{Client, Host, AuthMethod};
//! use async_ssh2_tokio::error::AsyncSsh2Error;
//! #[tokio::main]
//! async fn main() -> Result<(), AsyncSsh2Error> {
//!     let username = "root".to_string();
//!     // Key auth is under development. If you need this, then create github issue or contribute this.
//!     let password = AuthMethod::Password("root".to_string());
//!
//!     let mut client = Client::new("10.10.10.2:22", username, password);
//!     client.connect().await?;
//!     let result = client.execute("echo test!!!").await?;
//!     assert_eq!(result.output, "test!!!\n");
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
