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
//! async-ssh2-tokio = "0.4.0"
//! ```
//! # Example
//! ```
//! use async_ssh2_tokio::client::{Client, AuthMethod};
//! use async_ssh2_tokio::error::AsyncSsh2Error;
//! #[tokio::main]
//! async fn main() -> Result<(), AsyncSsh2Error> {
//!     // Only ip and password based authentification is implemented.
//!     // If you need key based authentification, create github issue or contribute.
//!     let mut client = Client::new(("10.10.10.2", 22), "root", AuthMethod::with_password("root"))?;
//!
//!     client.connect().await?;
//!     let result = client.execute("echo Hello SSH").await?;
//!     assert_eq!(result.output,  "Hello SSH\n");
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
