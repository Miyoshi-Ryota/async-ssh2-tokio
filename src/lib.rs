//! This library is an asynchronous and easy-to-use high level ssh client library
//! for rust with the tokio runtime. Powered by the rust ssh implementation
//! [russh](https://github.com/warp-tech/russh), a fork of thrussh.
//!
//! The heart of this library is [`client::Client`]. Use this for connection, authentification and execution.
//!
//! # Features
//! * Connect to a SSH Host via IP and password.
//! * Execute commands on the remote host
//! * Get the stdout and exit code of the command
//!
//! # Example
//! ```no_run
//! use async_ssh2_tokio::client::{Client, AuthMethod};
//! #[tokio::main]
//! async fn main() -> Result<(), async_ssh2_tokio::Error> {
//!     // Only ip and password based authentification is implemented.
//!     // If you need key based authentification, create github issue or contribute.
//!     let mut client = Client::connect(
//!         ("10.10.10.2", 22),
//!         "root",
//!         AuthMethod::with_password("root"),
//!     ).await?;
//!
//!     let result = client.execute("echo Hello SSH").await?;
//!     assert_eq!(result.output, "Hello SSH\n");
//!     assert_eq!(result.exit_status, 0);
//!
//!     let result = client.execute("echo Hello Again :)").await?;
//!     assert_eq!(result.output, "Hello Again :)\n");
//!     assert_eq!(result.exit_status, 0);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;

pub use client::{AuthMethod, Client};
pub use error::Error;
