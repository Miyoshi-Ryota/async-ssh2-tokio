//! This library is an asynchronous and easy-to-use high level ssh client library
//! for rust with the tokio runtime. Powered by the rust ssh implementation
//! [russh](https://github.com/warp-tech/russh), a fork of thrussh.
//!
//! The heart of this library is [`client::Client`]. Use this for connection, authentification and execution.
//!
//! # Features
//! * Connect to a SSH Host via IP
//! * Execute commands on the remote host
//! * Get the stdout and exit code of the command
//!
//! # Example
//! ```no_run
//! use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};
//! #[tokio::main]
//! async fn main() -> Result<(), async_ssh2_tokio::Error> {
//!     // if you want to use key auth, then use following:
//!     // AuthMethod::with_key_file("key_file_name", Some("passphrase"));
//!     // or
//!     // AuthMethod::with_key_file("key_file_name", None);
//!     // or
//!     // AuthMethod::with_key(key: &str, passphrase: Option<&str>)
//!     // if you want to use SSH agent (Unix/Linux only), then use following:
//!     // AuthMethod::with_agent();
//!     let auth_method = AuthMethod::with_password("root");
//!     let mut client = Client::connect(
//!         ("10.10.10.2", 22),
//!         "root",
//!         auth_method,
//!         ServerCheckMethod::NoCheck,
//!     ).await?;
//!
//!     let result = client.execute("echo Hello SSH").await?;
//!     assert_eq!(result.stdout, "Hello SSH\n");
//!     assert_eq!(result.exit_status, 0);
//!
//!     let result = client.execute("echo Hello Again :)").await?;
//!     assert_eq!(result.stdout, "Hello Again :)\n");
//!     assert_eq!(result.exit_status, 0);
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
mod to_socket_addrs_with_hostname;

pub use client::{AuthMethod, Client, ServerCheckMethod};
pub use error::Error;
pub use to_socket_addrs_with_hostname::ToSocketAddrsWithHostname;

pub use russh::client::Config;
