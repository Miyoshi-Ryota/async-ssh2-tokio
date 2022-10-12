# async-ssh2-tokio
![Unit Test Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/ci.yml/badge.svg)
![Lint Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/super_lint.yml/badge.svg)

This library, async-ssh2-tokio, is a asynchronous and super-easy-to-use high level ssh client library for rust.
This library is powered by russh.

## Features
* ssh host by password
* execute command to remote host

## Install
```rust
[dependencies]
tokio = "1"
async-ssh2-tokio = "0.3.0"
```
## Example
```rust
use async_ssh2_tokio::client::{Client, Host, AuthMethod};
use async_ssh2_tokio::error::AsyncSsh2Error;
#[tokio::main]
async fn main() -> Result<(), AsyncSsh2Error> {
    let username = "username".to_string();
    // Key auth is under development. If you need this, then create github issue or contribute this.
    let password = AuthMethod::Password("password".to_string());

    let mut client = Client::new("localhost:22", username, password);
    client.connect().await?;
    let result = client.execute("echo test!!!").await?;
    assert_eq!(result.output, "test!!!\n");
    Ok(())
}
```
