# async-ssh2-tokio
![Unit Test Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/ci.yml/badge.svg)
![Lint Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/super_lint.yml/badge.svg)

This library, async-ssh2-tokio, is a asynchronous and super-easy-to-use high level ssh client library for rust.
This library is powered by thrussh.

## Features
* ssh host by password
* execute command to remote host

## Install
```rust
[dependencies]
tokio = "1"
async-ssh2-tokio = "0.1"
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

    // If you want specify host by ip, then
    // use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    // let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // let host = Host::IpAddress(localhost_v4);
    let host = Host::Hostname("localhost".to_string());
    let port = 22;
    let mut client = Client::new(host, port, username, password);
    client.connect().await?;
    let result = client.execute("echo test!!!").await?;
    assert_eq!(result.output, "test!!!\n");
    Ok(())
}
```
