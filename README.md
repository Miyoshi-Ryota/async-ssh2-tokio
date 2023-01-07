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
use async_ssh2_tokio::client::{Client, AuthMethod};
use async_ssh2_tokio::error::AsyncSsh2Error;
#[tokio::main]
async fn main() -> Result<(), AsyncSsh2Error> {
    // Only ip and password based authentification is implemented.
    // If you need key based authentification, create github issue or contribute.
    let mut client = Client::new(("10.10.10.2", 22), "root", AuthMethod::with_password("root"))?;

    client.connect().await?;
    let result = client.execute("echo Hello SSH").await?;
    assert_eq!(result.output,  "Hello SSH\n");
    Ok(())
}
```

## Running Tests
In order to run the tests, either set up docker compose on your machine
or set the following environment variables for a working ssh host:

* `ASYNC_SSH2_TEST_HOST_IP`: The ip, e.g. `127.0.0.1` when testing with localhost.
* `ASYNC_SSH2_TEST_HOST_USER`: The username to connect as.
* `ASYNC_SSH2_TEST_HOST_PW`: The corresponding password. Since this is plain text, creating a new unpriviledged user is recommended.

Note: The doc tests do not use these variables.
