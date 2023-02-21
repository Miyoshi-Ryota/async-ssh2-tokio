# async-ssh2-tokio
![Unit Test Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/ci.yml/badge.svg)
![Lint Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/super_lint.yml/badge.svg)
[Docs.rs](https://docs.rs/async-ssh2-tokio/latest/async_ssh2_tokio/),
[Crates.io](https://crates.io/crates/async-ssh2-tokio)

This library is an asynchronous and easy-to-use high level ssh client library
for rust with the tokio runtime. Powered by the rust ssh implementation
[russh](https://github.com/warp-tech/russh).


## Features
* Connect to a SSH Host via IP and password
* Execute commands on the remote host
* Get the stdout and exit code of the command

## Install
```rust
[dependencies]
tokio = "1"
async-ssh2-tokio = "0.5.0"
```

## Usage
```rust
use async_ssh2_tokio::client::{Client, AuthMethod};
#[tokio::main]
async fn main() -> Result<(), async_ssh2_tokio::Error> {
    // Only ip and password based authentification is implemented.
    // If you need key based authentification, create github issue or contribute.
    let mut client = Client::connect(
        ("10.10.10.2", 22),
        "root",
        AuthMethod::with_password("root"),
    ).await?;

    let result = client.execute("echo Hello SSH").await?;
    assert_eq!(result.output, "Hello SSH\n");
    assert_eq!(result.exit_status, 0);

    let result = client.execute("echo Hello Again :)").await?;
    assert_eq!(result.output, "Hello Again :)\n");
    assert_eq!(result.exit_status, 0);

    Ok(())
}
```

## Running Tests
In order to run the tests, either set up docker compose on your machine
or set the following environment variables for a working ssh host:

* `ASYNC_SSH2_TEST_HOST_IP`: The ip, e.g. `127.0.0.1` when testing with localhost.
* `ASYNC_SSH2_TEST_HOST_USER`: The username to connect as.
* `ASYNC_SSH2_TEST_HOST_PW`: The corresponding password. Since this is plain text, creating a new unpriviledged user is recommended.

Note: The doc tests do not use these variables and are therefore not run, but only compiled.
