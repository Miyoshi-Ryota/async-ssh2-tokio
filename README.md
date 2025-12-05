# async-ssh2-tokio
![Unit Test Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/ci.yml/badge.svg)
![Lint Status](https://github.com/Miyoshi-Ryota/async-ssh2-tokio/actions/workflows/super_lint.yml/badge.svg)
[![Docs.rs](https://docs.rs/async-ssh2-tokio/badge.svg)](https://docs.rs/async-ssh2-tokio/latest/async_ssh2_tokio/)
[![Crates.io](https://img.shields.io/crates/v/async-ssh2-tokio.svg)](https://crates.io/crates/async-ssh2-tokio)

This library is an asynchronous and easy-to-use high level SSH client library
for rust with the tokio runtime. Powered by the rust SSH implementation
[russh](https://github.com/warp-tech/russh).


## Features
* Connect to an SSH Host
* Execute commands on the remote host
* Get the stdout and exit code of the command

## Install
```toml
[dependencies]
tokio = "1"
async-ssh2-tokio = "0.12.1"
```

## Usage
```rust
use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};

#[tokio::main]
async fn main() -> Result<(), async_ssh2_tokio::Error> {
    // if you want to use key auth, then use following:
    // AuthMethod::with_key_file("key_file_name", Some("passphrase"));
    // or
    // AuthMethod::with_key_file("key_file_name", None);
    // or
    // AuthMethod::with_key(key: &str, passphrase: Option<&str>)
    // if you want to use SSH agent (Unix/Linux only), then use following:
    // AuthMethod::with_agent();
    let auth_method = AuthMethod::with_password("root");
    let mut client = Client::connect(
        ("10.10.10.2", 22),
        "root",
        auth_method,
        ServerCheckMethod::NoCheck,
    ).await?;

    let result = client.execute("echo Hello SSH").await?;
    assert_eq!(result.stdout, "Hello SSH\n");
    assert_eq!(result.exit_status, 0);

    let result = client.execute("echo Hello Again :)").await?;
    assert_eq!(result.stdout, "Hello Again :)\n");
    assert_eq!(result.exit_status, 0);

    Ok(())
}
```

## Running Tests
1. install docker and docker compose
2. run shell script `./tests/run_unit_tests.sh`
