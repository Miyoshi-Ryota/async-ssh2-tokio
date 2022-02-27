use std::net::{IpAddr, Ipv4Addr};

use async_ssh2_tokio::client::{AuthMethod, Client, Host};
use async_ssh2_tokio::error::AsyncSsh2Error;

#[tokio::main]
async fn main() -> Result<(), AsyncSsh2Error> {
    let username = "testuser".to_string();
    // Key auth is under development. If you need this, then create github issue or contribute this.
    let password = AuthMethod::Password("testuser".to_string());
    let enable_password = "testpassword".to_string();
    // If you want specify host by ip, then
    // use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    // let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // let host = Host::IpAddress(localhost_v4);
    let host = Host::Hostname("172.16.1.211".to_string());
    let port = 22;
    let mut client = Client::new(host, port, username, password);
    client.connect().await.unwrap();
    let result = client
        .execute("en")
        .await.unwrap();
    println!("{}", result.output);

    let result = client
        .execute(&enable_password)
        .await.unwrap();

    println!("{}", result.output);

    let result = client
    .execute("show run")
    .await.unwrap();

    println!("{}", result.output);

    Ok(())
}
