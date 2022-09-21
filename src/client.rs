extern crate russh;
extern crate russh_keys;
use crate::error::AsyncSsh2Error;
use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Hostname(String),
    IpAddress(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Host::Hostname(host) => host.to_string(),
                Host::IpAddress(ip) => ip.to_string(),
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    Password(String),
}

pub struct Client {
    addr: String,
    username: String,
    auth: AuthMethod,
    config: Arc<russh::client::Config>,
    channel: Option<russh::Channel<russh::client::Msg>>,
}

impl Client {
    pub fn new(addr: &str, username: String, auth: AuthMethod) -> Self {
        let config = russh::client::Config::default();
        let config = Arc::new(config);
        Self {
            addr: addr.into(),
            username,
            auth,
            config,
            channel: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), AsyncSsh2Error> {
        let handler = Handler::new();
        let config = self.config.clone();
        let addr = &self.addr;
        let username = self.username.clone();
        let auth = self.auth.clone();
        let mut handle = russh::client::connect(
            config,
            addr.parse()
                .map_err(|_| AsyncSsh2Error::AddressWrong(addr.into()))?,
            handler,
        )
        .await?;
        let AuthMethod::Password(password) = auth;
        if handle.authenticate_password(username, password).await? {
            self.channel = Some(handle.channel_open_session().await?);
            Ok(())
        } else {
            Err(AsyncSsh2Error::PasswordWrong)
        }
    }

    pub async fn execute(
        &mut self,
        command: &str,
    ) -> Result<CommandExecutedResult, AsyncSsh2Error> {
        let mut command_execute_result_byte = vec![];
        if let Some(channel) = self.channel.as_mut() {
            channel.exec(true, command).await?;
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { ref data } => {
                        command_execute_result_byte.write_all(data).unwrap()
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        let result = CommandExecutedResult::new(
                            String::from_utf8_lossy(&command_execute_result_byte).to_string(),
                            exit_status,
                        );
                        return Ok(result);
                    }
                    _ => {}
                }
            }
        }

        Err(AsyncSsh2Error::PasswordWrong)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    pub output: String,
    pub exit_status: u32,
}

impl CommandExecutedResult {
    fn new(output: String, exit_status: u32) -> Self {
        Self {
            output,
            exit_status,
        }
    }
}

#[derive(Clone)]
struct Handler;

impl Handler {
    fn new() -> Self {
        Self {}
    }
}

impl russh::client::Handler for Handler {
    type Error = AsyncSsh2Error;
    type FutureUnit = std::future::Ready<Result<(Self, russh::client::Session), Self::Error>>;
    type FutureBool = std::future::Ready<Result<(Self, bool), Self::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        std::future::ready(Ok((self, b)))
    }
    fn finished(self, session: russh::client::Session) -> Self::FutureUnit {
        std::future::ready(Ok((self, session)))
    }
    fn check_server_key(self, _server_public_key: &russh_keys::key::PublicKey) -> Self::FutureBool {
        self.finished_bool(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::client::*;
    #[tokio::test]
    async fn connect_with_password() {
        let mut client = Client::new(
            "10.10.10.2:22",
            "root".to_string(),
            AuthMethod::Password("root".to_string()),
        );
        client.connect().await.unwrap();
        assert!(client.channel.is_some());
    }

    #[tokio::test]
    async fn execute_command() {
        let mut client = Client::new(
            "10.10.10.2:22",
            "root".to_string(),
            AuthMethod::Password("root".to_string()),
        );
        client.connect().await.unwrap();
        let output = client.execute("echo test!!!").await.unwrap().output;
        println!("{:?}", output);
        assert_eq!("test!!!\n", output);
    }

    #[tokio::test]
    async fn connect_with_wrong_password() {
        let mut client = Client::new(
            "10.10.10.2:22",
            "root".to_string(),
            AuthMethod::Password("wrongpassword".to_string()),
        );
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn connect_to_wrong_port() {
        let mut client = Client::new(
            "10.10.10.2:23",
            "root".to_string(),
            AuthMethod::Password("root".to_string()),
        );
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn connect_to_wrong_host() {
        let mut client = Client::new(
            "172.16.0.6:22",
            "xxx".to_string(),
            AuthMethod::Password("xxx".to_string()),
        );
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }
}
