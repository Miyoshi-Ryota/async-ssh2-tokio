use crate::error::AsyncSsh2Error;
use russh::client::Config;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    Password(String),
}

impl AuthMethod {
    pub fn with_password(password: &str) -> Self {
        Self::Password(password.to_string())
    }
}

pub struct Client {
    addr: SocketAddr,
    username: String,
    auth: AuthMethod,
    config: Arc<russh::client::Config>,
    channel: Option<russh::Channel<russh::client::Msg>>,
}

impl Client {
    pub fn new(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
    ) -> Result<Self, AsyncSsh2Error> {
        Self::with_config(addr, username, auth, Config::default())
    }

    pub fn with_config(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
        config: Config,
    ) -> Result<Self, AsyncSsh2Error> {
        let config = Arc::new(config);
        let addr = addr
            .to_socket_addrs()
            .map_err(AsyncSsh2Error::AddressInvalid)?
            .next()
            .ok_or_else(|| {
                AsyncSsh2Error::AddressInvalid(io::Error::new(
                    io::ErrorKind::Other,
                    "No valid address was provided",
                ))
            })?;
        Ok(Self {
            addr,
            username: username.to_string(),
            auth,
            config,
            channel: None,
        })
    }

    pub async fn connect(&mut self) -> Result<(), AsyncSsh2Error> {
        let handler = Handler::new();
        let mut handle = russh::client::connect(self.config.clone(), self.addr, handler).await?;

        let auth = self.auth.clone();
        let AuthMethod::Password(password) = auth;
        if handle
            .authenticate_password(&self.username, password)
            .await?
        {
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
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Accept proper ip address");
        client.connect().await.unwrap();
        assert!(client.channel.is_some());
    }

    #[tokio::test]
    async fn execute_command() {
        let mut client = Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Accept proper ip address");
        client.connect().await.unwrap();
        let output = client.execute("echo test!!!").await.unwrap().output;
        println!("{:?}", output);
        assert_eq!("test!!!\n", output);
    }

    #[tokio::test]
    async fn connect_with_wrong_password() {
        let mut client = Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
        )
        .expect("Accept proper ip address");
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn connect_to_wrong_port() {
        let mut client = Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 23),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Accept proper ip address");
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }

    #[tokio::test]
    #[ignore = "This times out only after 20 seconds"]
    async fn connect_to_wrong_host() {
        let mut client = Client::new("172.16.0.6:22", "xxx", AuthMethod::with_password("xxx"))
            .expect("Accept proper ip address");
        let res = client.connect().await;
        println!("{:?}", res);
        assert!(res.is_err());
    }
}
