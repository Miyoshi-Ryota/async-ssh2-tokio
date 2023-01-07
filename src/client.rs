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

    connection_handle: Option<russh::client::Handle<Handler>>,
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
            connection_handle: None,
        })
    }

    pub async fn connect(&mut self) -> Result<(), AsyncSsh2Error> {
        // Connect
        let handler = Handler::new();
        let mut handle = russh::client::connect(self.config.clone(), self.addr, handler).await?;

        // Authenticate
        let AuthMethod::Password(password) = self.auth.clone();
        let is_authentificated = handle
            .authenticate_password(&self.username, password)
            .await?;
        if is_authentificated {
            self.connection_handle = Some(handle);
            Ok(())
        } else {
            Err(AsyncSsh2Error::PasswordWrong)
        }
    }

    pub async fn execute(
        &mut self,
        command: &str,
    ) -> Result<CommandExecutedResult, AsyncSsh2Error> {
        if let Some(handle) = self.connection_handle.as_mut() {
            let mut receive_buffer = vec![];
            let mut channel = handle.channel_open_session().await?;
            channel.exec(true, command).await?;

            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { ref data } => receive_buffer.write_all(data).unwrap(),
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        let result = CommandExecutedResult::new(
                            String::from_utf8_lossy(&receive_buffer).to_string(),
                            exit_status,
                        );
                        return Ok(result);
                    }
                    _ => {}
                }
            }
        }

        Err(AsyncSsh2Error::NotConnected)
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
    async fn establish_test_host_connection() -> Client {
        let mut client = Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Accept proper ip address");

        client
            .connect()
            .await
            .expect("Connection/Authentification failed");

        client
    }

    use crate::client::*;
    #[tokio::test]
    async fn connect_with_password() {
        let client = establish_test_host_connection().await;
        assert!(client.connection_handle.is_some());
    }

    #[tokio::test]
    async fn execute_command_result() {
        let mut client = establish_test_host_connection().await;
        let output = client.execute("echo test!!!").await.unwrap();
        assert_eq!("test!!!\n", output.output);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn execute_command_status() {
        let mut client = establish_test_host_connection().await;
        let output = client.execute("exit 42").await.unwrap();
        assert_eq!(42, output.exit_status);
    }

    #[tokio::test]
    async fn execute_multiple_commands() {
        let mut client = establish_test_host_connection().await;
        let output = client.execute("echo test!!!").await.unwrap().output;
        assert_eq!("test!!!\n", output);

        let output = client.execute("echo Hello World").await.unwrap().output;
        assert_eq!("Hello World\n", output);
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
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn invalid_address() {
        let no_client = Client::new(
            "this is definitely not an address",
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
        );
        assert!(no_client.is_err());
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
        assert!(res.is_err());
    }

    #[tokio::test]
    #[ignore = "This times out only after 20 seconds"]
    async fn connect_to_wrong_host() {
        let mut client = Client::new("172.16.0.6:22", "xxx", AuthMethod::with_password("xxx"))
            .expect("Accept proper ip address");
        let res = client.connect().await;
        assert!(res.is_err());
    }
}
