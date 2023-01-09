use russh::client::{Config, Handle, Handler, Session};
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// An authentification token, currently only by password.
///
/// Used when creating a [`Client`] for authentification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    Password(String),
}

impl AuthMethod {
    /// Convenience method to create a [`AuthMethod`] from a string literal.
    pub fn with_password(password: &str) -> Self {
        Self::Password(password.to_string())
    }
}

/// A ssh connection to a remote server.
///
/// After creating a `Client` by [`connect`]ing to a remote host,
/// use [`execute`] to send commands and receive results through the connections.
///
/// [`connect`]: Client::connect
/// [`execute`]: Client::execute
///
/// # Examples
///
/// ```no_run
/// use async_ssh2_tokio::{Client, AuthMethod};
/// #[tokio::main]
/// async fn main() -> Result<(), async_ssh2_tokio::Error> {
///     let mut client = Client::connect(
///         ("10.10.10.2", 22),
///         "root",
///         AuthMethod::with_password("root"),
///     ).await?;
///
///     let result = client.execute("echo Hello SSH").await?;
///     assert_eq!(result.output, "Hello SSH\n");
///     assert_eq!(result.exit_status, 0);
///
///     Ok(())
/// }
pub struct Client {
    connection_handle: Handle<ClientHandler>,
    username: String,
    address: SocketAddr,
}

impl Client {
    /// Open a ssh connection to a remot host.
    ///
    /// `addr` is an address of the remote host. Anything which implements
    /// [`ToSocketAddrs`] trait can be supplied for the address; see this trait
    /// documentation for concrete examples.
    ///
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until a connection is successful.
    /// Authentification is tried on the first successful connection and the whole
    /// process aborted if this fails.
    pub async fn connect(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
    ) -> Result<Self, crate::Error> {
        Self::connect_with_config(addr, username, auth, Config::default()).await
    }

    /// Same as `connect`, but with the option to specify a non default
    /// [`russh::client::Config`].
    pub async fn connect_with_config(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
        config: Config,
    ) -> Result<Self, crate::Error> {
        let config = Arc::new(config);

        // Connection code inspired from std::net::TcpStream::connect and std::net::each_addr
        let addrs = match addr.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => return Err(crate::Error::AddressInvalid(e)),
        };
        let mut connect_res = Err(crate::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )));
        for addr in addrs {
            let handler = ClientHandler::new();
            match russh::client::connect(config.clone(), addr, handler).await {
                Ok(h) => {
                    connect_res = Ok((addr, h));
                    break;
                }
                Err(e) => connect_res = Err(e),
            }
        }
        let (address, mut handle) = connect_res?;
        let username = username.to_string();

        Self::authenticate(&mut handle, &username, auth).await?;

        Ok(Self {
            connection_handle: handle,
            username,
            address,
        })
    }

    /// This takes a handle and performs authentification with the given method.
    async fn authenticate(
        handle: &mut Handle<ClientHandler>,
        username: &String,
        auth: AuthMethod,
    ) -> Result<(), crate::Error> {
        match auth {
            AuthMethod::Password(password) => {
                let is_authentificated = handle.authenticate_password(username, password).await?;
                if is_authentificated {
                    Ok(())
                } else {
                    Err(crate::Error::PasswordWrong)
                }
            }
        }
    }

    /// Execute a remote command via the ssh connection.
    ///
    /// Returns both the stdout output and the exit code of the command,
    /// packaged in a [`CommandExecutedResult`] struct.
    ///
    /// Can be called multiple times, but every invocation is a new shell context.
    /// Thus `cd`, setting variables and alike have no effect on future invocations.
    pub async fn execute(&mut self, command: &str) -> Result<CommandExecutedResult, crate::Error> {
        let mut receive_buffer = vec![];
        let mut channel = self.connection_handle.channel_open_session().await?;
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

        Err(crate::Error::CommandDidntExit)
    }

    /// A debugging function to get the username this client is connected as.
    pub fn get_connection_username(&self) -> &String {
        &self.username
    }

    /// A debugging function to get the address this client is connected to.
    pub fn get_connection_address(&self) -> &SocketAddr {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    /// The stdout output of the command.
    pub output: String,
    /// The unix exit status (`$?` in bash).
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
struct ClientHandler;

impl ClientHandler {
    fn new() -> Self {
        Self {}
    }
}

impl Handler for ClientHandler {
    type Error = crate::Error;
    type FutureUnit = std::future::Ready<Result<(Self, Session), Self::Error>>;
    type FutureBool = std::future::Ready<Result<(Self, bool), Self::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        std::future::ready(Ok((self, b)))
    }
    fn finished(self, session: Session) -> Self::FutureUnit {
        std::future::ready(Ok((self, session)))
    }
    fn check_server_key(self, _server_public_key: &russh_keys::key::PublicKey) -> Self::FutureBool {
        self.finished_bool(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::client::*;

    async fn establish_test_host_connection() -> Client {
        Client::connect(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .await
        .expect("Connection/Authentification failed")
    }

    #[tokio::test]
    async fn connect_with_password() {
        let client = establish_test_host_connection().await;
        assert_eq!(
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            client.get_connection_username(),
        );
        assert_eq!(
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22").parse(),
            Ok(*client.get_connection_address()),
        );
    }

    #[tokio::test]
    async fn execute_command_result() {
        let mut client = establish_test_host_connection().await;
        let output = client.execute("echo test!!!").await.unwrap();
        assert_eq!("test!!!\n", output.output);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn unicode_output() {
        let mut client = establish_test_host_connection().await;
        let output = client.execute("echo To thḙ moon! 🚀").await.unwrap();
        assert_eq!("To thḙ moon! 🚀\n", output.output);
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
    async fn thousands_commands() {
        let mut client = establish_test_host_connection().await;

        for i in 0..1000 {
            let res = client
                .execute(&format!("echo {i}"))
                .await
                .expect(&format!("Execution failed in iteration {i}"));
            assert_eq!(format!("{i}\n"), res.output);
        }
    }

    #[tokio::test]
    async fn execute_multiple_context() {
        // This is maybe not expected behaviour, thus documenting this via a test is important.
        let mut client = establish_test_host_connection().await;
        let output = client
            .execute("export VARIABLE=42; echo $VARIABLE")
            .await
            .unwrap()
            .output;
        assert_eq!("42\n", output);

        let output = client.execute("echo $VARIABLE").await.unwrap().output;
        assert_eq!("\n", output);
    }

    #[tokio::test]
    async fn connect_second_address() {
        let addresses = [
            SocketAddr::from(([127, 0, 0, 1], 23)),
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22")
                .parse()
                .expect("invalid env var"),
        ];
        let client = Client::connect(
            &addresses[..],
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .await
        .expect("Resolution to second address failed");

        assert_eq!(
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22").parse(),
            Ok(*client.get_connection_address()),
        );
    }

    #[tokio::test]
    async fn connect_with_wrong_password() {
        let error = Client::connect(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
        )
        .await
        .err()
        .expect("Client connected with wrong password");

        match error {
            crate::Error::PasswordWrong => {}
            _ => panic!("Wrong error type"),
        }
    }

    #[tokio::test]
    async fn invalid_address() {
        let no_client = Client::connect(
            "this is definitely not an address",
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
        )
        .await;
        assert!(no_client.is_err());
    }

    #[tokio::test]
    async fn connect_to_wrong_port() {
        let no_client = Client::connect(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 23),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .await;
        assert!(no_client.is_err());
    }

    #[tokio::test]
    #[ignore = "This times out only after 20 seconds"]
    async fn connect_to_wrong_host() {
        let no_client =
            Client::connect("172.16.0.6:22", "xxx", AuthMethod::with_password("xxx")).await;
        assert!(no_client.is_err());
    }
}
