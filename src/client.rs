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

/// A ssh connection description to a remote server.
///
/// After creating a `Client` with [`new`], use [`execute`] to connect,
/// authenticate, send commands and receive results.
///
/// [`new`]: Client::new
/// [`execute`]: Client::execute
///
/// # Examples
///
/// ```no_run
/// use async_ssh2_tokio::{Client, AuthMethod};
/// #[tokio::main]
/// async fn main() -> Result<(), async_ssh2_tokio::Error> {
///     let mut client = Client::new(
///         ("10.10.10.2", 22),
///         "root",
///         AuthMethod::with_password("root"),
///     )?;
///
///     let result = client.execute("echo Hello SSH").await?;
///     assert_eq!(result.output, "Hello SSH\n");
///     assert_eq!(result.exit_status, 0);
///
///     Ok(())
/// }
pub struct Client {
    addresses: Vec<SocketAddr>,
    username: String,
    auth: AuthMethod,
    config: Arc<russh::client::Config>,
}

impl Client {
    /// Defines a ssh connection to a remote host.
    ///
    /// This does not yet establish any connection, the only error this can return
    /// is because of an illdefined `addr` argument.
    ///
    /// `addr` is an address of the remote host. Anything which implements
    /// [`ToSocketAddrs`] trait can be supplied for the address; see this trait
    /// documentation for concrete examples.
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until a connection is successful.
    /// Authentification is tried on the first successful connection and the whole
    /// process aborted if this fails.
    pub fn new(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
    ) -> Result<Self, crate::Error> {
        Self::new_with_config(addr, username, auth, Config::default())
    }

    /// Same as `new`, but with the option to specify a non default
    /// [`russh::client::Config`].
    pub fn new_with_config(
        addr: impl ToSocketAddrs,
        username: &str,
        auth: AuthMethod,
        config: Config,
    ) -> Result<Self, crate::Error> {
        let addresses: Vec<SocketAddr> = addr
            .to_socket_addrs()
            .map_err(crate::Error::AddressInvalid)?
            .collect();
        // This assertion is purely for early error reporting
        if addresses.is_empty() {
            return Err(crate::Error::AddressInvalid(io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )));
        }
        let config = Arc::new(config);
        let username = username.to_string();
        Ok(Self {
            addresses,
            username,
            auth,
            config,
        })
    }

    /// Private function to establish and authenticate a connection.
    async fn connect(&mut self) -> Result<(SocketAddr, Handle<ClientHandler>), crate::Error> {
        // This error should never be returned, as the assertion in `new` garantees
        // `self.addresses` is non-empty.
        let mut connect_res = Err(crate::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )));
        // Connection code inspired from std::net::TcpStream::connect and std::net::each_addr
        for &addr in self.addresses.iter() {
            match russh::client::connect(self.config.clone(), addr, ClientHandler).await {
                Ok(h) => {
                    connect_res = Ok((addr, h));
                    break;
                }
                Err(e) => connect_res = Err(e),
            }
        }
        let (address, mut handle) = connect_res?;

        // Authenticate
        match &self.auth {
            AuthMethod::Password(password) => {
                let is_authentificated = handle
                    .authenticate_password(&self.username, password)
                    .await?;
                if is_authentificated {
                    Ok((address, handle))
                } else {
                    Err(crate::Error::PasswordWrong)
                }
            }
        }
    }

    /// Execute a remote command by establishing and authenticating a ssh connection.
    ///
    /// Returns the stdout output and the exit code of the command, as well as
    /// the actual address the command was executed on,
    /// packaged in a [`CommandExecutedResult`] struct.
    ///
    /// Can be called multiple times, but every invocation is a new connection and thus
    /// a new shell context.
    /// Therefore `cd`, setting variables and alike have no effect on future invocations.
    pub async fn execute(&mut self, command: &str) -> Result<CommandExecutedResult, crate::Error> {
        let (address, mut handle) = self.connect().await?;
        let mut channel = handle.channel_open_session().await?;

        let mut receive_buffer = vec![];

        channel.exec(true, command).await?;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => receive_buffer.write_all(data).unwrap(),
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    let result = CommandExecutedResult {
                        actual_address: address,
                        output: String::from_utf8_lossy(&receive_buffer).to_string(),
                        exit_status,
                    };
                    return Ok(result);
                }
                _ => {}
            }
        }

        // TODO: Should we disconnect or close the session here?
        // handle.disconnect(russh::Disconnect::ByApplication, "", "");

        Err(crate::Error::CommandDidntExit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    /// The stdout output of the command.
    pub output: String,
    /// The unix exit status (`$?` in bash).
    pub exit_status: u32,
    /// The actual address of the [`ToSocketAddrs`] argument that was used for the ssh connection.
    pub actual_address: SocketAddr,
}

#[derive(Clone)]
struct ClientHandler;

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

    async fn new_test_host_client() -> Client {
        Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Address parsing failed")
    }

    #[tokio::test]
    async fn connect_with_password() {
        let mut client = new_test_host_client().await;
        // Testing private interface here.
        let (address, _handle) = client
            .connect()
            .await
            .expect("Connection/Authentification failed");

        assert_eq!(
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22").parse(),
            Ok(address),
        );
    }

    #[tokio::test]
    async fn execute_command_result() {
        let mut client = new_test_host_client().await;
        let output = client.execute("echo test!!!").await.unwrap();
        assert_eq!("test!!!\n", output.output);
        assert_eq!(0, output.exit_status);
        assert_eq!(
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22").parse(),
            Ok(output.actual_address),
        );
    }

    #[tokio::test]
    async fn unicode_output() {
        let mut client = new_test_host_client().await;
        let output = client.execute("echo To thḙ moon! 🚀").await.unwrap();
        assert_eq!("To thḙ moon! 🚀\n", output.output);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn execute_command_status() {
        let mut client = new_test_host_client().await;
        let output = client.execute("exit 42").await.unwrap();
        assert_eq!(42, output.exit_status);
    }

    #[tokio::test]
    async fn execute_multiple_commands() {
        let mut client = new_test_host_client().await;
        let output = client.execute("echo test!!!").await.unwrap().output;
        assert_eq!("test!!!\n", output);

        let output = client.execute("echo Hello World").await.unwrap().output;
        assert_eq!("Hello World\n", output);
    }

    #[tokio::test]
    async fn many_commands() {
        let mut client = new_test_host_client().await;

        // Assert that the `maxSession` limit is not a problem.
        // This time this takes is somewhere in the 30s range.
        for i in 0..50 {
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
        let mut client = new_test_host_client().await;
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
        let mut client = Client::new(
            &addresses[..],
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(env!("ASYNC_SSH2_TEST_HOST_PW")),
        )
        .expect("Address parsing failed");

        let (address, _handle) = client
            .connect()
            .await
            .expect("Connection/Authentification to second address failed");

        assert_eq!(
            concat!(env!("ASYNC_SSH2_TEST_HOST_IP"), ":22").parse(),
            Ok(address),
        );
    }

    #[tokio::test]
    async fn connect_with_wrong_password() {
        let mut client = Client::new(
            (env!("ASYNC_SSH2_TEST_HOST_IP"), 22),
            env!("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
        )
        .expect("Address parsing failed");

        let error = client
            .connect()
            .await
            .err()
            .expect("Connected with wrong password");

        assert!(matches!(error, crate::Error::PasswordWrong));
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
        .expect("Address parsing failed");

        let error = client
            .connect()
            .await
            .err()
            .expect("Connected to wrong port");

        assert!(matches!(error, crate::Error::SshError(_)));
    }

    #[tokio::test]
    #[ignore = "This times out only after 20 seconds"]
    async fn connect_to_wrong_host() {
        let mut client = Client::new("172.16.0.6:22", "xxx", AuthMethod::with_password("xxx"))
            .expect("Address parsing failed");

        let error = client
            .connect()
            .await
            .err()
            .expect("Connected to wrong port");

        assert!(matches!(error, crate::Error::SshError(_)));
    }
}
