use russh::client::KeyboardInteractiveAuthResponse;
use russh::{
    Channel,
    client::{Config, Handle, Handler, Msg},
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::{fmt::Debug, path::Path};
use std::{io, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::ToSocketAddrsWithHostname;

/// An authentification token.
///
/// Used when creating a [`Client`] for authentification.
/// Supports password, private key, public key, SSH agent, and keyboard interactive authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        /// entire contents of private key file
        key_data: String,
        key_pass: Option<String>,
    },
    PrivateKeyFile {
        key_file_path: PathBuf,
        key_pass: Option<String>,
    },
    #[cfg(not(target_os = "windows"))]
    PublicKeyFile {
        key_file_path: PathBuf,
    },
    #[cfg(not(target_os = "windows"))]
    Agent,
    KeyboardInteractive(AuthKeyboardInteractive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SteamingOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ExitStatus(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PromptResponse {
    exact: bool,
    prompt: String,
    response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct AuthKeyboardInteractive {
    /// Hnts to the server the preferred methods to be used for authentication.
    submethods: Option<String>,
    responses: Vec<PromptResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerCheckMethod {
    NoCheck,
    /// base64 encoded key without the type prefix or hostname suffix (type is already encoded)
    PublicKey(String),
    PublicKeyFile(String),
    DefaultKnownHostsFile,
    KnownHostsFile(String),
}

impl AuthMethod {
    /// Convenience method to create a [`AuthMethod`] from a string literal.
    pub fn with_password(password: &str) -> Self {
        Self::Password(password.to_string())
    }

    pub fn with_key(key: &str, passphrase: Option<&str>) -> Self {
        Self::PrivateKey {
            key_data: key.to_string(),
            key_pass: passphrase.map(str::to_string),
        }
    }

    pub fn with_key_file<T: AsRef<Path>>(key_file_path: T, passphrase: Option<&str>) -> Self {
        Self::PrivateKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
            key_pass: passphrase.map(str::to_string),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn with_public_key_file<T: AsRef<Path>>(key_file_path: T) -> Self {
        Self::PublicKeyFile {
            key_file_path: key_file_path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new SSH agent authentication method.
    ///
    /// This will attempt to authenticate using all identities available in the SSH agent.
    /// The SSH agent must be running and the SSH_AUTH_SOCK environment variable must be set.
    ///
    /// # Example
    /// ```no_run
    /// use async_ssh2_tokio::client::AuthMethod;
    ///
    /// let auth = AuthMethod::with_agent();
    /// ```
    ///
    /// # Platform Support
    /// This method is only available on Unix-like systems (Linux, macOS, etc.).
    /// It is not available on Windows.
    #[cfg(not(target_os = "windows"))]
    pub fn with_agent() -> Self {
        Self::Agent
    }

    pub const fn with_keyboard_interactive(auth: AuthKeyboardInteractive) -> Self {
        Self::KeyboardInteractive(auth)
    }
}

impl AuthKeyboardInteractive {
    pub fn new() -> Self {
        Default::default()
    }

    /// Hnts to the server the preferred methods to be used for authentication.
    pub fn with_submethods(mut self, submethods: impl Into<String>) -> Self {
        self.submethods = Some(submethods.into());
        self
    }

    /// Adds a response to the list of responses for a given prompt.
    ///
    /// The comparison for the prompt is done using a "contains".
    pub fn with_response(mut self, prompt: impl Into<String>, response: impl Into<String>) -> Self {
        self.responses.push(PromptResponse {
            exact: false,
            prompt: prompt.into(),
            response: response.into(),
        });

        self
    }

    /// Adds a response to the list of responses for a given exact prompt.
    pub fn with_response_exact(
        mut self,
        prompt: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        self.responses.push(PromptResponse {
            exact: true,
            prompt: prompt.into(),
            response: response.into(),
        });

        self
    }
}

impl PromptResponse {
    fn matches(&self, received_prompt: &str) -> bool {
        if self.exact {
            self.prompt.eq(received_prompt)
        } else {
            received_prompt.contains(&self.prompt)
        }
    }
}

impl From<AuthKeyboardInteractive> for AuthMethod {
    fn from(value: AuthKeyboardInteractive) -> Self {
        Self::with_keyboard_interactive(value)
    }
}

impl ServerCheckMethod {
    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key(key: &str) -> Self {
        Self::PublicKey(key.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_public_key_file(key_file_name: &str) -> Self {
        Self::PublicKeyFile(key_file_name.to_string())
    }

    /// Convenience method to create a [`ServerCheckMethod`] from a string literal.
    pub fn with_known_hosts_file(known_hosts_file: &str) -> Self {
        Self::KnownHostsFile(known_hosts_file.to_string())
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
/// use async_ssh2_tokio::{Client, AuthMethod, ServerCheckMethod};
/// #[tokio::main]
/// async fn main() -> Result<(), async_ssh2_tokio::Error> {
///     let mut client = Client::connect(
///         ("10.10.10.2", 22),
///         "root",
///         AuthMethod::with_password("root"),
///         ServerCheckMethod::NoCheck,
///     ).await?;
///
///     let result = client.execute("echo Hello SSH").await?;
///     assert_eq!(result.stdout, "Hello SSH\n");
///     assert_eq!(result.exit_status, 0);
///
///     Ok(())
/// }
#[derive(Clone)]
pub struct Client {
    connection_handle: Arc<Handle<ClientHandler>>,
    username: String,
    address: SocketAddr,
}

impl Client {
    /// Open a ssh connection to a remote host.
    ///
    /// `addr` is an address of the remote host. Anything which implements
    /// [`ToSocketAddrsWithHostname`] trait can be supplied for the address;
    /// ToSocketAddrsWithHostname reimplements all of [`ToSocketAddrs`];
    /// see this trait's documentation for concrete examples.
    ///
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until a connection is successful.
    /// Authentification is tried on the first successful connection and the whole
    /// process aborted if this fails.
    pub async fn connect(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
    ) -> Result<Self, crate::Error> {
        Self::connect_with_config(addr, username, auth, server_check, Config::default()).await
    }

    /// Same as `connect`, but with the option to specify a non default
    /// [`russh::client::Config`].
    pub async fn connect_with_config(
        addr: impl ToSocketAddrsWithHostname,
        username: &str,
        auth: AuthMethod,
        server_check: ServerCheckMethod,
        config: Config,
    ) -> Result<Self, crate::Error> {
        let config = Arc::new(config);

        // Connection code inspired from std::net::TcpStream::connect and std::net::each_addr
        let socket_addrs = addr
            .to_socket_addrs()
            .map_err(crate::Error::AddressInvalid)?;
        let mut connect_res = Err(crate::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )));
        for socket_addr in socket_addrs {
            let handler = ClientHandler {
                hostname: addr.hostname(),
                host: socket_addr,
                server_check: server_check.clone(),
            };
            match russh::client::connect(config.clone(), socket_addr, handler).await {
                Ok(h) => {
                    connect_res = Ok((socket_addr, h));
                    break;
                }
                Err(e) => connect_res = Err(e),
            }
        }
        let (address, mut handle) = connect_res?;
        let username = username.to_string();

        Self::authenticate(&mut handle, &username, auth).await?;

        Ok(Self {
            connection_handle: Arc::new(handle),
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
                if !is_authentificated.success() {
                    return Err(crate::Error::PasswordWrong);
                }
            }
            AuthMethod::PrivateKey { key_data, key_pass } => {
                let cprivk = russh::keys::decode_secret_key(key_data.as_str(), key_pass.as_deref())
                    .map_err(crate::Error::KeyInvalid)?;
                let is_authentificated = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(cprivk),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(crate::Error::KeyAuthFailed);
                }
            }
            AuthMethod::PrivateKeyFile {
                key_file_path,
                key_pass,
            } => {
                let cprivk = russh::keys::load_secret_key(key_file_path, key_pass.as_deref())
                    .map_err(crate::Error::KeyInvalid)?;
                let is_authentificated = handle
                    .authenticate_publickey(
                        username,
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(cprivk),
                            handle.best_supported_rsa_hash().await?.flatten(),
                        ),
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(crate::Error::KeyAuthFailed);
                }
            }
            #[cfg(not(target_os = "windows"))]
            AuthMethod::PublicKeyFile { key_file_path } => {
                let cpubk = russh::keys::load_public_key(key_file_path)
                    .map_err(crate::Error::KeyInvalid)?;
                let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                    .await
                    .unwrap();
                let mut auth_identity: Option<russh::keys::PublicKey> = None;
                for identity in agent
                    .request_identities()
                    .await
                    .map_err(crate::Error::KeyInvalid)?
                {
                    if identity == cpubk {
                        auth_identity = Some(identity.clone());
                        break;
                    }
                }

                if auth_identity.is_none() {
                    return Err(crate::Error::KeyAuthFailed);
                }

                let is_authentificated = handle
                    .authenticate_publickey_with(
                        username,
                        cpubk,
                        handle.best_supported_rsa_hash().await?.flatten(),
                        &mut agent,
                    )
                    .await?;
                if !is_authentificated.success() {
                    return Err(crate::Error::KeyAuthFailed);
                }
            }
            #[cfg(not(target_os = "windows"))]
            AuthMethod::Agent => {
                let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|_| crate::Error::AgentConnectionFailed)?;

                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|_| crate::Error::AgentRequestIdentitiesFailed)?;

                if identities.is_empty() {
                    return Err(crate::Error::AgentNoIdentities);
                }

                let mut auth_success = false;
                for identity in identities {
                    let result = handle
                        .authenticate_publickey_with(
                            username,
                            identity.clone(),
                            handle.best_supported_rsa_hash().await?.flatten(),
                            &mut agent,
                        )
                        .await;

                    if let Ok(auth_result) = result
                        && auth_result.success()
                    {
                        auth_success = true;
                        break;
                    }
                }

                if !auth_success {
                    return Err(crate::Error::AgentAuthenticationFailed);
                }
            }
            AuthMethod::KeyboardInteractive(mut kbd) => {
                let mut res = handle
                    .authenticate_keyboard_interactive_start(username, kbd.submethods)
                    .await?;
                loop {
                    let prompts = match res {
                        KeyboardInteractiveAuthResponse::Success => break,
                        KeyboardInteractiveAuthResponse::Failure { .. } => {
                            return Err(crate::Error::KeyboardInteractiveAuthFailed);
                        }
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => prompts,
                    };

                    let mut responses = vec![];
                    for prompt in prompts {
                        let Some(pos) = kbd
                            .responses
                            .iter()
                            .position(|pr| pr.matches(&prompt.prompt))
                        else {
                            return Err(crate::Error::KeyboardInteractiveNoResponseForPrompt(
                                prompt.prompt,
                            ));
                        };
                        let pr = kbd.responses.remove(pos);
                        responses.push(pr.response);
                    }

                    res = handle
                        .authenticate_keyboard_interactive_respond(responses)
                        .await?;
                }
            }
        };
        Ok(())
    }

    pub async fn get_channel(&self) -> Result<Channel<Msg>, crate::Error> {
        self.connection_handle
            .channel_open_session()
            .await
            .map_err(crate::Error::SshError)
    }

    /// Open a TCP/IP forwarding channel.
    ///
    /// This opens a `direct-tcpip` channel to the given target.
    pub async fn open_direct_tcpip_channel<
        T: ToSocketAddrsWithHostname,
        S: Into<Option<SocketAddr>>,
    >(
        &self,
        target: T,
        src: S,
    ) -> Result<Channel<Msg>, crate::Error> {
        let targets = target
            .to_socket_addrs()
            .map_err(crate::Error::AddressInvalid)?;
        let src = src
            .into()
            .map(|src| (src.ip().to_string(), src.port().into()))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 22));

        let mut connect_err = crate::Error::AddressInvalid(io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        ));
        for target in targets {
            match self
                .connection_handle
                .channel_open_direct_tcpip(
                    target.ip().to_string(),
                    target.port().into(),
                    src.0.clone(),
                    src.1,
                )
                .await
            {
                Ok(channel) => return Ok(channel),
                Err(err) => connect_err = crate::Error::SshError(err),
            }
        }

        Err(connect_err)
    }

    /// Upload a file with sftp to the remote server.
    ///
    /// `src_file_path` is the path to the file on the local machine.
    /// `dest_file_path` is the path to the file on the remote machine.
    /// 'timeout_seconds' is the timeout, in seconds, for the operation, passed on to the sftp session.
    /// If not specified it will default to the underlying value in the sftp code, which as of this writing is 10 seconds.
    /// 'buffer_size_in_bytes' is the value this function will buffer the file through.  it defaults to 4KB.
    /// 'show_progress' if true, logs will be emitted every 5% of the file upload, measured in bytes
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn upload_file<T, U>(
        &self,
        src_file_path: T,
        //fa993: This cannot be AsRef<Path> because of underlying lib constraints as described here
        //https://github.com/AspectUnk/russh-sftp/issues/7#issuecomment-1738355245
        dest_file_path: U,
        timeout_seconds: Option<u64>,
        buffer_size_in_bytes: Option<usize>,
        show_progress: bool,
    ) -> Result<(), crate::Error>
    where
        T: AsRef<Path> + std::fmt::Display,
        U: Into<String>,
    {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new_opts(channel.into_stream(), timeout_seconds).await?;

        let file_size = tokio::fs::metadata(&src_file_path).await?.len();
        // read file contents locally
        let local_file = tokio::fs::File::open(&src_file_path)
            .await
            .map_err(crate::Error::IoError)?;
        let mut local_file_buffered = tokio::io::BufReader::new(local_file);

        let dest_file_path = dest_file_path.into();
        let mut remote_file = sftp
            .open_with_flags(
                dest_file_path.clone(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await?;

        let buffer_size_in_bytes = buffer_size_in_bytes.unwrap_or(4096);
        let mut buffer = vec![0; buffer_size_in_bytes];

        let mut total_bytes_copied = 0;
        let mut next_progress_marker = 5.0;

        let start_time = Instant::now();
        if show_progress {
            log::info!(
                "Starting file upload from {src_file_path} to {dest_file_path}, total bytes to be transferred: {}",
                file_size
            );
        }
        loop {
            let n = local_file_buffered.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            remote_file
                .write_all(&buffer[..n])
                .await
                .map_err(crate::Error::IoError)?;
            if show_progress {
                total_bytes_copied += n as u64;
                let progress = (total_bytes_copied as f64 / file_size as f64) * 100.0;
                if progress >= next_progress_marker {
                    log::info!(
                        "Progress of upload from {src_file_path} to {dest_file_path}: {:.0}% in elapsed time: {}s",
                        next_progress_marker,
                        start_time.elapsed().as_secs_f64()
                    );
                    next_progress_marker += 5.0;
                }
            }
        }

        if show_progress {
            log::info!(
                "file upload comprising {file_size} bytes from {src_file_path} to {dest_file_path} completed successfully in {}s",
                start_time.elapsed().as_secs_f64()
            );
        }
        remote_file
            .shutdown()
            .await
            .map_err(crate::Error::IoError)?;

        Ok(())
    }

    /// Download a file from the remote server using sftp.
    ///
    /// `remote_file_path` is the path to the file on the remote machine.
    /// `local_file_path` is the path to the file on the local machine.
    /// Some sshd_config does not enable sftp by default, so make sure it is enabled.
    /// A config line like a `Subsystem sftp internal-sftp` or
    /// `Subsystem sftp /usr/lib/openssh/sftp-server` is needed in the sshd_config in remote machine.
    pub async fn download_file<T: AsRef<Path>, U: Into<String>>(
        &self,
        remote_file_path: U,
        local_file_path: T,
    ) -> Result<(), crate::Error> {
        // start sftp session
        let channel = self.get_channel().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        // open remote file for reading
        let mut remote_file = sftp
            .open_with_flags(remote_file_path, OpenFlags::READ)
            .await?;

        // read remote file contents
        let mut contents = Vec::new();
        remote_file.read_to_end(contents.as_mut()).await?;

        // write contents to local file
        let mut local_file = tokio::fs::File::create(local_file_path.as_ref())
            .await
            .map_err(crate::Error::IoError)?;

        local_file
            .write_all(&contents)
            .await
            .map_err(crate::Error::IoError)?;
        local_file.flush().await.map_err(crate::Error::IoError)?;

        Ok(())
    }

    /// Execute a remote command via the ssh connection.
    ///
    /// Returns stdout, stderr and the exit code of the command,
    /// packaged in a [`CommandExecutedResult`] struct.
    /// If you need the stderr output interleaved within stdout, you should postfix the command with a redirection,
    /// e.g. `echo foo 2>&1`.
    /// If you dont want any output at all, use something like `echo foo >/dev/null 2>&1`.
    ///
    /// Make sure your commands don't read from stdin and exit after bounded time.
    ///
    /// Can be called multiple times, but every invocation is a new shell context.
    /// Thus `cd`, setting variables and alike have no effect on future invocations.
    pub async fn execute(&self, command: &str) -> Result<CommandExecutedResult, crate::Error> {
        let mut stdout_buffer = vec![];
        let mut stderr_buffer = vec![];
        let mut channel = self.connection_handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut result: Option<u32> = None;

        // While the channel has messages...
        while let Some(msg) = channel.wait().await {
            //dbg!(&msg);
            match msg {
                // If we get data, add it to the buffer
                russh::ChannelMsg::Data { ref data } => {
                    stdout_buffer.write_all(data).await.unwrap()
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr_buffer.write_all(data).await.unwrap()
                    }
                }

                // If we get an exit code report, store it, but crucially don't
                // assume this message means end of communications. The data might
                // not be finished yet!
                russh::ChannelMsg::ExitStatus { exit_status } => result = Some(exit_status),

                // We SHOULD get this EOF messagge, but 4254 sec 5.3 also permits
                // the channel to close without it being sent. And sometimes this
                // message can even precede the Data message, so don't handle it
                // russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        // If we received an exit code, report it back
        if let Some(result) = result {
            Ok(CommandExecutedResult {
                stdout: String::from_utf8_lossy(&stdout_buffer).to_string(),
                stderr: String::from_utf8_lossy(&stderr_buffer).to_string(),
                exit_status: result,
            })

        // Otherwise, report an error
        } else {
            Err(crate::Error::CommandDidntExit)
        }
    }

    /// Execute a remote command via the ssh connection.
    ///
    /// Command output is stream to the provided channel. Returns the exit code.
    /// The channel sends `SteamingOutput` enum variants to distinguish stdout,
    /// stderr and exit code so message arrive interleaved and in the order
    /// they are received. See `execute` for more details.
    ///
    #[deprecated(
        since = "0.11.0",
        note = "Use execute_io with channels directly for more flexibility.\n\
              This method will be removed or introduced breaking changes in future versions.\n\
              At minimum, SteamingOutput will be renamed to StreamingOutput"
    )]
    pub async fn execute_streaming(
        &self,
        command: &str,
        ch: tokio::sync::mpsc::Sender<SteamingOutput>,
    ) -> Result<u32, crate::Error> {
        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel(1);
        let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

        let exec_future = self.execute_io(command, stdout_tx, Some(stderr_tx), None, false, None);
        tokio::pin!(exec_future);
        let result = loop {
            tokio::select! {
                result = &mut exec_future => break result,
                Some(stdout) = stdout_rx.recv() => {
                    ch.send(SteamingOutput::Stdout(stdout)).await.unwrap();
                },
                Some(stderr) = stderr_rx.recv() => {
                    ch.send(SteamingOutput::Stderr(stderr)).await.unwrap();
                },
            };
        }?;
        // see if any output is left in the channels
        if let Some(stdout) = stdout_rx.recv().await {
            ch.send(SteamingOutput::Stdout(stdout)).await.unwrap();
        }
        if let Some(stderr) = stderr_rx.recv().await {
            ch.send(SteamingOutput::Stderr(stderr)).await.unwrap();
        }
        ch.send(SteamingOutput::ExitStatus(result)).await.unwrap();
        Ok(result)
    }

    /// Execute a remote command via the ssh connection and perform i/o via channels.
    ///
    /// `execute_io` does the same as `execute`, but ties stdin and stdout/stderr to channels.
    /// Giving a stdin channel is optional. If there is only a stdout channel, stderr will be
    /// sent to the stdout channel. Sending an empty string to the stdin channel will send an
    /// EOF to the remote side.
    /// If `request_pty` is true, a pseudo terminal is requested for the session. This is
    /// sometime necessary for example to enter a password, which is not request via stdin
    /// but directly from the terminal. NOTE: A pty has no stderr, so stderr output is
    /// sent to the stdout channel.
    /// The exit code of the command is returned as a result. If the remote ssh server
    /// does not report an exit code, a default exit code can be passed, otherwise an error
    /// is returned.
    ///
    /// Example:
    ///
    /// ```no_run
    /// use async_ssh2_tokio::{Client, AuthMethod, ServerCheckMethod};
    /// use tokio::sync::mpsc;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), async_ssh2_tokio::Error> {
    ///     let mut client = Client::connect(
    ///         ("10.10.10.2", 22),
    ///         "root",
    ///         AuthMethod::with_password("root"),
    ///         ServerCheckMethod::NoCheck,
    ///     ).await?;
    ///     let mut result_stdout = vec![];
    ///     let mut result_stderr = vec![];
    ///
    ///     let (stdout_tx, mut stdout_rx) = mpsc::channel(10);
    ///     let (stderr_tx, mut stderr_rx) = mpsc::channel(10);
    ///     let cmd = "date";
    ///     let exec_future = client.execute_io(&cmd, stdout_tx, Some(stderr_tx), None, false, None);
    ///     tokio::pin!(exec_future);
    ///     let result = loop {
    ///         tokio::select! {
    ///             result = &mut exec_future => break result,
    ///             Some(stdout) = stdout_rx.recv() => {
    ///                 println!("ssh stdout: {}", String::from_utf8_lossy(&stdout));
    ///                 result_stdout.push(stdout);
    ///             },
    ///             Some(stderr) = stderr_rx.recv() => {
    ///                 println!("ssh stderr: {}", String::from_utf8_lossy(&stderr));
    ///                 result_stderr.push(stderr);
    ///             },
    ///         };
    ///     }?;
    ///
    ///     // see if any output is left in the channels
    ///     if let Some(stdout) = stdout_rx.recv().await {
    ///         println!("ssh stdout: {}", String::from_utf8_lossy(&stdout));
    ///         result_stdout.push(stdout);
    ///     }
    ///     if let Some(stderr) = stderr_rx.recv().await {
    ///         println!("ssh stderr: {}", String::from_utf8_lossy(&stderr));
    ///         result_stderr.push(stderr);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub async fn execute_io(
        &self,
        command: &str,
        stdout_channel: mpsc::Sender<Vec<u8>>,
        stderr_channel: Option<mpsc::Sender<Vec<u8>>>,
        mut stdin_channel: Option<mpsc::Receiver<Vec<u8>>>,
        request_pty: bool,
        default_exit_code: Option<u32>,
    ) -> Result<u32, crate::Error> {
        let mut channel = self.connection_handle.channel_open_session().await?;

        let mut result: Option<u32> = None;
        if request_pty {
            channel
                .request_pty(false, "xterm", 80_u32, 24_u32, 0, 0, &[])
                .await?;
        }

        channel.exec(true, command).await?;

        // While the channel has messages...
        loop {
            let recv_stdin = async {
                if let Some(ch) = stdin_channel.as_mut() {
                    Some(ch.recv().await)
                } else {
                    None
                }
            };
            tokio::select! {
                Some(input) = recv_stdin => {
                    if let Some(input) = input {
                        if input.is_empty() {
                            channel.eof().await? ;
                        } else {
                            channel.data(&input as &[u8]).await?;
                        }
                    }
                },
                msg = channel.wait() => {
                    //dbg!(&msg);
                    match msg {
                        // If we get data, add it to the buffer
                        Some(russh::ChannelMsg::Data { ref data }) => {
                            //dbg!("sending stdout");
                            stdout_channel
                                .send(data.to_vec())
                                .await
                                .map_err(crate::Error::ChannelSendError)?;
                        }
                        Some (russh::ChannelMsg::ExtendedData { ref data, ext }) => {
                            if ext == 1 {
                                if let Some(stderr_channel) = &stderr_channel {
                                    //dbg!("sending stderr");
                                    stderr_channel
                                        .send(data.to_vec())
                                        .await
                                        .map_err(crate::Error::ChannelSendError)?;
                                } else {
                                    //dbg!("sending stderr to stdout");
                                    stdout_channel
                                        .send(data.to_vec())
                                        .await
                                        .map_err(crate::Error::ChannelSendError)?;
                                }
                            }
                        }

                        // If we get an exit code report, store it, but crucially don't
                        // assume this message means end of communications. The data might
                        // not be finished yet!
                        Some (russh::ChannelMsg::ExitStatus { exit_status }) => result = Some(exit_status),

                        // We SHOULD get this EOF messagge, but 4254 sec 5.3 also permits
                        // the channel to close without it being sent. And sometimes this
                        // message can even precede the Data message, so don't handle it
                        // russh::ChannelMsg::Eof => break,
                        Some (_) => {},
                        None => break,
                    }
                }
            }
        }

        // If we received an exit code, report it back
        if let Some(result) = result {
            Ok(result)
        // If we have an default exit code, report it back
        } else if let Some(default_exit_code) = default_exit_code {
            Ok(default_exit_code)
        // Otherwise, report an error
        } else {
            Err(crate::Error::CommandDidntExit)
        }
    }

    /// A debugging function to get the username this client is connected as.
    pub fn get_connection_username(&self) -> &String {
        &self.username
    }

    /// A debugging function to get the address this client is connected to.
    pub fn get_connection_address(&self) -> &SocketAddr {
        &self.address
    }

    pub async fn disconnect(&self) -> Result<(), crate::Error> {
        self.connection_handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(crate::Error::SshError)
    }

    pub fn is_closed(&self) -> bool {
        self.connection_handle.is_closed()
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("username", &self.username)
            .field("address", &self.address)
            .field("connection_handle", &"Handle<ClientHandler>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandExecutedResult {
    /// The stdout output of the command.
    pub stdout: String,
    /// The stderr output of the command.
    pub stderr: String,
    /// The unix exit status (`$?` in bash).
    pub exit_status: u32,
}

#[derive(Debug, Clone)]
struct ClientHandler {
    hostname: String,
    host: SocketAddr,
    server_check: ServerCheckMethod,
}

impl Handler for ClientHandler {
    type Error = crate::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.server_check {
            ServerCheckMethod::NoCheck => Ok(true),
            ServerCheckMethod::PublicKey(key) => {
                let pk = russh::keys::parse_public_key_base64(key)
                    .map_err(|_| crate::Error::ServerCheckFailed)?;

                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::PublicKeyFile(key_file_name) => {
                let pk = russh::keys::load_public_key(key_file_name)
                    .map_err(|_| crate::Error::ServerCheckFailed)?;

                Ok(pk == *server_public_key)
            }
            ServerCheckMethod::KnownHostsFile(known_hosts_path) => {
                let result = russh::keys::check_known_hosts_path(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                    known_hosts_path,
                )
                .map_err(|_| crate::Error::ServerCheckFailed)?;

                Ok(result)
            }
            ServerCheckMethod::DefaultKnownHostsFile => {
                let result = russh::keys::check_known_hosts(
                    &self.hostname,
                    self.host.port(),
                    server_public_key,
                )
                .map_err(|_| crate::Error::ServerCheckFailed)?;

                Ok(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated, clippy::useless_vec)]

    use crate::client::*;
    use core::time;
    use dotenv::dotenv;
    use std::path::Path;
    use std::sync::Once;
    use tokio::io::AsyncReadExt;
    static INIT: Once = Once::new();

    fn initialize() {
        // Perform your initialization tasks here
        println!("Running initialization code before tests...");
        // Example: load .env file if we are using non-docker environment
        if is_running_in_docker() {
            println!("Running inside Docker.");
        } else {
            println!("Not running inside Docker. Load env from file");
            dotenv().ok();
        }
    }
    fn is_running_in_docker() -> bool {
        Path::new("/.dockerenv").exists() || check_cgroup()
    }

    fn check_cgroup() -> bool {
        match std::fs::read_to_string("/proc/1/cgroup") {
            Ok(contents) => contents.contains("docker"),
            Err(_) => false,
        }
    }

    fn env(name: &str) -> String {
        INIT.call_once(|| {
            initialize();
        });
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "Failed to get env var needed for test, make sure to set the following env var: {name}",
            )
        })
    }

    fn test_address() -> SocketAddr {
        format!(
            "{}:{}",
            env("ASYNC_SSH2_TEST_HOST_IP"),
            env("ASYNC_SSH2_TEST_HOST_PORT")
        )
        .parse()
        .unwrap()
    }

    fn test_hostname() -> impl ToSocketAddrsWithHostname {
        (
            env("ASYNC_SSH2_TEST_HOST_NAME"),
            env("ASYNC_SSH2_TEST_HOST_PORT").parse().unwrap(),
        )
    }

    async fn establish_test_host_connection() -> Client {
        Client::connect(
            (
                env("ASYNC_SSH2_TEST_HOST_IP"),
                env("ASYNC_SSH2_TEST_HOST_PORT").parse().unwrap(),
            ),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::NoCheck,
        )
        .await
        .expect("Connection/Authentification failed")
    }

    #[tokio::test]
    async fn connect_with_password() {
        let client = establish_test_host_connection().await;
        assert_eq!(
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            client.get_connection_username(),
        );
        assert_eq!(test_address(), *client.get_connection_address(),);
    }

    #[tokio::test]
    async fn execute_command_result() {
        let client = establish_test_host_connection().await;
        let output = client.execute("echo test!!!").await.unwrap();
        assert_eq!("test!!!\n", output.stdout);
        assert_eq!("", output.stderr);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn execute_streaming_command_result() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let client = establish_test_host_connection().await;
        let result = client.execute_streaming("echo test!!!", tx).await.unwrap();
        let mut output = Vec::new();
        while let Some(msg) = rx.recv().await {
            output.push(msg);
        }
        assert_eq!(0, result);
        assert_eq!(
            &[
                SteamingOutput::Stdout(b"test!!!\n".to_vec()),
                SteamingOutput::ExitStatus(0),
            ],
            output.as_slice(),
        );
    }

    #[tokio::test]
    async fn execute_command_result_stderr() {
        let client = establish_test_host_connection().await;
        let output = client.execute("echo test!!! 1>&2").await.unwrap();
        assert_eq!("", output.stdout);
        assert_eq!("test!!!\n", output.stderr);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn execute_streaming_command_result_stderr() {
        let client = establish_test_host_connection().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let result = client
            .execute_streaming("echo test!!! 1>&2", tx)
            .await
            .unwrap();
        let mut output = Vec::new();
        while let Some(msg) = rx.recv().await {
            output.push(msg);
        }
        assert_eq!(0, result);
        assert_eq!(
            &[
                SteamingOutput::Stderr(b"test!!!\n".to_vec()),
                SteamingOutput::ExitStatus(0),
            ],
            output.as_slice()
        );
    }

    #[tokio::test]
    async fn unicode_output() {
        let client = establish_test_host_connection().await;
        let output = client.execute("echo To thḙ moon! 🚀").await.unwrap();
        assert_eq!("To thḙ moon! 🚀\n", output.stdout);
        assert_eq!(0, output.exit_status);
    }

    #[tokio::test]
    async fn execute_command_status() {
        let client = establish_test_host_connection().await;
        let output = client.execute("exit 42").await.unwrap();
        assert_eq!(42, output.exit_status);
    }

    #[tokio::test]
    async fn execute_streaming_command_status() {
        let client = establish_test_host_connection().await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let result = client.execute_streaming("exit 42", tx).await.unwrap();
        let mut output = Vec::new();
        while let Some(msg) = rx.recv().await {
            output.push(msg);
        }
        assert_eq!(42, result);
        assert_eq!(&[SteamingOutput::ExitStatus(42),], output.as_slice());
    }

    #[tokio::test]
    async fn execute_io_command() {
        let client = establish_test_host_connection().await;
        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel(10);
        let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel(10);
        let cmd = "echo out1; echo err1 1>&2; echo out2; echo err2 1>&2; exit 7";
        let exec_future = client.execute_io(cmd, stdout_tx, Some(stderr_tx), None, false, None);
        tokio::pin!(exec_future);
        let mut result: Option<u32> = None;
        let mut stdout_output = vec![];
        let mut stderr_output = vec![];
        loop {
            tokio::select! {
                result_inner = &mut exec_future => {
                    result = Some(result_inner.unwrap());
                },
                Some(stdout) = stdout_rx.recv() => {
                    stdout_output.push(stdout);
                },
                Some(stderr) = stderr_rx.recv() => {
                    stderr_output.push(stderr);
                },
            };
            if result.is_some() {
                break;
            }
        }
        assert_eq!(Some(7), result);
        assert_eq!(
            vec![b"out1\n".to_vec(), b"out2\n".to_vec()].concat(),
            stdout_output.concat()
        );
        assert_eq!(
            vec![b"err1\n".to_vec(), b"err2\n".to_vec()].concat(),
            stderr_output.concat()
        );
    }

    #[tokio::test]
    async fn execute_multiple_commands() {
        let client = establish_test_host_connection().await;
        let output = client.execute("echo test!!!").await.unwrap().stdout;
        assert_eq!("test!!!\n", output);

        let output = client.execute("echo Hello World").await.unwrap().stdout;
        assert_eq!("Hello World\n", output);
    }

    #[tokio::test]
    async fn direct_tcpip_channel() {
        let client = establish_test_host_connection().await;
        let channel = client
            .open_direct_tcpip_channel(
                format!(
                    "{}:{}",
                    env("ASYNC_SSH2_TEST_HTTP_SERVER_IP"),
                    env("ASYNC_SSH2_TEST_HTTP_SERVER_PORT"),
                ),
                None,
            )
            .await
            .unwrap();

        let mut stream = channel.into_stream();
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        let body = response.split_once("\r\n\r\n").unwrap().1;
        assert_eq!("Hello", body);
    }

    #[tokio::test]
    async fn stderr_redirection() {
        let client = establish_test_host_connection().await;

        let output = client.execute("echo foo >/dev/null").await.unwrap();
        assert_eq!("", output.stdout);

        let output = client.execute("echo foo >>/dev/stderr").await.unwrap();
        assert_eq!("", output.stdout);

        let output = client.execute("2>&1 echo foo >>/dev/stderr").await.unwrap();
        assert_eq!("foo\n", output.stdout);
    }

    #[tokio::test]
    async fn sequential_commands() {
        let client = establish_test_host_connection().await;

        for i in 0..100 {
            std::thread::sleep(time::Duration::from_millis(100));
            let res = client
                .execute(&format!("echo {i}"))
                .await
                .unwrap_or_else(|_| panic!("Execution failed in iteration {i}"));
            assert_eq!(format!("{i}\n"), res.stdout);
        }
    }

    #[tokio::test]
    async fn execute_multiple_context() {
        // This is maybe not expected behaviour, thus documenting this via a test is important.
        let client = establish_test_host_connection().await;
        let output = client
            .execute("export VARIABLE=42; echo $VARIABLE")
            .await
            .unwrap()
            .stdout;
        assert_eq!("42\n", output);

        let output = client.execute("echo $VARIABLE").await.unwrap().stdout;
        assert_eq!("\n", output);
    }

    #[tokio::test]
    async fn connect_second_address() {
        let client = Client::connect(
            &[SocketAddr::from(([127, 0, 0, 1], 23)), test_address()][..],
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::NoCheck,
        )
        .await
        .expect("Resolution to second address failed");

        assert_eq!(test_address(), *client.get_connection_address(),);
    }

    #[tokio::test]
    async fn connect_with_wrong_password() {
        let error = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
            ServerCheckMethod::NoCheck,
        )
        .await
        .expect_err("Client connected with wrong password");

        match error {
            crate::Error::PasswordWrong => {}
            _ => panic!("Wrong error type"),
        }
    }

    #[tokio::test]
    async fn invalid_address() {
        let no_client = Client::connect(
            "this is definitely not an address",
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password("hopefully the wrong password"),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(no_client.is_err());
    }

    #[tokio::test]
    async fn connect_to_wrong_port() {
        let no_client = Client::connect(
            (env("ASYNC_SSH2_TEST_HOST_IP"), 23),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(no_client.is_err());
    }

    #[tokio::test]
    #[ignore = "This times out only after 20 seconds"]
    async fn connect_to_wrong_host() {
        let no_client = Client::connect(
            "172.16.0.6:22",
            "xxx",
            AuthMethod::with_password("xxx"),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(no_client.is_err());
    }

    #[tokio::test]
    async fn auth_key_file() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_key_file(env("ASYNC_SSH2_TEST_CLIENT_PRIV"), None),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn auth_with_agent() {
        // This test requires SSH agent to be running with the test key loaded
        // In Docker environment, the agent is always properly configured
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_agent(),
            ServerCheckMethod::NoCheck,
        )
        .await
        .expect("Agent authentication should succeed with correct key loaded");

        // Verify we can execute a command
        let output = client.execute("echo test").await.unwrap();
        assert_eq!("test\n", output.stdout);
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn auth_with_agent_wrong_user() {
        // This test verifies that agent auth fails with wrong username
        let result = Client::connect(
            test_address(),
            "wrong_user_that_does_not_exist",
            AuthMethod::with_agent(),
            ServerCheckMethod::NoCheck,
        )
        .await;

        // Should fail with authentication error
        assert!(matches!(
            result,
            Err(crate::Error::AgentAuthenticationFailed)
        ));
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn auth_with_agent_no_sock() {
        // Test behavior when SSH_AUTH_SOCK is not set
        // Temporarily unset SSH_AUTH_SOCK for this test
        let original_sock = std::env::var("SSH_AUTH_SOCK").ok();
        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }

        let result = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_agent(),
            ServerCheckMethod::NoCheck,
        )
        .await;

        // Restore original SSH_AUTH_SOCK if it was set
        if let Some(sock) = original_sock {
            unsafe {
                std::env::set_var("SSH_AUTH_SOCK", sock);
            }
        }

        // Should fail with connection error
        assert!(matches!(result, Err(crate::Error::AgentConnectionFailed)));
    }

    #[tokio::test]
    async fn auth_key_file_with_passphrase() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_key_file(
                env("ASYNC_SSH2_TEST_CLIENT_PROT_PRIV"),
                Some(&env("ASYNC_SSH2_TEST_CLIENT_PROT_PASS")),
            ),
            ServerCheckMethod::NoCheck,
        )
        .await;
        if client.is_err() {
            println!("{:?}", client.err());
            panic!();
        }
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn auth_key_str() {
        let key = std::fs::read_to_string(env("ASYNC_SSH2_TEST_CLIENT_PRIV")).unwrap();

        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_key(key.as_str(), None),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn auth_key_str_with_passphrase() {
        let key = std::fs::read_to_string(env("ASYNC_SSH2_TEST_CLIENT_PROT_PRIV")).unwrap();

        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_key(key.as_str(), Some(&env("ASYNC_SSH2_TEST_CLIENT_PROT_PASS"))),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn auth_keyboard_interactive() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthKeyboardInteractive::new()
                .with_response("Password", env("ASYNC_SSH2_TEST_HOST_PW"))
                .into(),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn auth_keyboard_interactive_exact() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthKeyboardInteractive::new()
                .with_response_exact("Password: ", env("ASYNC_SSH2_TEST_HOST_PW"))
                .into(),
            ServerCheckMethod::NoCheck,
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn auth_keyboard_interactive_wrong_response() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthKeyboardInteractive::new()
                .with_response_exact("Password: ", "wrong password")
                .into(),
            ServerCheckMethod::NoCheck,
        )
        .await;
        match client {
            Err(crate::error::Error::KeyboardInteractiveAuthFailed) => {}
            Err(e) => {
                panic!("Expected KeyboardInteractiveAuthFailed error. Got error: {e:?}")
            }
            Ok(_) => panic!("Expected KeyboardInteractiveAuthFailed error."),
        }
    }

    #[tokio::test]
    async fn auth_keyboard_interactive_no_response() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthKeyboardInteractive::new()
                .with_response_exact("Password:", "123")
                .into(),
            ServerCheckMethod::NoCheck,
        )
        .await;
        match client {
            Err(crate::error::Error::KeyboardInteractiveNoResponseForPrompt(prompt)) => {
                assert_eq!(prompt, "Password: ");
            }
            Err(e) => {
                panic!("Expected KeyboardInteractiveNoResponseForPrompt error. Got error: {e:?}")
            }
            Ok(_) => panic!("Expected KeyboardInteractiveNoResponseForPrompt error."),
        }
    }

    #[tokio::test]
    async fn server_check_file() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::with_public_key_file(&env("ASYNC_SSH2_TEST_SERVER_PUB")),
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn server_check_str() {
        let line = std::fs::read_to_string(env("ASYNC_SSH2_TEST_SERVER_PUB")).unwrap();
        let mut split = line.split_whitespace();
        let key = match (split.next(), split.next()) {
            (Some(_), Some(k)) => k,
            (Some(k), None) => k,
            _ => panic!("Failed to parse pub key file"),
        };

        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::with_public_key(key),
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn server_check_by_known_hosts_for_ip() {
        let client = Client::connect(
            test_address(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::with_known_hosts_file(&env("ASYNC_SSH2_TEST_KNOWN_HOSTS")),
        )
        .await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn server_check_by_known_hosts_for_hostname() {
        let client = Client::connect(
            test_hostname(),
            &env("ASYNC_SSH2_TEST_HOST_USER"),
            AuthMethod::with_password(&env("ASYNC_SSH2_TEST_HOST_PW")),
            ServerCheckMethod::with_known_hosts_file(&env("ASYNC_SSH2_TEST_KNOWN_HOSTS")),
        )
        .await;
        if is_running_in_docker() {
            assert!(client.is_ok());
        } else {
            assert!(client.is_err()); // DNS can't find the docker hostname if the rust running without docker container
        }
    }

    #[tokio::test]
    async fn client_can_be_cloned() {
        let client = establish_test_host_connection().await;
        let client2 = client.clone();

        let result1 = client.execute("echo test clone").await.unwrap();
        let result2 = client2.execute("echo test clone2").await.unwrap();

        assert_eq!(result1.stdout, "test clone\n");
        assert_eq!(result2.stdout, "test clone2\n");
    }

    #[tokio::test]
    async fn client_can_upload_file() {
        let client = establish_test_host_connection().await;
        client
            .upload_file(
                &env("ASYNC_SSH2_TEST_UPLOAD_FILE"),
                "/tmp/uploaded",
                None,
                None,
                false,
            )
            .await
            .unwrap();
        let result = client.execute("cat /tmp/uploaded").await.unwrap();
        assert_eq!(result.stdout, "this is a test file\n");
    }

    #[tokio::test]
    async fn client_can_download_file() {
        let client = establish_test_host_connection().await;

        client
            .execute("echo 'this is a downloaded test file' > /tmp/test_download")
            .await
            .unwrap();

        let local_path = std::env::temp_dir().join("downloaded_test_file");
        client
            .download_file("/tmp/test_download", &local_path)
            .await
            .unwrap();

        let contents = tokio::fs::read_to_string(&local_path).await.unwrap();
        assert_eq!(contents, "this is a downloaded test file\n");
    }
}
