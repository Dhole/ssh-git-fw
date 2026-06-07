use std::borrow::Cow;
use std::sync::Arc;

// use anyhow::Context;
use dashmap::{mapref::one::Ref, DashMap};
use fast_socks5::{server::Socks5ServerProtocol, ReplyError, Result, Socks5Command, SocksError};
use log::{debug, error, info};
use russh::client;
use russh::keys::{Certificate, *};
use russh::server::{self, run_stream, Server as _};
use russh::{Channel, ChannelId, Preferred};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use std::time::Duration;
use tokio::net::{self, TcpListener};
// use tokio::sync::Mutex;
use std::collections::HashMap;
use tokio::task;

use fast_socks5::server::ErrorContext;
use fast_socks5::server::{states, SocksServerError};
use fast_socks5::util::stream::tcp_connect_with_timeout;
use fast_socks5::util::target_addr::{AddrError, TargetAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{
    MappedMutexGuard, Mutex, MutexGuard, OnceCell, RwLock, RwLockReadGuard, SetOnce,
};

#[derive(Clone)]
struct Config {
    ssh_server: Arc<russh::server::Config>,
    ssh_client: Arc<russh::client::Config>,
    outbound_client_key: Arc<PrivateKey>,
}

#[derive(Clone)]
struct Handler {
    outbound_client_key: Arc<PrivateKey>,
    // Requires mut
    outbound_session: Arc<SetOnce<Mutex<russh::client::Handle<Self>>>>,
    inbound_session: Arc<SetOnce<russh::server::Handle>>,
    // inbound_outbound_chan_id_map: Arc<RwLock<Vec<Option<ChannelId>>>>,
    // outbound_inbound_chan_id_map: Arc<RwLock<Vec<Option<ChannelId>>>>,
    outbound_inbound_chan_id_map: Arc<DashMap<u32, ChannelId>>,
    inbound_outbound_chan_map: Arc<DashMap<u32, Channel<client::Msg>>>,
}

impl Handler {
    fn new(outbound_client_key: Arc<PrivateKey>) -> Self {
        Self {
            outbound_client_key,
            outbound_session: Arc::new(SetOnce::new()),
            inbound_session: Arc::new(SetOnce::new()),
            // inbound_outbound_chan_id_map: Arc::new(RwLock::new(Vec::new())),
            // outbound_inbound_chan_id_map: Arc::new(RwLock::new(Vec::new())),
            outbound_inbound_chan_id_map: Arc::new(DashMap::new()),
            inbound_outbound_chan_map: Arc::new(DashMap::new()),
        }
    }
    async fn outbound_handle(&self) -> MutexGuard<russh::client::Handle<Self>> {
        self.outbound_session.wait().await.lock().await
    }
    async fn inbound_handle(&self) -> &russh::server::Handle {
        self.inbound_session.wait().await
    }
    fn inbound_chan_id_get(&self, outbound_id: ChannelId) -> ChannelId {
        self.outbound_inbound_chan_id_map
            .get(&u32::from(outbound_id))
            .unwrap()
            .clone()
    }
    fn chan_map_set(&self, inbound_id: ChannelId, outbound_chan: Channel<client::Msg>) {
        self.outbound_inbound_chan_id_map
            .insert(u32::from(outbound_chan.id()), inbound_id);
        self.inbound_outbound_chan_map
            .insert(u32::from(inbound_id), outbound_chan);
    }
    fn outbound_chan_get(&self, inbound_id: ChannelId) -> Ref<u32, Channel<client::Msg>> {
        self.inbound_outbound_chan_map
            .get(&u32::from(inbound_id))
            .unwrap()
    }
}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: TOFU like OpenSSH
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn channel_success(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!("client: channel success");
        Ok(())
    }

    #[allow(unused_variables)]
    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!("client: channel failure");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let inbound_channel_id = self.inbound_chan_id_get(channel);
        self.inbound_handle()
            .await
            .eof(inbound_channel_id)
            .await
            .unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let inbound_channel_id = self.inbound_chan_id_get(channel);
        self.inbound_handle()
            .await
            .close(inbound_channel_id)
            .await
            .unwrap();
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!(
            "DBG outbound server data: {}",
            String::from_utf8_lossy(data)
        );
        let inbound_channel_id = self.inbound_chan_id_get(channel);
        self.inbound_handle()
            .await
            .data(inbound_channel_id, data.to_vec())
            .await
            .unwrap();
        Ok(())
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        info!("DBG channel_open_session {}", channel.id());
        let outbound_channel = self.outbound_handle().await.channel_open_session().await?;
        self.chan_map_set(channel.id(), outbound_channel);
        // {
        //     let mut clients = self.clients.lock().await;
        //     clients.insert(self.id, (channel.id(), session.handle()));
        // }
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan_get(channel);
        outbound_channel.eof().await.unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan_get(channel);
        outbound_channel.close().await.unwrap();
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        info!(
            "DBG auth_publickey user={}, key={}",
            user,
            key.to_openssh().unwrap()
        );
        let hash_alg = self
            .outbound_handle()
            .await
            .best_supported_rsa_hash()
            .await?
            .flatten();
        let auth_res = self
            .outbound_handle()
            .await
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(self.outbound_client_key.clone(), hash_alg),
            )
            .await?;

        if !auth_res.success() {
            panic!("Authentication (with publickey) failed");
        } else {
            info!("Authentication success");
        }
        Ok(server::Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        info!("DBG auth_openssh_certificate");
        Ok(server::Auth::Accept)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        info!(
            "DBG exec_request chan {}: {}",
            channel,
            String::from_utf8_lossy(data)
        );
        // TODO: Allow or deny based on config
        let outbound_channel = self.outbound_chan_get(channel);
        outbound_channel.exec(true, data).await?;
        // TODO: sync with client channel success/failure
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        info!("DBG inbound client data: {}", String::from_utf8_lossy(data));
        let outbound_channel = self.outbound_chan_get(channel);
        outbound_channel.data(data).await?;
        // let data = format!("Got data: {}\r\n", String::from_utf8_lossy(data)).into_bytes();
        // self.post(data.clone()).await;
        // session.data(channel, data)?;
        Ok(())
    }
}

/// # How to use it:
///
/// Listen on a local address, authentication-free:
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 no-auth`
///
/// Listen on a local address, with basic username/password requirement:
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 password --username admin --password password`
///
/// Same as above but with UDP support
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 --allow-udp --public-addr 127.0.0.1 password --username admin --password password`
// #[derive(Debug, StructOpt)]
// #[structopt(
//     name = "socks5-server",
//     about = "A simple implementation of a socks5-server."
// )]
// struct Opt {
//     /// Bind on address address. eg. `127.0.0.1:1080`
//     #[structopt(short, long)]
//     pub listen_addr: String,
//
//     /// Our external IP address to be sent in reply packets (required for UDP)
//     #[structopt(long)]
//     pub public_addr: Option<std::net::IpAddr>,
//
//     /// Request timeout
//     #[structopt(short = "t", long, default_value = "10", parse(try_from_str=parse_duration))]
//     pub request_timeout: Duration,
//
//     /// Choose authentication type
//     #[structopt(subcommand, name = "auth")] // Note that we mark a field as a subcommand
//     pub auth: AuthMode,
//
//     /// Don't perform the auth handshake, send directly the command request
//     #[structopt(short = "k", long)]
//     pub skip_auth: bool,
//
//     /// Allow UDP proxying, requires public-addr to be set
//     #[structopt(short = "U", long)]
//     pub allow_udp: bool,
// }
//
// /// Choose the authentication type
// #[derive(StructOpt, Debug, PartialEq)]
// enum AuthMode {
//     NoAuth,
//     Password {
//         #[structopt(short, long)]
//         username: String,
//
//         #[structopt(short, long)]
//         password: String,
//     },
// }

// fn parse_duration(s: &str) -> Result<Duration, ParseFloatError> {
//     let seconds = s.parse()?;
//     Ok(Duration::from_secs_f64(seconds))
// }

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let addr = "0.0.0.0:2324";
    let listener = TcpListener::bind(addr).await?;

    info!("Listen for socks connections @ {}", addr);

    // Testing hardcoded key
    let server_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[0; 32])),
        "",
    )
    .unwrap();
    info!(
        "inbound server key: {}",
        server_key.public_key().to_openssh().unwrap()
    );
    let client_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[1; 32])),
        "",
    )
    .unwrap();
    info!(
        "outbound client key: {}",
        client_key.public_key().to_openssh().unwrap()
    );

    let config_ssh_server = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![server_key],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config_ssh_client = client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            ]),
            ..Default::default()
        },
        ..<_>::default()
    };

    let config = Config {
        ssh_server: Arc::new(config_ssh_server),
        ssh_client: Arc::new(config_ssh_client),
        outbound_client_key: Arc::new(client_key),
    };

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                let config = config.clone();
                task::spawn(async move {
                    match serve_socks5(socket, config).await {
                        Ok(()) => {}
                        Err(err) => error!("{:#}", &err),
                    }
                });
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }
}

async fn serve_socks5(socket: tokio::net::TcpStream, config: Config) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;
    info!("DBG accept socks5 to {}", target_addr);

    let socket_addrs = match target_addr {
        TargetAddr::Ip(ip) => vec![ip],
        TargetAddr::Domain(domain, port) => {
            debug!("Attempt to DNS resolve the domain {}...", &domain);

            let socket_addrs: Vec<_> = net::lookup_host((&domain[..], port))
                .await
                .map_err(|err| AddrError::DNSResolutionFailed(err))?
                .collect();
            if socket_addrs.is_empty() {
                return Err(AddrError::NoDNSRecords)?;
            }
            debug!("domain name resolved to {:?}", socket_addrs);
            socket_addrs
        }
    };

    match cmd {
        Socks5Command::TCPConnect => {
            // TODO: Duration from config
            run_tcp_proxy(proto, &socket_addrs, config, Duration::from_secs(5)).await?;
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };
    Ok(())
}

macro_rules! try_notify {
    ($proto:expr, $e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => {
                if let Err(rep_err) = $proto.reply_error(&err.to_reply_error()).await {
                    error!(
                        "extra error while reporting an error to the client: {}",
                        rep_err
                    );
                }
                return Err(err.into());
            }
        }
    };
}

/// Run a bidirectional proxy between two streams.
/// Using 2 different generators, because they could be different structs with same traits.
pub async fn transfer<I, O>(mut inbound: I, mut outbound: O)
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(res) => debug!("transfer closed ({}, {})", res.0, res.1),
        Err(err) => error!("transfer error: {:?}", err),
    };
}

/// Handle the connect command by running a TCP proxy until the connection is done.
async fn run_tcp_proxy<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    addrs: &[SocketAddr],
    config: Config,
    request_timeout: Duration,
    // nodelay: bool,
) -> Result<(), SocksServerError> {
    // let _addr = try_notify!(
    //     proto,
    //     addr.to_socket_addrs()
    //         .err_when("converting to socket addr")
    //         .and_then(|mut addrs| addrs.next().ok_or(SocksServerError::Bug("no socket addrs")))
    // );

    // TCP connect with timeout, to avoid memory leak for connection that takes forever
    // TODO: Use the other addrs if the first one fails
    let outbound_stream = try_notify!(
        proto,
        tcp_connect_with_timeout(addrs[0], request_timeout).await
    );

    // // Disable Nagle's algorithm if config specifies to do so.
    // try_notify!(
    //     proto,
    //     outbound.set_nodelay(nodelay).err_when("setting nodelay")
    // );

    // debug!("Connected to remote destination");

    let inbound_stream = proto
        .reply_success(outbound_stream.local_addr().expect("ok"))
        .await?;

    let handler = Handler::new(config.outbound_client_key);
    let outbound_session =
        match russh::client::connect_stream(config.ssh_client, outbound_stream, handler.clone())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                panic!("Connection setup failed: {}", e);
            }
        };
    handler
        .outbound_session
        .set(Mutex::new(outbound_session))
        .unwrap_or_else(|_| panic!("todo"));

    // TODO
    // let auth_res = session
    //     .authenticate_publickey(
    //         user,
    //         PrivateKeyWithHashAlg::new(
    //             Arc::new(key_pair),
    //             session.best_supported_rsa_hash().await?.flatten(),
    //         ),
    //     )
    //     .await?;

    // if !auth_res.success() {
    //     anyhow::bail!("Authentication (with publickey) failed");
    // }
    let inbound_session = match run_stream(config.ssh_server, inbound_stream, handler.clone()).await
    {
        Ok(s) => s,
        Err(e) => {
            panic!("Connection setup failed: {}", e);
        }
    };
    handler
        .inbound_session
        .set(inbound_session.handle())
        .unwrap_or_else(|_| panic!("todo"));

    tokio::select! {
        result = inbound_session => {
            if let Err(e) = result {
                panic!("Connection closed with error: {}", e);
            } else {
                debug!("Connection closed");
            }
        }
    }

    // transfer(&mut inner, outbound).await;
    Ok(())
}
