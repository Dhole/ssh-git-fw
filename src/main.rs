use std::borrow::Cow;
use std::sync::Arc;

// use anyhow::Context;
use fast_socks5::{server::Socks5ServerProtocol, ReplyError, Result, Socks5Command, SocksError};
use log::{debug, error, info};
use russh::keys::{Certificate, *};
use russh::server::{run_stream, Msg, Server as _, Session};
use russh::*;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use std::time::Duration;
use tokio::net::{self, TcpListener};
// use tokio::sync::Mutex;
use tokio::task;

use fast_socks5::server::ErrorContext;
use fast_socks5::server::{states, SocksServerError};
use fast_socks5::util::stream::tcp_connect_with_timeout;
use fast_socks5::util::target_addr::{AddrError, TargetAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
struct Config {
    ssh_server: Arc<russh::server::Config>,
    ssh_client: Arc<russh::client::Config>,
    outbound_client_key: Arc<PrivateKey>,
}

#[derive(Clone)]
struct Server {
    // clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    // id: usize,
}

// impl Server {
//     async fn post(&mut self, data: Vec<u8>) {
//         let mut clients = self.clients.lock().await;
//         for (id, (channel, s)) in clients.iter_mut() {
//             if *id != self.id {
//                 let _ = s.data(*channel, data.clone()).await;
//             }
//         }
//     }
// }

// impl server::Server for Server {
//     type Handler = Handler;
//     fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
//         Handler {}
//     }
//     fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
//         eprintln!("Session error: {_error:#?}");
//     }
// }

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: TOFU like OpenSSH
        Ok(true)
    }
}

// #[derive(Clone)]
struct Handler {
    outbound_client_key: Arc<PrivateKey>,
    outbound_session: russh::client::Handle<Client>,
}

// impl Handler {
//     fn new() -> Self {
//         Self {}
//     }
// }

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!("DBG channel_open_session");
        // {
        //     let mut clients = self.clients.lock().await;
        //     clients.insert(self.id, (channel.id(), session.handle()));
        // }
        Ok(true)
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
        let auth_res = self
            .outbound_session
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(
                    self.outbound_client_key.clone(),
                    self.outbound_session
                        .best_supported_rsa_hash()
                        .await?
                        .flatten(),
                ),
            )
            .await?;

        if !auth_res.success() {
            panic!("Authentication (with publickey) failed");
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("DBG exec_request: {}", String::from_utf8_lossy(data));
        session.channel_success(channel)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("DBG data: {}", String::from_utf8_lossy(data));
        // let data = format!("Got data: {}\r\n", String::from_utf8_lossy(data)).into_bytes();
        // self.post(data.clone()).await;
        // session.data(channel, data)?;
        Ok(())
    }
}

// impl Drop for Server {
//     fn drop(&mut self) {
//         let id = self.id;
//         let clients = self.clients.clone();
//         tokio::spawn(async move {
//             let mut clients = clients.lock().await;
//             clients.remove(&id);
//         });
//     }
// }

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
    let client_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[1; 32])),
        "",
    )
    .unwrap();

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

    let ssh_client = Client {};
    let outbound_session =
        match russh::client::connect_stream(config.ssh_client, outbound_stream, ssh_client).await {
            Ok(s) => s,
            Err(e) => {
                panic!("Connection setup failed: {}", e);
            }
        };

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

    let handler = Handler {
        outbound_client_key: config.outbound_client_key,
        outbound_session,
    };
    let inbound_session = match run_stream(config.ssh_server, inbound_stream, handler).await {
        Ok(s) => s,
        Err(e) => {
            panic!("Connection setup failed: {}", e);
        }
    };
    let _handle = inbound_session.handle();

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
