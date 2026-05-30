use std::collections::HashMap;
use std::sync::Arc;

use log::{debug, error, info};
use russh::keys::{Certificate, *};
use russh::server::{run_stream, Msg, Server as _, Session};
use russh::*;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// #[tokio::main]
// async fn main() {
//     env_logger::builder()
//         .filter_level(log::LevelFilter::Debug)
//         .init();
//
//     // Testing hardcoded key
//     let key = PrivateKey::new(
//         KeypairData::Ed25519(Ed25519Keypair::from_seed(&[0; 32])),
//         "",
//     )
//     .unwrap();
//     let config = russh::server::Config {
//         inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
//         auth_rejection_time: std::time::Duration::from_secs(3),
//         auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
//         // keys: vec![russh::keys::PrivateKey::random(
//         //     &mut rand::rng(),
//         //     russh::keys::Algorithm::Ed25519,
//         // )
//         // .unwrap()],
//         keys: vec![key],
//         preferred: Preferred {
//             // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
//             ..Preferred::default()
//         },
//         ..Default::default()
//     };
//     let config = Arc::new(config);
//     let mut sh = Server {
//         clients: Arc::new(Mutex::new(HashMap::new())),
//         id: 0,
//     };
//
//     let socket = TcpListener::bind(("0.0.0.0", 2222)).await.unwrap();
//     let server = sh.run_on_socket(config, &socket);
//     let handle = server.handle();
//
//     tokio::spawn(async move {
//         tokio::time::sleep(std::time::Duration::from_secs(600)).await;
//         handle.shutdown("Server shutting down after 10 minutes".into());
//     });
//
//     server.await.unwrap()
// }
//
#[derive(Clone)]
struct Server {
    config: Arc<russh::server::Config>,
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

impl Server {
    async fn post(&mut self, data: Vec<u8>) {
        let mut clients = self.clients.lock().await;
        for (id, (channel, s)) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {_error:#?}");
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
        }
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        _key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("exec_request: {}", String::from_utf8_lossy(data));
        session.channel_success(channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }

        info!("data: {}", String::from_utf8_lossy(data));
        let data = format!("Got data: {}\r\n", String::from_utf8_lossy(data)).into_bytes();
        self.post(data.clone()).await;
        session.data(channel, data)?;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        Ok(true)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}

// use anyhow::Context;
use fast_socks5::{
    server::{DnsResolveHelper as _, Socks5ServerProtocol},
    ReplyError, Result, Socks5Command, SocksError,
};
use std::{future::Future, time::Duration};
use tokio::task;

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

/// Useful read 1. https://blog.yoshuawuyts.com/rust-streams/
/// Useful read 2. https://blog.yoshuawuyts.com/futures-concurrency/
/// Useful read 3. https://blog.yoshuawuyts.com/streams-concurrency/
/// error-libs benchmark: https://blog.yoshuawuyts.com/error-handling-survey/
///
/// TODO: Write functional tests: https://github.com/ark0f/async-socks5/blob/master/src/lib.rs#L762
/// TODO: Write functional tests with cURL?
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let addr = "0.0.0.0:2324";
    let listener = TcpListener::bind(addr).await?;

    info!("Listen for socks connections @ {}", addr);

    // Testing hardcoded key
    let key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[0; 32])),
        "",
    )
    .unwrap();

    let config = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![key],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(config);
    let sh = Server {
        config,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(serve_socks5(socket, sh.clone()));
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }
}

async fn serve_socks5(socket: tokio::net::TcpStream, sh: Server) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;
    info!("accept socks5 to {}", target_addr);
    let target_addr = target_addr.resolve_dns().await?;

    match cmd {
        Socks5Command::TCPConnect => {
            run_tcp_proxy(proto, &target_addr, sh).await?;
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{:#}", &err),
        }
    })
}

use fast_socks5::server::ErrorContext;
use fast_socks5::server::{states, SocksServerError};
// use fast_socks5::util::stream::tcp_connect_with_timeout;
use fast_socks5::util::target_addr::TargetAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use tokio::io::{AsyncRead, AsyncWrite};

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
    addr: &TargetAddr,
    mut sh: Server,
    // request_timeout: Duration,
    // nodelay: bool,
) -> Result<(), SocksServerError> {
    let _addr = try_notify!(
        proto,
        addr.to_socket_addrs()
            .err_when("converting to socket addr")
            .and_then(|mut addrs| addrs.next().ok_or(SocksServerError::Bug("no socket addrs")))
    );

    // TCP connect with timeout, to avoid memory leak for connection that takes forever
    // let outbound = match tcp_connect_with_timeout(addr, request_timeout).await {
    //     Ok(stream) => stream,
    //     Err(err) => {
    //         proto.reply_error(&err.to_reply_error()).await?;
    //         return Err(err.into());
    //     }
    // };

    // // Disable Nagle's algorithm if config specifies to do so.
    // try_notify!(
    //     proto,
    //     outbound.set_nodelay(nodelay).err_when("setting nodelay")
    // );

    // debug!("Connected to remote destination");

    let inner = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    let handler = sh.new_client(None);
    let session = match run_stream(sh.config.clone(), inner, handler).await {
        Ok(s) => s,
        Err(e) => {
            panic!("Connection setup failed: {}", e);
        }
    };
    let _handle = session.handle();

    tokio::select! {
        result = session => {
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
