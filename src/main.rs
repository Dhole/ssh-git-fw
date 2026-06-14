// use tokio::sync::Mutex;
use std::collections::HashMap;
use std::{cell::RefCell, rc::Rc, sync::OnceLock};

use gtk4::{
    self as gtk, glib, prelude::*, Align, Application, ApplicationWindow, Button, Justification,
    Label,
};
use std::{
    borrow::Cow,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use std::{cell::Cell, io, os::fd::AsRawFd as _};

use async_channel::{Receiver, Sender};
use dashmap::{mapref::one::Ref, DashMap};
use fast_socks5::{
    server::{states, ErrorContext, Socks5ServerProtocol, SocksServerError},
    util::{
        stream::tcp_connect_with_timeout,
        target_addr::{AddrError, TargetAddr},
    },
    ReplyError, Result, Socks5Command, SocksError,
};
use log::{debug, error, info};
use russh::{
    client,
    keys::{Certificate, *},
    server::{self, run_stream, Server as _},
    Channel, ChannelId, Preferred,
};
use serde::{Deserialize, Serialize};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use structopt::StructOpt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{self, TcpListener},
    // sync::mpsc::{self, Receiver, Sender},
    sync::{MappedMutexGuard, Mutex, MutexGuard, OnceCell, RwLock, RwLockReadGuard, SetOnce},
    task,
    time::sleep,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    inbound_server_address: String,
    inbound_server_identity_file: PathBuf,
    outbound_client_identity_file: PathBuf,
}

type Rules = HashMap<String, ClientRules>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ClientRules {
    name: Option<String>,
    servers: HashMap<String, ServerRules>,
}

enum UiRequest {
    Permission(PermissionRequest),
}

struct PermissionRequest {
    pk_openssh: String,
    action: String,
    reply: Arc<SetOnce<(bool, Permission)>>,
}

struct RequestHandler {
    pk_openssh: String,
    tx: Sender<UiRequest>,
}

impl RequestHandler {
    async fn request(&self, action: String) -> (bool, Permission) {
        let reply = Arc::new(SetOnce::new());
        let req = PermissionRequest {
            pk_openssh: self.pk_openssh.clone(),
            action,
            reply: reply.clone(),
        };
        self.tx.send(UiRequest::Permission(req)).await.unwrap();
        reply.wait().await.clone()
    }
}

impl ClientRules {
    async fn validate_exec(
        &self,
        handler: &RequestHandler,
        server_addr: &str,
        user: &str,
        data: &str,
    ) -> Result<(), String> {
        let Some(server_rules) = self.servers.get(server_addr) else {
            return Err(format!("server {} not in rules", server_addr));
        };
        if GitRules::matches_exec(user, data) {
            return server_rules
                .git
                .validate_exec(handler, user, data)
                .await
                .map_err(|e| format!("git: {}", e));
        }
        return Err(format!(
            "no plugin matches with user:{}, data:{}",
            user, data
        ));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerRules {
    git: GitRules,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GitRules {
    #[serde(flatten)]
    paths: HashMap<String, GitAccessRule>,
}

impl GitRules {
    fn matches_exec(user: &str, data: &str) -> bool {
        user == "git"
            && (data.starts_with("git-upload-pack") || data.starts_with("git-receive-pack"))
    }
    async fn validate_exec(
        &self,
        handler: &RequestHandler,
        _user: &str,
        data: &str,
    ) -> Result<(), String> {
        let Some(args) = shlex::split(data) else {
            return Err("parsing command".to_string());
        };
        let Some(arg0) = args.get(0) else {
            return Err("missing arg0".to_string());
        };
        let Some(arg1) = args.get(1) else {
            return Err("missing arg1".to_string());
        };
        let access_rule = self.paths.get(arg1).cloned().unwrap_or_default();
        match arg0.as_str() {
            "git-upload-pack" => match access_rule.read {
                Permission::Yes => Ok(()),
                Permission::No => Err("read not allowed".to_string()),
                Permission::Ask => {
                    let (r, _perm) = handler.request(format!("read from {}", arg1)).await;
                    if r {
                        Ok(())
                    } else {
                        Err("interactively denied".to_string())
                    }
                    // TODO: update rules with _perm
                }
            },
            "git-receive-pack" => match access_rule.write {
                Permission::Yes => Ok(()),
                Permission::No => Err("write not allowed".to_string()),
                Permission::Ask => {
                    let (r, _perm) = handler.request(format!("write to {}", arg1)).await;
                    if r {
                        Ok(())
                    } else {
                        Err("interactively denied".to_string())
                    }
                    // TODO: update rules with _perm
                }
            },
            _ => Err(format!("invalid command {}", arg0)),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GitAccessRule {
    read: Permission,
    write: Permission,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
enum Permission {
    #[default]
    #[serde(rename = "ask")]
    Ask,
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "no")]
    No,
}

impl GitAccessRule {
    fn read(&self) -> bool {
        matches!(self.read, Permission::Yes)
    }
    fn write(&self) -> bool {
        matches!(self.write, Permission::Yes)
    }
}

#[derive(Clone)]
struct Setup {
    ssh_server: Arc<russh::server::Config>,
    ssh_client: Arc<russh::client::Config>,
    outbound_client_key: PrivateKey,
    request_timeout: Duration,
    req_tx: Sender<UiRequest>,
}

struct SessionState {
    //
    // Static
    //
    outbound_server_addr: TargetAddr,
    outbound_client_key: PrivateKey,
    inbound_client_auth: SetOnce<(String, ssh_key::PublicKey)>,
    inbound_client_pk_openssh: SetOnce<String>,
    // Requires mut
    outbound_session: SetOnce<Mutex<russh::client::Handle<Handler>>>,
    inbound_session: SetOnce<russh::server::Handle>,
    client_rules: SetOnce<ClientRules>,
    req_tx: Sender<UiRequest>,
    //
    // Dynamic
    //
    outbound_inbound_chan_id_map: DashMap<u32, ChannelId>,
    inbound_outbound_chan_map: DashMap<u32, Channel<client::Msg>>,
    rules: Arc<RwLock<Rules>>,
}

#[derive(Clone)]
struct Handler(Arc<SessionState>);

impl Deref for Handler {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SessionState {
    fn new(
        outbound_server_addr: TargetAddr,
        outbound_client_key: PrivateKey,
        rules: Arc<RwLock<Rules>>,
        req_tx: Sender<UiRequest>,
    ) -> Self {
        Self {
            outbound_server_addr,
            outbound_client_key,
            inbound_client_auth: SetOnce::new(),
            inbound_client_pk_openssh: SetOnce::new(),
            outbound_session: SetOnce::new(),
            inbound_session: SetOnce::new(),
            client_rules: SetOnce::new(),
            req_tx,
            outbound_inbound_chan_id_map: DashMap::new(),
            inbound_outbound_chan_map: DashMap::new(),
            rules,
        }
    }
    async fn outbound_handle(&self) -> MutexGuard<russh::client::Handle<Handler>> {
        self.outbound_session.wait().await.lock().await
    }
    async fn inbound_handle(&self) -> &russh::server::Handle {
        self.inbound_session.wait().await
    }
    fn inbound_chan_id(&self, outbound_id: ChannelId) -> ChannelId {
        self.outbound_inbound_chan_id_map
            .get(&u32::from(outbound_id))
            .unwrap()
            .clone()
    }
    fn set_chan_map(&self, inbound_id: ChannelId, outbound_chan: Channel<client::Msg>) {
        self.outbound_inbound_chan_id_map
            .insert(u32::from(outbound_chan.id()), inbound_id);
        self.inbound_outbound_chan_map
            .insert(u32::from(inbound_id), outbound_chan);
    }
    fn outbound_chan(&self, inbound_id: ChannelId) -> Ref<u32, Channel<client::Msg>> {
        self.inbound_outbound_chan_map
            .get(&u32::from(inbound_id))
            .unwrap()
    }
    // panics if called before auth
    fn inbound_client_pk_openssh(&self) -> &str {
        self.inbound_client_pk_openssh.get().expect("set at auth")
    }
    fn set_inbound_client_auth(&self, user: String, pk: ssh_key::PublicKey) {
        // TODO: Figure out when may this fail, considering that the pk has been authenticated
        // at this point
        let pk_openssh = pk.to_openssh().expect("TODO");
        self.inbound_client_auth
            .set((user, pk))
            .expect("auth not set");
        self.inbound_client_pk_openssh
            .set(pk_openssh)
            .expect("pk not set");
    }
    async fn client_rules(&self) -> &ClientRules {
        if let Some(client_rules) = self.client_rules.get() {
            &client_rules
        } else {
            // Make a local copy of the client rules for this session
            let pk_ssh = self.inbound_client_pk_openssh();
            let client_rules = self
                .rules
                .read()
                .await
                .get(pk_ssh)
                .cloned()
                .unwrap_or_default();
            // This set could be raced but the value would be the same, so we ignore the error
            self.client_rules.set(client_rules).unwrap_or_default();
            self.client_rules.get().expect("just set")
        }
    }
    fn user_req_handler(&self) -> RequestHandler {
        RequestHandler {
            pk_openssh: self.inbound_client_pk_openssh().to_string(),
            tx: self.req_tx.clone(),
        }
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
        debug!("client: channel success");
        Ok(())
    }

    #[allow(unused_variables)]
    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!("client: channel failure");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let inbound_channel_id = self.inbound_chan_id(channel);
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
        let inbound_channel_id = self.inbound_chan_id(channel);
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
        debug!(
            "DBG outbound server data: {}",
            String::from_utf8_lossy(data)
        );
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .data(inbound_channel_id, data.to_vec())
            .await
            .unwrap();
        Ok(())
    }

    async fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!("DBG outbound server exit_status: {}", exit_status);
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .exit_status_request(inbound_channel_id, exit_status)
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
        debug!("DBG channel_open_session {}", channel.id());
        let outbound_channel = self.outbound_handle().await.channel_open_session().await?;
        self.set_chan_map(channel.id(), outbound_channel);
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.eof().await.unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.close().await.unwrap();
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        debug!(
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
                PrivateKeyWithHashAlg::new(Arc::new(self.outbound_client_key.clone()), hash_alg),
            )
            .await?;

        if !auth_res.success() {
            panic!("Authentication (with publickey) failed");
        } else {
            debug!("Authentication success");
        }
        self.set_inbound_client_auth(user.to_string(), key.clone());
        Ok(server::Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        info!("DBG auth_openssh_certificate");
        Ok(server::Auth::UnsupportedMethod)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let (user, pk) = self.inbound_client_auth.get().unwrap();
        info!(
            "DBG exec_request auth: ({}, {}) chan {}: {} - {}",
            user,
            pk.to_openssh().unwrap(),
            channel,
            self.outbound_server_addr,
            String::from_utf8_lossy(data)
        );
        let server_addr = format!("{}", self.outbound_server_addr);
        let data = str::from_utf8(data).expect("TODO");
        let user_req_handler = self.user_req_handler();
        match self
            .client_rules()
            .await
            .validate_exec(&user_req_handler, &server_addr, user, data)
            .await
        {
            Ok(()) => info!("approved exec"),

            Err(e) => {
                info!("denied exec: {}", e);
                panic!("TODO");
            }
        }
        // TODO: Allow or deny based on config
        let outbound_channel = self.outbound_chan(channel);
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
        debug!("DBG inbound client data: {}", String::from_utf8_lossy(data));
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.data(data).await?;
        // let data = format!("Got data: {}\r\n", String::from_utf8_lossy(data)).into_bytes();
        // self.post(data.clone()).await;
        // session.data(channel, data)?;
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "ssh-git-fw", about = "git over ssh proxy firewall")]
struct Opt {
    #[structopt(short = "c", long)]
    pub config: PathBuf,

    #[structopt(short = "r", long)]
    pub rules: PathBuf,
}

const APP_ID: &str = "com.example.MyApp";

use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime setup failed"))
}

fn main() -> glib::ExitCode {
    env_logger::init();

    let opt = Opt::from_args();
    let config_toml = fs::read(opt.config).expect("TODO");
    let config: Config = toml::from_slice(&config_toml).unwrap();
    let rules_toml = fs::read(opt.rules).expect("TODO");
    let rules: Rules = toml::from_slice(&rules_toml).unwrap();
    let rules = Arc::new(RwLock::new(rules));

    let addr = config.inbound_server_address.clone();

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
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(2)),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            ]),
            ..Default::default()
        },
        ..<_>::default()
    };

    let local = task::LocalSet::new();

    //     let (tx_user_req, mut rx_user_req) = mpsc::channel::<PermissionRequest>(16);

    // GLib-native channel: tokio thread → GTK main loop
    // The Sender is Send, the Receiver integrates with the GLib event loop
    let (req_tx, req_rx) = async_channel::bounded::<UiRequest>(16);
    let setup = Setup {
        ssh_server: Arc::new(config_ssh_server),
        ssh_client: Arc::new(config_ssh_client),
        outbound_client_key: client_key,
        request_timeout: Duration::from_secs(5),
        req_tx,
    };

    let app = Application::builder().build();
    let _app_hold = app.hold();

    // let window_slot: Rc<RefCell<Option<ApplicationWindow>>> = Rc::new(RefCell::new(None));

    // gtk::init().unwrap();
    // let win = ApplicationWindow::builder()
    //     .application(&app)
    //     .title("My App")
    //     .default_width(400)
    //     .default_height(300)
    //     .build();

    // win.connect_close_request(|w| {
    //     w.set_visible(false);
    //     glib::Propagation::Stop
    // });
    // let win = Arc::new(win);

    // Spawn the tokio task — sends a wakeup every 10 seconds
    // runtime().spawn(async move {
    //     loop {
    //         if req_tx.send(()).await.is_err() {
    //             break; // GTK side shut down
    //         }
    //         tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    //     }
    // });

    // Standard TCP loop
    runtime().spawn(async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            match listener.accept().await {
                Ok((socket, _client_addr)) => {
                    let setup = setup.clone();
                    let rules = rules.clone();
                    task::spawn(async move {
                        match serve_socks5(socket, setup, rules).await {
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
    });

    // while let Some(req) = rx_user_req.recv().await {
    //     req.reply.set((true, Permission::Ask)).unwrap();
    // }

    let req_rx = Rc::new(RefCell::new(Some(req_rx)));
    app.connect_startup({
        // let window_slot = window_slot.clone();
        // let win = win.clone();
        // let wake_rx = wake_rx;
        let app = app.clone();
        move |_| {
            println!("DBG connect_startup");
            // let window_slot = window_slot.clone();
            // let win = win.clone();

            let app = app.clone();
            // Receive wakeups on the GTK main loop via glib::spawn_future_local
            let req_rx = req_rx.borrow_mut().take().unwrap();
            // let wake_rx = wake_rx.clone();
            glib::spawn_future_local(async move {
                while let Ok(req) = req_rx.recv().await {
                    let win = ApplicationWindow::builder()
                        .application(&app)
                        .title("proxy-fw-ssh")
                        .default_width(32)
                        .default_height(32)
                        .build();
                    match req {
                        UiRequest::Permission(r) => {
                            win.connect_close_request({
                                let reply = r.reply.clone();
                                move |w| {
                                    reply.set((false, Permission::Ask)).unwrap_or_default();
                                    w.set_visible(false);
                                    glib::Propagation::Stop
                                }
                            });
                            let grid = gtk::Grid::builder()
                                .margin_start(6)
                                .margin_end(6)
                                .margin_top(6)
                                .margin_bottom(6)
                                .halign(gtk::Align::Center)
                                .valign(gtk::Align::Center)
                                .row_spacing(6)
                                .column_spacing(6)
                                .build();
                            win.set_child(Some(&grid));
                            let label = Label::builder().justify(Justification::Center).build();
                            label.set_markup(&format!(
                                concat!("Allow\n", "<b>{}</b>\n", "to {}?"),
                                r.pk_openssh, r.action
                            ));

                            let btn_allow = Button::builder().label("Allow always").build();
                            let btn_allow_once = Button::builder().label("Allow once").build();
                            let btn_deny = Button::builder().label("Deny always").build();

                            btn_allow.connect_clicked({
                                let win = win.clone();
                                let reply = r.reply.clone();
                                move |button| {
                                    println!("DBG allow always");
                                    reply.set((true, Permission::Yes)).unwrap();
                                    win.close();
                                }
                            });
                            btn_allow_once.connect_clicked({
                                let win = win.clone();
                                let reply = r.reply.clone();
                                move |button| {
                                    println!("DBG allow once");
                                    reply.set((true, Permission::Ask)).unwrap();
                                    win.close();
                                }
                            });
                            btn_deny.connect_clicked({
                                let win = win.clone();
                                let reply = r.reply.clone();
                                move |button| {
                                    println!("DBG deny always");
                                    reply.set((false, Permission::No)).unwrap();
                                    win.close();
                                }
                            });

                            grid.attach(&label, 0, 0, 3, 1);
                            grid.attach(&btn_allow, 0, 1, 1, 1);
                            grid.attach(&btn_allow_once, 1, 1, 1, 1);
                            grid.attach(&btn_deny, 2, 1, 1, 1);
                        }
                    }

                    win.present();
                }
            });
        }
    });

    app.connect_activate(move |_| {
        println!("DBG connect_activate");
        // win.present();
    });

    app.run_with_args::<glib::GString>(&[])
}

async fn serve_socks5(
    socket: tokio::net::TcpStream,
    setup: Setup,
    rules: Arc<RwLock<Rules>>,
) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;
    debug!("DBG accept socks5 to {}", target_addr);

    match cmd {
        Socks5Command::TCPConnect => {
            // TODO: Duration from config
            run_tcp_proxy(proto, target_addr, setup, rules).await?;
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

/// Handle the connect command by running a TCP proxy until the connection is done.
async fn run_tcp_proxy<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    target_addr: TargetAddr,
    setup: Setup,
    rules: Arc<RwLock<Rules>>,
    // nodelay: bool,
) -> Result<(), SocksServerError> {
    let addrs = match &target_addr {
        TargetAddr::Ip(ip) => vec![*ip],
        TargetAddr::Domain(domain, port) => {
            debug!("Attempt to DNS resolve the domain {}...", &domain);

            let socket_addrs: Vec<_> = net::lookup_host((&domain[..], *port))
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
        tcp_connect_with_timeout(addrs[0], setup.request_timeout).await
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

    let handler = Handler(Arc::new(SessionState::new(
        target_addr,
        setup.outbound_client_key,
        rules,
        setup.req_tx,
    )));
    let outbound_session =
        match russh::client::connect_stream(setup.ssh_client, outbound_stream, handler.clone())
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

    let inbound_session = match run_stream(setup.ssh_server, inbound_stream, handler.clone()).await
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
    // russh doesn't expose the (reason, description, language_tag) of a client disconnect, so we
    // can't propagate those values when we disconnect the outbound session.
    handler
        .outbound_handle()
        .await
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();

    Ok(())
}
