use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::net::{IpAddr, UdpSocket};
use std::os::unix::prelude::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::Duration;

use fast_socks5::client::{Socks5Datagram, Socks5Stream};

use nix::cmsg_space;
use nix::errno::Errno;
use nix::sys::socket::sockopt::{IpTransparent, Ipv4OrigDstAddr, Ipv6OrigDstAddr};
use nix::sys::socket::{
    recvmsg, setsockopt, ControlMessageOwned, MsgFlags, RecvMsg, SockaddrIn, SockaddrIn6,
};
use thiserror::Error;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::time::{sleep, Instant};
use tokio::{process::Command, spawn, task::JoinHandle};

use crate::command::CommandError;
use crate::firewall::{
    raw_to_socket_addr_v4, raw_to_socket_addr_v6, Firewall, FirewallConfig, FirewallError,
    FirewallListenerConfig, FirewallSubnetConfig,
};
use crate::network::{ListenerAddr, Subnets};
use crate::options::FirewallType;

pub struct Config {
    pub includes: Subnets,
    pub excludes: Subnets,
    pub remote: Option<String>,
    pub listen: Vec<ListenerAddr>,
    pub socks_addr: SocketAddr,
    pub firewall: FirewallType,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Firewall Error")]
    Firewall(#[from] FirewallError),

    #[error("Join Error")]
    Join(#[from] JoinError),

    #[error("Command Error")]
    Command(#[from] CommandError),

    #[error("IO Error")]
    Io(#[from] std::io::Error),

    #[error("Errno error")]
    Errno(#[from] Errno),

    #[error("No source address")]
    NoSourceAddress,

    #[error("No destination address")]
    NoDestinationAddress,
}
// #[derive(Debug)]
// pub struct ClientError {
//     message: String,
// }

// impl Display for ClientError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{}", self.message)
//     }
// }

// impl From<FirewallError> for ClientError {
//     fn from(err: FirewallError) -> Self {
//         ClientError {
//             message: format!("FirewallError: {err}"),
//         }
//     }
// }

// impl From<JoinError> for ClientError {
//     fn from(err: JoinError) -> Self {
//         ClientError {
//             message: format!("JoinError: {err}"),
//         }
//     }
// }

// impl From<CommandError> for ClientError {
//     fn from(err: CommandError) -> Self {
//         ClientError {
//             message: format!("CommandError: {err}"),
//         }
//     }
// }

// impl From<std::io::Error> for ClientError {
//     fn from(err: std::io::Error) -> Self {
//         ClientError {
//             message: format!("std::io::Error: {err}"),
//         }
//     }
// }

// impl From<mpsc::error::SendError<Message>> for ClientError {
//     fn from(err: mpsc::error::SendError<Message>) -> Self {
//         ClientError {
//             message: format!("mpsc::error::SendError: {err}"),
//         }
//     }
// }

// impl Error for ClientError {}

pub async fn main(config: &Config) -> Result<(), ClientError> {
    let (control_tx, control_rx) = mpsc::channel(1);

    let tx_clone = control_tx.clone();
    ctrlc::set_handler(move || {
        tx_clone
            .blocking_send(Message::Shutdown)
            .expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");

    let firewall_config = get_firewall_config(config);
    let firewall = get_firewall(config)?;
    let setup_commands = firewall.setup_firewall(&firewall_config)?;
    let shutdown_commands = firewall.restore_firewall(&firewall_config)?;

    log::info!("Setting up firewall {:#?}", setup_commands);
    setup_commands.run_all().await?;

    log::debug!("run_everything");
    let client_result = run_everything(config, firewall, control_tx, control_rx).await;
    if let Err(err) = &client_result {
        log::error!("run_everything error: {err}");
    } else {
        log::debug!("run_everything exited normally");
    }

    log::info!("Restoring firewall{:#?}", shutdown_commands);
    let shutdown_result = shutdown_commands.run_all().await;
    if let Err(err) = &shutdown_result {
        log::error!("Error restoring firewall: {err}");
    } else {
        log::debug!("Restored firewall");
    }

    client_result?;
    shutdown_result?;
    Ok(())
}

async fn run_everything(
    config: &Config,
    firewall: Box<dyn Firewall + Send + Sync>,
    control_tx: mpsc::Sender<Message>,
    mut control_rx: mpsc::Receiver<Message>,
) -> Result<(), ClientError> {
    let client = run_client(config, firewall);

    if let Some(remote) = &config.remote {
        // ssh shutdown sequence with ssh:
        // ctrlc handler sends signal to control_tx.
        // ssh handler receives event from control_rx.
        // ssh handler kills ssh.
        // ssh_handle completes, and the select finishes.
        // we return.
        let c = run_ssh(config, remote.to_string(), control_rx).await?;
        let ssh_handle = c.handle;

        tokio::pin!(ssh_handle);
        tokio::pin!(client);

        select! {
            res = &mut ssh_handle => {
                log::info!("ssh_handle finished");
                res??;
            },
            res = &mut client => {
                log::info!("client finished");
                res?;
            },
            else => {
                log::info!("everything finished");
            }
        }

        // We don't care if the message fails, probably because ssh already exited.
        _ = control_tx.send(Message::Shutdown).await;
    } else {
        // ssh shutdown sequence without ssh:
        // ctrlc handler sends signal to control_tx.
        // the select finishes.
        // we return.
        select! {
            res = client => {
                log::info!("client finished");
                res?;
            },
            Some(_) = control_rx.recv() => {
                log::info!("control_rx shutdown requested");
            }
        }
    }

    Ok(())
}

// async fn read_tcpstream(
//     stream: &mut TcpStream,
//     buf: &mut [u8],
//     shutdown: bool,
// ) -> Option<Result<usize, std::io::Error>> {
//     if shutdown {
//         None
//     } else {
//         Some(stream.read(buf).await)
//     }
// }

// async fn read_socksstream(
//     stream: &mut Socks5Stream<TcpStream>,
//     buf: &mut [u8],
//     shutdown: bool,
// ) -> Option<Result<usize, std::io::Error>> {
//     if shutdown {
//         None
//     } else {
//         Some(stream.read(buf).await)
//     }
// }

// async fn write(stream: &mut Option<TcpStream>, buf: &[u8]) -> Option<Result<(), std::io::Error>> {
//     if let Some(s) = stream {
//         Some(s.write_all(buf).await)
//     } else {
//         None
//     }
// }

fn get_firewall(config: &Config) -> Result<Box<dyn Firewall + Send + Sync>, ClientError> {
    let firewall: Box<dyn Firewall + Send + Sync> = match config.firewall {
        FirewallType::Nat => Box::new(crate::firewall::nat::NatFirewall::new()),
        FirewallType::TProxy => Box::new(crate::firewall::tproxy::TProxyFirewall::new()),
    };
    Ok(firewall)
}

fn get_firewall_config(config: &Config) -> FirewallConfig {
    let familys = config
        .listen
        .iter()
        .map(|addr| match addr.ip() {
            IpAddr::V4(_) => FirewallListenerConfig::Ipv4(FirewallSubnetConfig {
                enable: true,
                listener: addr.clone(),
                includes: config.includes.ipv4(),
                excludes: config.excludes.ipv4(),
            }),
            IpAddr::V6(_) => FirewallListenerConfig::Ipv6(FirewallSubnetConfig {
                enable: true,
                listener: addr.clone(),
                includes: config.includes.ipv6(),
                excludes: config.excludes.ipv6(),
            }),
        })
        .collect();
    FirewallConfig {
        filter_from_user: None,
        listeners: familys,
    }
}

#[derive(Debug, Clone)]
enum Message {
    Shutdown,
}

struct Task {
    // tx: mpsc::Sender<Message>,
    handle: JoinHandle<Result<(), std::io::Error>>,
}

async fn run_ssh(
    config: &Config,
    remote: String,
    mut rx: mpsc::Receiver<Message>,
) -> Result<Task, ClientError> {
    let socks = config.socks_addr;

    let handle: JoinHandle<Result<(), std::io::Error>> = spawn(async move {
        let args = vec![
            "-D".to_string(),
            socks.to_string(),
            "-N".to_string(),
            remote,
        ];

        let mut child = Command::new("ssh").args(args).spawn()?;

        tokio::select! {
            msg = rx.recv() => {
                log::info!("ssh shutdown requested, killing child ssh: {msg:?}");
                child.kill().await?;
                Ok(())
            }
            status = child.wait() => {
                match status {
                    Ok(rc) => {
                        if rc.success() {
                            log::error!("ssh exited with rc: {rc}");
                            Ok(())
                        } else {
                            log::info!("ssh exited with rc: {rc}");
                            Err(std::io::Error::new(std::io::ErrorKind::Other, "ssh failed"))
                        }
                    }
                    Err(err) => {
                        log::error!("ssh wait failed: {err}");
                        Err(err)
                    }
                }
            }
        }
    });

    Ok(Task { handle })
}

async fn run_client(
    config: &Config,
    firewall: Box<dyn Firewall + Send + Sync>,
) -> Result<Task, ClientError> {
    let socks_addr = config.socks_addr;
    let listen = config.listen.clone();

    let firewall: Arc<dyn Firewall + Send + Sync> = Arc::from(firewall);
    for l_addr in listen {
        println!("----> {}", l_addr);
        match l_addr.protocol {
            crate::network::Protocol::Tcp => listen_tcp(&firewall, l_addr, socks_addr).await?,
            crate::network::Protocol::Udp => listen_udp(&firewall, l_addr, socks_addr).await?,
        }
    }

    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

async fn listen_tcp(
    firewall: &Arc<dyn Firewall + Send + Sync>,
    l_addr: ListenerAddr,
    socks_addr: SocketAddr,
) -> Result<(), ClientError> {
    let firewall = Arc::clone(firewall);
    let listener = TcpListener::bind(l_addr.addr).await?;
    firewall.setup_tcp_listener(&listener)?;

    let _handle = tokio::spawn(async move {
        loop {
            let firewall = Arc::clone(&firewall);
            let (socket, _) = listener.accept().await.unwrap();
            let l_addr = l_addr.clone();
            tokio::spawn(async move {
                handle_tcp_client(socket, &l_addr, socks_addr, firewall).await;
            });
        }
    });
    Ok(())
}

#[derive(Debug)]
enum UdpMessage {
    Packet(SocketAddr, Vec<u8>),
}

struct UdpState {
    tx: mpsc::Sender<UdpMessage>,
    last_packet: Instant,
}

async fn listen_udp(
    firewall: &Arc<dyn Firewall + Send + Sync>,
    l_addr: ListenerAddr,
    socks_addr: SocketAddr,
) -> Result<(), ClientError> {
    let _firewall = Arc::clone(firewall);

    let listener = UdpSocket::bind(l_addr.addr)?;
    let fd = listener.as_raw_fd();

    // let s: SockAddr = l_addr.addr.clone().into();
    // let s: dyn SockaddrLike = match l_addr.ip() {
    //     IpAddr::V4(ip4) => SockaddrIn::new(ip4, l_addr.port()),
    //     IpAddr::V6(ip6) => todo!(),
    // };

    // // let s: SockaddrIn = s.into();
    // let receive = socket(
    //     AddressFamily::Inet,
    //     SockType::Datagram,
    //     SockFlag::empty(),
    //     None,
    // )
    // .expect("creating socket failed");

    setsockopt(fd, IpTransparent, &true).unwrap();
    match l_addr.ip() {
        IpAddr::V4(_) => {
            setsockopt(fd, Ipv4OrigDstAddr, &true).expect("setsockopt Ipv4OrigDstAddr failed");
        }
        IpAddr::V6(_) => {
            setsockopt(fd, Ipv6OrigDstAddr, &true).expect("setsockopt Ipv6OrigDstAddr failed");
        }
    }

    tokio::spawn(async move {
        let receive = listener.as_raw_fd();
        let mut index: HashMap<SocketAddr, UdpState> = HashMap::new();
        // let mut index: HashMap<SocketAddr, usize> = HashMap::new();
        // let mut socks: Vec<Socks5Datagram<TcpStream>> = Vec::new();
        // let mut buffers: Vec<RefCell<Vec<u8>>> = Vec::new();
        let l_addr = l_addr;

        // let mut operation = Box::pin(recv_udp(&l_addr, receive));
        // tokio::pin!(operation);

        loop {
            let l_addr = l_addr.clone();
            println!("{l_addr} UDP waiting");

            // // let refcell = RefCell::new(buf);
            // let flist = socks.iter().map(|s| {
            //     let mut buf = Vec::with_capacity(1024);
            //     unsafe { buf.set_len(1024) };
            //     let future = s.recv_from(&mut buf);
            //     // Box::pin(future)
            //     // tokio::pin!(future);
            //     future
            // });
            // let x = futures::future::select_all(flist);

            // tokio::select! {
            //     udp = &mut operation => {
            //         let (local_address, remote_address, bytes) = udp.unwrap();
            //         println!("{l_addr} UDP operation");
            //         let l_addr = l_addr.clone();
            //         operation = Box::pin(recv_udp(l_addr, receive));
            //         // tokio::pin!(operation);
            //     },
            //     // _ = futures::future::select_all(flist) => {
            //     //     break;
            //     // }
            // }
            let (local_addr, remote_addr, bytes) = recv_udp(&l_addr, receive).await.unwrap();
            // println!("{l_addr} {local_addr:?} {remote_addr:?} UDP {bytes:?}");

            if let Some(state) = index.get_mut(&local_addr) {
                let message = UdpMessage::Packet(remote_addr, bytes);
                state.last_packet = Instant::now();
                state.tx.send(message).await.unwrap();
            } else {
                let (tx, rx) = mpsc::channel(1);

                tokio::spawn(async move {
                    handle_udp_client(fd, rx, socks_addr).await;
                });

                let message = UdpMessage::Packet(remote_addr, bytes);
                tx.send(message).await.unwrap();

                let state = UdpState {
                    tx,
                    last_packet: Instant::now(),
                };

                index.insert(local_addr, state);
            }
        }
    });

    Ok(())
}

async fn recv_udp(
    l_addr: &ListenerAddr,
    fd: i32,
) -> Result<(SocketAddr, SocketAddr, Vec<u8>), ClientError> {
    let rc = match l_addr.ip() {
        IpAddr::V4(_) => recv_udp_v4(fd).await,
        IpAddr::V6(_) => recv_udp_v6(fd).await,
    }?;

    let (local_addr, remote_addr, bytes) = rc;

    let local_addr = if let Some(local_addr) = local_addr {
        local_addr
    } else {
        return Err(ClientError::NoSourceAddress);
    };

    let remote_addr = if let Some(remote_addr) = remote_addr {
        remote_addr
    } else {
        return Err(ClientError::NoDestinationAddress);
    };

    Ok((local_addr, remote_addr, bytes))
}

async fn recv_udp_v4(
    receive: i32,
) -> Result<(Option<SocketAddr>, Option<SocketAddr>, Vec<u8>), ClientError> {
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 1024];
        let mut iov = [IoSliceMut::new(&mut buf)];

        let mut cmsg = cmsg_space!(libc::sockaddr_in);
        let msg: RecvMsg<SockaddrIn> =
            recvmsg(receive, &mut iov, Some(&mut cmsg), MsgFlags::empty())?;
        let local_addr: Option<SocketAddr> = msg.address.map(|addr| SocketAddr::V4(addr.into()));
        println!("recvmsg: {:?}", msg);

        let mut remote_addr: Option<SocketAddr> = None;
        for cmsg in msg.cmsgs() {
            if let ControlMessageOwned::Ipv4OrigDstAddr(addr) = cmsg {
                remote_addr = Some(raw_to_socket_addr_v4(addr));
            }
        }
        Ok((local_addr, remote_addr, Vec::from(&buf[0..msg.bytes])))
    })
    .await?
}

async fn recv_udp_v6(
    receive: i32,
) -> Result<(Option<SocketAddr>, Option<SocketAddr>, Vec<u8>), ClientError> {
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 1024];
        let mut iov = [IoSliceMut::new(&mut buf)];

        let mut cmsg = cmsg_space!(libc::sockaddr_in6);
        let msg: RecvMsg<SockaddrIn6> =
            recvmsg(receive, &mut iov, Some(&mut cmsg), MsgFlags::empty())?;
        let local_addr: Option<SocketAddr> = msg.address.map(|addr| SocketAddr::V6(addr.into()));
        println!("recvmsg: {:?}", msg);

        let mut remote_addr: Option<SocketAddr> = None;
        for cmsg in msg.cmsgs() {
            if let ControlMessageOwned::Ipv6OrigDstAddr(addr) = cmsg {
                remote_addr = Some(raw_to_socket_addr_v6(addr));
            }
        }
        Ok((local_addr, remote_addr, Vec::from(&buf[0..msg.bytes])))
    })
    .await?
}

async fn handle_tcp_client(
    socket: TcpStream,
    l_addr: &ListenerAddr,
    socks_addr: SocketAddr,
    firewall: Arc<dyn Firewall + Send + Sync>,
) {
    let mut local = socket;
    let local_addr = local.peer_addr().unwrap();
    log::debug!("new connection from: {}", local_addr);

    let remote_addr = firewall.get_dst_addr(&local).unwrap();
    log::info!("{l_addr} got connection from {local_addr} to {remote_addr}");

    let (addr_str, port) = {
        let addr = remote_addr.ip().to_string();
        let port = remote_addr.port();
        (addr, port)
    };

    let mut remote_config = fast_socks5::client::Config::default();
    remote_config.set_skip_auth(false);
    let mut remote = Socks5Stream::connect(socks_addr, addr_str, port, remote_config)
        .await
        .unwrap();

    let result = copy_bidirectional(&mut local, &mut remote).await;
    // let result = my_bidirectional_copy(&mut local, &mut remote).await;

    log::debug!("copy_bidirectional result: {:?}", result);
}

async fn handle_udp_client(fd: i32, mut rx: mpsc::Receiver<UdpMessage>, socks_addr: SocketAddr) {
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let backing_socket = TcpStream::connect(socks_addr).await.unwrap();
    let socks5 = Socks5Datagram::bind(backing_socket, "[::]:0")
        .await
        .unwrap();

    let mut buffer = [0u8; 1024];
    loop {
        select! {
            Some(msg) = rx.recv() => {
                match msg {
                    UdpMessage::Packet(remote_addr, bytes) => {
                        log::info!("{} sending packet {:?} for {}", socks_addr, bytes, remote_addr);
                        socks5.send_to(&bytes, remote_addr).await.unwrap();
                    }
                }
            },
            result = socks5.recv_from(&mut buffer) => {
                match result {
                    Ok((bytes, remote_addr)) => {
                        log::info!("{} received packet {:?} from {}", socks_addr, &buffer[0..bytes], remote_addr);
                        socket.send_to(&buffer[0..bytes], remote_addr).unwrap();
                    }
                    Err(e) => {
                        log::error!("socks5 error: {:?}", e);
                    }
                }
            },
            else => {
                log::info!("udp done");
                break;
            }
        }
    }
}

// async fn my_bidirectional_copy(
//     local: &mut TcpStream,
//     remote: &mut Socks5Stream<TcpStream>,
// ) -> Result<(), ClientError> {
//     let mut local_buf = [0; 1024];
//     let mut remote_buf = [0; 1024];
//     let remote_shutdown: bool = false;
//     let mut local_shutdown: bool = false;

//     println!("start loop");
//     loop {
//         println!("start select");
//         select! {
//             Some(res) = read_tcpstream(local, &mut local_buf, local_shutdown) => {
//                 println!("local read");
//                 match res {
//                     Ok(0) => {
//                         println!("local shutdown request");
//                         remote.shutdown().await.unwrap();
//                         local_shutdown = true;
//                     }
//                     Ok(n) => {
//                         println!("local read -> remote write: {}", n);
//                         remote.write_all(&local_buf[..n]).await.unwrap();
//                     }
//                     Err(err) => {
//                         println!("local read failed: {}", err);
//                         remote.shutdown().await.unwrap();
//                         break;
//                     }
//                 }
//             }
//             Some(res) = read_socksstream(remote, &mut remote_buf, remote_shutdown) => {
//                 println!("remote read {:?}", res);
//                 match res {
//                     Ok(0) => {
//                         println!("remote shutdown request");
//                         let _ = local.shutdown().await.map_err(|err| {log::warn!("local shutdown failed {err}"); err});                        // remote_shutdown = true;
//                         break;
//                     }
//                     Ok(n) => {
//                         println!("remote read -> local write: {} {}", n, remote_shutdown);
//                         println!("{:?}", &remote_buf[..n]);
//                         local.write_all(&remote_buf[..n]).await.unwrap();
//                     }
//                     Err(err) => {
//                         println!("remote read failed: {}", err);
//                         local.shutdown().await.unwrap();
//                         break;
//                     }
//                 }
//             }
//             else => {
//                 print!("else Shutdown");
//                 break;
//             }
//         }
//         println!("end select");
//     }
//     println!("end loop");

//     Ok(())
// }
