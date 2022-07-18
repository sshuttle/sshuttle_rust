use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::prelude::AsRawFd;
use std::time::Duration;
use std::{error::Error, fmt::Display, net::SocketAddr};

use fast_socks5::client::Socks5Stream;

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::{Ip6tOriginalDst, OriginalDst};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::time::sleep;
use tokio::{process::Command, spawn, task::JoinHandle};

use crate::command::CommandError;
use crate::commands::Commands;
use crate::firewall::{
    Firewall, FirewallConfig, FirewallError, FirewallListenerConfig, FirewallSubnetConfig,
};
use crate::network::Subnets;

pub struct Config {
    pub includes: Subnets,
    pub excludes: Subnets,
    pub remote: String,
    pub listen: Vec<SocketAddr>,
    pub socks_addr: SocketAddr,
}

#[derive(Debug)]
pub struct ClientError {
    message: String,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<FirewallError> for ClientError {
    fn from(err: FirewallError) -> Self {
        ClientError {
            message: format!("FirewallError: {err}"),
        }
    }
}

impl From<JoinError> for ClientError {
    fn from(err: JoinError) -> Self {
        ClientError {
            message: format!("JoinError: {err}"),
        }
    }
}

impl From<CommandError> for ClientError {
    fn from(err: CommandError) -> Self {
        ClientError {
            message: format!("CommandError: {err}"),
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError {
            message: format!("std::io::Error: {err}"),
        }
    }
}

impl From<mpsc::error::SendError<Message>> for ClientError {
    fn from(err: mpsc::error::SendError<Message>) -> Self {
        ClientError {
            message: format!("mpsc::error::SendError: {err}"),
        }
    }
}

// impl Debug for ParseError {}
impl Error for ClientError {}

pub async fn main(config: &Config) -> Result<(), ClientError> {
    let shutdown_commands = start_firewall(config).await?;

    let (ssh_tx, ssh_handle) = run_ssh(config).await?;

    let client = run_client(config);

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
    _ = ssh_tx.send(Message::Shutdown).await;

    println!("{:#?}", shutdown_commands);
    shutdown_commands.run_all().await?;

    log::info!("eeee");

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

#[derive(Debug)]
enum Message {
    Shutdown,
}

async fn run_ssh(
    config: &Config,
) -> Result<
    (
        mpsc::Sender<Message>,
        JoinHandle<Result<(), std::io::Error>>,
    ),
    ClientError,
> {
    let remote = config.remote.clone();
    let (tx, mut rx) = mpsc::channel(1);
    let socks = config.socks_addr;

    let tx_clone = tx.clone();
    let handle: JoinHandle<Result<(), std::io::Error>> = spawn(async move {
        let args = vec![
            "-D".to_string(),
            socks.to_string(),
            "-N".to_string(),
            remote.clone(),
        ];

        let mut child = Command::new("ssh").args(args).spawn()?;

        ctrlc::set_handler(move || {
            tx_clone
                .blocking_send(Message::Shutdown)
                .expect("Could not send signal on channel.")
        })
        .expect("Error setting Ctrl-C handler");

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

    Ok((tx, handle))
}

async fn start_firewall(config: &Config) -> Result<Commands, ClientError> {
    let familys = config
        .listen
        .iter()
        .map(|addr| match addr.ip() {
            IpAddr::V4(_) => FirewallListenerConfig::Ipv4(FirewallSubnetConfig {
                enable: true,
                port: addr.port(),
                includes: config.includes.ipv4(),
                excludes: config.excludes.ipv4(),
            }),
            IpAddr::V6(_) => FirewallListenerConfig::Ipv6(FirewallSubnetConfig {
                enable: true,
                port: addr.port(),
                includes: config.includes.ipv6(),
                excludes: config.excludes.ipv6(),
            }),
        })
        .collect();

    let firewall_config = FirewallConfig {
        filter_from_user: None,
        listeners: familys,
    };
    let firewall = crate::firewall::nat::NatFirewall::new();
    let commands = firewall.setup_firewall(&firewall_config)?;
    let shutdown_commands = firewall.restore_firewall(&firewall_config)?;
    println!("{:#?}", commands);
    commands.run_all().await?;

    Ok(shutdown_commands)
}

async fn run_client(config: &Config) -> Result<(), ClientError> {
    let socks_addr = config.socks_addr;
    let listen = config.listen.clone();
    for addr in listen {
        println!("listening on: {}", addr);
        let listener = TcpListener::bind(addr).await?;

        let _handle = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                println!("new connection from: {}", socket.peer_addr().unwrap());
                tokio::spawn(async move {
                    handle_tcp_client(socket, addr, socks_addr).await;
                });
            }
        });
    }

    loop {
        sleep(Duration::from_secs(60)).await;
    }
}

async fn handle_tcp_client(socket: TcpStream, addr: SocketAddr, socks_addr: SocketAddr) {
    let mut local = socket;

    let (addr, port) = match addr {
        SocketAddr::V4(_) => {
            let a = getsockopt(local.as_raw_fd(), OriginalDst).unwrap();
            (
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).to_string(),
                a.sin_port.to_be(),
            )
        }
        SocketAddr::V6(_) => {
            let a = getsockopt(local.as_raw_fd(), Ip6tOriginalDst).unwrap();
            let mut b = a.sin6_addr.s6_addr;
            let u16 = unsafe { std::slice::from_raw_parts_mut(b.as_mut_ptr() as *mut u8, 8) };
            for i in u16.iter_mut() {
                *i = i.to_be();
            }

            (Ipv6Addr::from(b).to_string(), a.sin6_port.to_be())
        }
    };
    println!("-----> target ip: [{addr}]:{port}");

    let mut remote_config = fast_socks5::client::Config::default();
    remote_config.set_skip_auth(false);
    let mut remote = Socks5Stream::connect(socks_addr, addr, port, remote_config)
        .await
        .unwrap();

    let result = copy_bidirectional(&mut local, &mut remote).await;
    // let result = my_bidirectional_copy(&mut local, &mut remote).await;

    log::info!("copy_bidirectional result: {:?}", result);
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
