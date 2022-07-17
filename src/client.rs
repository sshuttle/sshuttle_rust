use std::net::IpAddr;
use std::os::unix::prelude::AsRawFd;
use std::{error::Error, fmt::Display, net::SocketAddr};

use fast_socks5::client::Socks5Stream;
use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::OriginalDst;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::{process::Command, spawn, task::JoinHandle};

use crate::command::CommandError;
use crate::commands::Commands;
use crate::firewall::{
    Firewall, FirewallAnyConfig, FirewallConfig, FirewallError, FirewallFamilyConfig,
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
    // let remote = config.remote.clone();
    // let (tx, mut rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);
    // let socks = config.socks_addr;

    // let handle: JoinHandle<Result<(), std::io::Error>> = spawn(async move {
    //     let args = vec![
    //         "-D".to_string(),
    //         socks.to_string(),
    //         "-N".to_string(),
    //         remote.clone(),
    //     ];

    //     let mut child = Command::new("ssh").args(args).spawn()?;

    //     tokio::select! {
    //         None = rx.recv() => {
    //             log::info!("parent died, killing child ssh");
    //             child.kill().await?;
    //             Ok(())
    //         }
    //         status = child.wait() => {
    //             match status {
    //                 Ok(rc) => {
    //                     if rc.success() {
    //                         log::error!("ssh exited with rc: {rc}");
    //                         Ok(())
    //                     } else {
    //                         log::info!("ssh exited with rc: {rc}");
    //                         Err(std::io::Error::new(std::io::ErrorKind::Other, "ssh failed"))
    //                     }
    //                 }
    //                 Err(err) => {
    //                     log::error!("ssh wait failed: {err}");
    //                     Err(err)
    //                 }
    //             }
    //         }
    //     }
    // });

    // let err = run_client(config).await;
    // drop(tx);

    // handle.await??;

    let shutdown_commands = start_firewall(config).await?;

    log::info!("aaaaaaaaaa");

    let (ssh_tx, ssh_handle) = run_ssh(config).await?;

    log::info!("bbbbb");

    let client = run_client(config);

    tokio::pin!(ssh_handle);
    tokio::pin!(client);

    // #[allow(unused_variables)]
    // let mut ssh_tx = Some(ssh_tx);

    // #[allow(unused_assignments)]
    // loop {
    log::info!("cccc");
    select! {
        res = &mut ssh_handle => {
            log::info!("ssh_handle finished");
            res??;
            // break;
        },
        res = &mut client => {
            log::info!("client finished");
            res?;
            // ssh_tx = None;
        },
        else => {
            log::info!("everything finished");
            // break;
        }
    }
    log::info!("cccc22222");
    // }

    // We don't care if the message fails, probably because ssh already exited.
    _ = ssh_tx.send(Message::Shutdown).await;
    log::info!("dddd {:?}", shutdown_commands);

    println!("-------> {:#?}", shutdown_commands);
    shutdown_commands.run_all().await?;

    log::info!("eeee");

    Ok(())
}

// async fn read(
//     stream: &mut Option<TcpStream>,
//     buf: &mut [u8],
// ) -> Option<Result<usize, std::io::Error>> {
//     if let Some(s) = stream {
//         Some(s.read(buf).await)
//     } else {
//         None
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

    // let err = run_client(config).await;
    // drop(tx);

    // handle.await??;

    // let wait = || {
    //     handle.
    // }
    // err
}

async fn start_firewall(config: &Config) -> Result<Commands, ClientError> {
    let familys = config
        .listen
        .iter()
        .map(|addr| match addr.ip() {
            IpAddr::V4(_) => FirewallAnyConfig::Ipv4(FirewallFamilyConfig {
                enable: true,
                port: addr.port(),
                includes: config.includes.ipv4(),
                excludes: config.excludes.ipv4(),
            }),
            IpAddr::V6(_) => FirewallAnyConfig::Ipv6(FirewallFamilyConfig {
                enable: true,
                port: addr.port(),
                includes: config.includes.ipv6(),
                excludes: config.excludes.ipv6(),
            }),
        })
        .collect();

    let firewall_config = FirewallConfig {
        filter_from_user: None,
        familys,
    };
    let firewall = crate::firewall::nat::NatFirewall::new();
    let commands = firewall.setup_firewall(&firewall_config)?;
    let shutdown_commands = firewall.restore_firewall(&firewall_config)?;
    println!("{:#?}", commands);
    commands.run_all().await?;

    Ok(shutdown_commands)
}

async fn run_client(config: &Config) -> Result<(), ClientError> {
    // let familys = config
    //     .listen
    //     .iter()
    //     .map(|addr| match addr.ip() {
    //         IpAddr::V4(_) => FirewallAnyConfig::Ipv4(FirewallFamilyConfig {
    //             enable: true,
    //             port: addr.port(),
    //             includes: config.includes.ipv4(),
    //             excludes: config.excludes.ipv4(),
    //         }),
    //         IpAddr::V6(_) => FirewallAnyConfig::Ipv6(FirewallFamilyConfig {
    //             enable: true,
    //             port: addr.port(),
    //             includes: config.includes.ipv6(),
    //             excludes: config.excludes.ipv6(),
    //         }),
    //     })
    //     .collect();

    // let firewall_config = FirewallConfig {
    //     filter_from_user: None,
    //     familys,
    // };
    // let firewall = crate::firewall::nat::NatFirewall::new();
    // let commands = firewall.setup_firewall(&firewall_config)?;
    // let shutdown_commands = firewall.restore_firewall(&firewall_config)?;
    // println!("{:#?}", commands);
    // commands.run_all().await?;

    let socks_addr = config.socks_addr;
    for addr in &config.listen {
        println!("listening on: {}", addr);
        let listener = TcpListener::bind(addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;
            println!("new connection: {}", socket.peer_addr()?);
            tokio::spawn(async move {
                let mut local = socket;
                let mut local_buf = [0; 1024];

                let target = getsockopt(local.as_raw_fd(), OriginalDst).unwrap();
                // let s: IpAddr = target.into();
                // let target_ip: String = inet_ntoa(&target.sin_addr).to_string();
                // println!("target ip: {}", target_ip);
                let target_port: u16 = target.sin_port;
                let mut remote_config = fast_socks5::client::Config::default();
                remote_config.set_skip_auth(true);

                let mut remote = Socks5Stream::connect(
                    socks_addr,
                    "195.201.220.110".to_string(),
                    target_port,
                    remote_config,
                )
                .await
                .unwrap();
                let mut remote_buf = [0; 1024];

                let mut shutdown_local: bool = false;
                let mut shutdown_remote: bool = false;

                loop {
                    select! {
                        res = local.read(&mut local_buf) => {
                            match res {
                                Ok(0) => {
                                    println!("local shutdown request");
                                    remote.shutdown().await.unwrap();
                                    shutdown_remote = true;
                                }
                                Ok(n) => {
                                    println!("local read: {}", n);
                                    remote.write_all(&local_buf[..n]).await.unwrap();
                                }
                                Err(err) => {
                                    println!("local read failed: {}", err);
                                    remote.shutdown().await.unwrap();
                                    shutdown_remote = true;
                                }
                            }
                        }
                        res = remote.read(&mut remote_buf) => {
                            match res {
                                Ok(0) => {
                                    println!("remote shutdown request");
                                    local.shutdown().await.unwrap();
                                    shutdown_local = true;
                                }
                                Ok(n) => {
                                    println!("local read: {}", n);
                                    local.write_all(&local_buf[..n]).await.unwrap();
                                }
                                Err(err) => {
                                    println!("local read failed: {}", err);
                                    local.shutdown().await.unwrap();
                                    shutdown_local = true;
                                }
                            }
                        }
                        else => {
                            break;
                        }
                    }

                    if shutdown_local && shutdown_remote {
                        break;
                    }
                }
            });
        }
    }

    // println!("{:#?}", shutdown_commands);
    // shutdown_commands.run_all().await?;
    Ok(())
}
