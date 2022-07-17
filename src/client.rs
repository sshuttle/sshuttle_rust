use std::net::IpAddr;
use std::{error::Error, fmt::Display, net::SocketAddr};

use tokio::sync::mpsc;
use tokio::task::JoinError;
use tokio::{process::Command, spawn, task::JoinHandle};

use crate::command::CommandError;
use crate::firewall::{
    Firewall, FirewallAnyConfig, FirewallConfig, FirewallError, FirewallFamilyConfig,
};
use crate::network::Subnets;

pub struct Config {
    pub includes: Subnets,
    pub excludes: Subnets,
    pub remote: String,
    pub listen: Vec<SocketAddr>,
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

// impl Debug for ParseError {}
impl Error for ClientError {}

pub async fn main(config: &Config) -> Result<(), ClientError> {
    let remote = config.remote.clone();
    let (tx, mut rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);

    let handle: JoinHandle<Result<(), std::io::Error>> = spawn(async move {
        let args = vec![
            "-D".to_string(),
            "1025".to_string(),
            "-N".to_string(),
            remote.clone(),
        ];

        let mut child = Command::new("ssh").args(args).spawn()?;

        tokio::select! {
            None = rx.recv() => {
                log::info!("parent died, killing child ssh");
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

    let err = run_client(config).await;
    drop(tx);

    handle.await?.map_err(|err| ClientError {
        message: format!("ssh process error: {err:?}"),
    })?;

    err
}

async fn run_client(config: &Config) -> Result<(), ClientError> {
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

    let config = FirewallConfig {
        filter_from_user: None,
        familys,
    };
    let firewall = crate::firewall::nat::NatFirewall::new();
    let commands = firewall.setup_firewall(&config)?;
    println!("{:#?}", commands);
    commands.run_all().await?;

    Ok(())
}
