// #![warn(missing_docs)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::use_self)]
#![allow(clippy::unused_self)]

use std::{error::Error, fmt::Display, process::ExitCode};

mod network;

mod client;
use client::Config;
use network::{ListenerAddr, Subnets};

mod options;

mod command;
mod commands;

mod firewall;

mod linux;

#[derive(Clone, Debug)]
pub struct ConfigError {
    message: String,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// impl Debug for ParseError {}
impl Error for ConfigError {}

fn options_to_config(opt: &options::Options) -> Result<Config, ConfigError> {
    let includes = {
        let mut includes = Vec::new();
        for list1 in &opt.include {
            let inner_list = &list1.0;
            includes.extend(inner_list.iter().cloned());
        }
        Subnets::new(includes)
    };

    let excludes = {
        let mut excludes = Vec::new();
        for list2 in &opt.exclude {
            let inner_list = &list2.0;
            excludes.extend(inner_list.iter().cloned());
        }
        Subnets::new(excludes)
    };

    if opt.include.is_empty() {
        return Err(ConfigError {
            message: "No subnets specified".to_string(),
        });
    }

    let num_ipv4_listen = opt.listen.iter().filter(|l| l.is_ipv4()).count();
    if num_ipv4_listen > 1 {
        return Err(ConfigError {
            message: "Multiple IPv4 listeners specified".to_string(),
        });
    }

    let num_ipv6_listen = opt.listen.iter().filter(|l| l.is_ipv6()).count();
    if num_ipv6_listen > 1 {
        return Err(ConfigError {
            message: "Multiple IPv6 listeners specified".to_string(),
        });
    }

    if num_ipv4_listen == 0 && num_ipv6_listen == 0 {
        return Err(ConfigError {
            message: "No IPv4 or IPv6 listeners specified".to_string(),
        });
    }

    let ipv4_includes = includes.count_ipv4();
    let ipv4_excludes = excludes.count_ipv4();
    let ipv6_includes = includes.count_ipv6();
    let ipv6_excludes = excludes.count_ipv6();

    if (ipv4_includes > 0 || ipv4_excludes > 0) && num_ipv4_listen == 0 {
        return Err(ConfigError {
            message: "IPv4 subnets supplied but not enabled".to_string(),
        });
    }

    if (ipv6_includes > 0 || ipv6_excludes > 0) && num_ipv6_listen == 0 {
        return Err(ConfigError {
            message: "IPv6 subnets supplied but not enabled".to_string(),
        });
    }

    let remote = opt.remote.clone();

    let listen = {
        let mut listen = Vec::new();

        opt.listen
            .iter()
            .map(|l| ListenerAddr {
                addr: *l,
                protocol: network::Protocol::Tcp,
            })
            .for_each(|l| listen.push(l));

        listen
    };

    let config = Config {
        includes,
        excludes,
        remote,
        listen,
        socks_addr: opt.socks,
        firewall: opt.firewall,
    };

    Ok(config)
}

async fn run_client() -> Result<(), Box<dyn Error>> {
    let opt = options::parse();
    let config = options_to_config(&opt)?;
    client::main(&config).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    match run_client().await {
        Ok(()) => {
            log::info!("Exiting normally");
            ExitCode::SUCCESS
        }
        Err(err) => {
            log::error!("Exiting with error: {}", err);
            ExitCode::FAILURE
        }
    }
}
