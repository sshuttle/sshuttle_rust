use std::{error::Error, fmt::Display, process::ExitCode};

mod network;

mod client;
use client::Config;
use network::Subnets;

mod options;

mod command;
mod commands;

mod duration;

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

    let remote = opt.remote.to_string();

    let config = Config {
        includes,
        excludes,
        remote,
        listen: opt.listen.clone(),
        socks_addr: opt.socks,
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
