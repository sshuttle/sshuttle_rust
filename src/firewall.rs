use std::{error::Error, fmt::Display};

use crate::{
    commands::Commands,
    network::SubnetsV4,
    network::{Family, SubnetsFamily, SubnetsV6},
};

pub mod nat;

#[derive(Debug)]
pub struct FirewallError {
    message: String,
}

impl Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for FirewallError {}

pub trait Firewall {
    fn setup_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError>;
    fn restore_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError>;
}

pub struct FirewallFamilyConfig<T: SubnetsFamily> {
    pub enable: bool,
    pub port: u16,
    pub includes: T,
    pub excludes: T,
}

impl<T: SubnetsFamily> FirewallFamilyConfig<T> {
    pub fn family(&self) -> Family {
        self.includes.family()
    }
}

pub enum FirewallAnyConfig {
    Ipv4(FirewallFamilyConfig<SubnetsV4>),
    Ipv6(FirewallFamilyConfig<SubnetsV6>),
}

#[derive(Default)]
pub struct FirewallConfig {
    pub filter_from_user: Option<String>,
    pub familys: Vec<FirewallAnyConfig>,
}
