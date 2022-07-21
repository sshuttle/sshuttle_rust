use std::{
    error::Error,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::prelude::AsRawFd,
};

use nix::{
    errno::Errno,
    sys::socket::{
        getsockopt,
        sockopt::{Ip6tOriginalDst, OriginalDst},
    },
};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    commands::Commands,
    network::SubnetsV4,
    network::{Family, SubnetsFamily, SubnetsV6},
};

pub mod nat;
pub mod tproxy;

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

impl From<Errno> for FirewallError {
    fn from(err: Errno) -> Self {
        FirewallError {
            message: format!("Errno {}", err),
        }
    }
}

impl From<std::io::Error> for FirewallError {
    fn from(err: std::io::Error) -> Self {
        FirewallError {
            message: format!("std::io::Error: {}", err),
        }
    }
}

fn get_dst_addr_sockopt(s: &TcpStream) -> Result<SocketAddr, FirewallError> {
    let addr = match s.local_addr()? {
        SocketAddr::V4(_) => {
            let a = getsockopt(s.as_raw_fd(), OriginalDst).unwrap();
            let addr = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            let port = a.sin_port.to_be();
            SocketAddr::new(IpAddr::V4(addr), port)
        }
        SocketAddr::V6(_) => {
            let a = getsockopt(s.as_raw_fd(), Ip6tOriginalDst).unwrap();
            let mut b = a.sin6_addr.s6_addr;
            let u16 = unsafe { std::slice::from_raw_parts_mut(b.as_mut_ptr() as *mut u8, 8) };
            for i in u16.iter_mut() {
                *i = i.to_be();
            }

            let addr = Ipv6Addr::from(b);
            let port = a.sin6_port.to_be();
            SocketAddr::new(IpAddr::V6(addr), port)
        }
    };
    Ok(addr)
}

pub trait Firewall {
    fn setup_tcp_listener(&self, _l: &TcpListener) -> Result<(), FirewallError> {
        Ok(())
    }

    fn get_dst_addr(&self, s: &TcpStream) -> Result<SocketAddr, FirewallError> {
        get_dst_addr_sockopt(s)
    }

    fn setup_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError>;
    fn restore_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError>;
}

pub struct FirewallSubnetConfig<T: SubnetsFamily> {
    pub enable: bool,
    pub port: u16,
    pub includes: T,
    pub excludes: T,
}

impl<T: SubnetsFamily> FirewallSubnetConfig<T> {
    pub fn family(&self) -> Family {
        self.includes.family()
    }
}

pub enum FirewallListenerConfig {
    Ipv4(FirewallSubnetConfig<SubnetsV4>),
    Ipv6(FirewallSubnetConfig<SubnetsV6>),
}

#[derive(Default)]
pub struct FirewallConfig {
    pub filter_from_user: Option<String>,
    pub listeners: Vec<FirewallListenerConfig>,
}
