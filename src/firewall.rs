use std::{
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
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::{
    commands::Commands,
    network::{Family, SubnetsFamily, SubnetsV6},
    network::{ListenerAddr, SubnetsV4},
};

pub mod nat;
pub mod tproxy;

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Errno error `{0}`")]
    Errno(#[from] Errno),

    #[error("IO Error `{0}`")]
    Io(#[from] std::io::Error),

    #[error("Not supported `{0}`")]
    NotSupported(String),
}

fn get_dst_addr_sockopt(s: &TcpStream) -> Result<SocketAddr, FirewallError> {
    let addr = match s.local_addr()? {
        SocketAddr::V4(_) => {
            let a = getsockopt(s.as_raw_fd(), OriginalDst)?;
            raw_to_socket_addr_v4(a)
        }
        SocketAddr::V6(_) => {
            let a = getsockopt(s.as_raw_fd(), Ip6tOriginalDst)?;
            raw_to_socket_addr_v6(a)
        }
    };
    Ok(addr)
}

fn raw_to_socket_addr_v4(a: libc::sockaddr_in) -> SocketAddr {
    let addr = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
    let port = a.sin_port.to_be();
    SocketAddr::new(IpAddr::V4(addr), port)
}

fn raw_to_socket_addr_v6(a: libc::sockaddr_in6) -> SocketAddr {
    let mut b = a.sin6_addr.s6_addr;
    let u16 = unsafe { std::slice::from_raw_parts_mut(b.as_mut_ptr().cast::<u8>(), 8) };
    for i in u16.iter_mut() {
        *i = i.to_be();
    }
    let addr = Ipv6Addr::from(b);
    let port = a.sin6_port.to_be();
    SocketAddr::new(IpAddr::V6(addr), port)
}

pub trait Firewall {
    fn setup_tcp_listener(&self, _l: &TcpListener) -> Result<(), FirewallError> {
        Ok(())
    }

    fn setup_udp_socket(&self, _l: &UdpSocket) -> Result<(), FirewallError> {
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
    pub listener: ListenerAddr,
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
