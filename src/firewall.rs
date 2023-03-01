use std::{net::SocketAddr, os::unix::prelude::AsRawFd};

use nix::{
    errno::Errno,
    libc::{sockaddr, sockaddr_in, sockaddr_in6},
    sys::socket::{
        getsockopt,
        sockopt::{Ip6tOriginalDst, OriginalDst},
        SockaddrIn, SockaddrIn6, SockaddrLike,
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

    #[error("Cannot get destination address")]
    CannotGetDstAddress,
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
    addr.ok_or(FirewallError::CannotGetDstAddress)
}

fn raw_to_socket_addr_v4(a: sockaddr_in) -> Option<SocketAddr> {
    let a_ptr: *const sockaddr = std::ptr::addr_of!(a).cast();
    let addr = unsafe { SockaddrIn::from_raw(a_ptr, None) };
    addr.map(|a| SocketAddr::V4(a.into()))
}

fn raw_to_socket_addr_v6(a: sockaddr_in6) -> Option<SocketAddr> {
    let a_ptr: *const sockaddr = std::ptr::addr_of!(a).cast();
    let addr = unsafe { SockaddrIn6::from_raw(a_ptr, None) };
    addr.map(|a| SocketAddr::V6(a.into()))
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
