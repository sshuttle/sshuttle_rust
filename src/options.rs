use clap::Parser;
use std::{error::Error, fmt::Display, net::SocketAddr};

use crate::network::Subnets;

#[derive(Debug)]
pub struct ParseError {
    message: String,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// impl Debug for ParseError {}
impl Error for ParseError {}

#[derive(Clone, clap::ArgEnum, Debug, Copy)]
pub enum FirewallType {
    Nat,
    #[clap(name = "tproxy")]
    TProxy,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
    /// ssh hostname (and optional username and password) of remote server
    /// [USERNAME[:PASSWORD]@]ADDR[:PORT]
    #[clap(short, long, value_parser)]
    pub remote: Option<String>,

    /// transproxy to this ip address and port number
    ///
    /// Maybe used twice, once for IPv4 and once for IPv6.
    #[clap(short, long, value_parser)]
    pub listen: Vec<SocketAddr>,

    /// Capture and forward traffic to these subnets (whitespace separated)
    /// IP/MASK[:PORT[-PORT]]...
    pub include: Vec<Subnets>,

    /// Exclude this subnet (can be used more than once)
    #[clap(short, long)]
    pub exclude: Vec<Subnets>,

    /// Exclude this subnet (can be used more than once)
    #[clap(short, long, default_value = "127.0.0.1:1080")]
    pub socks: SocketAddr,

    /// What kind of firewall to use
    #[clap(short, long, arg_enum, default_value_t = FirewallType::Nat)]
    pub firewall: FirewallType,

    /// Enable UDP support
    #[clap(short, long)]
    pub udp: bool,
}

pub fn parse() -> Options {
    Options::parse()
}
