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

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
    /// ssh hostname (and optional username and password) of remote server
    /// [USERNAME[:PASSWORD]@]ADDR[:PORT]
    #[clap(short, long, value_parser)]
    pub remote: String,

    /// transproxy to this ip address and port number
    #[clap(short, long, value_parser)]
    pub listen: Vec<SocketAddr>,

    /// capture and forward traffic to these subnets (whitespace separated)
    /// IP/MASK[:PORT[-PORT]]...
    pub include: Vec<Subnets>,

    //exclude this subnet (can be used more than once)
    #[clap(short, long)]
    pub exclude: Vec<Subnets>,
}

pub fn parse() -> Options {
    Options::parse()
}
