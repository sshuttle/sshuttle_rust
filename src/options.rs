use clap::Parser;
use dns_lookup::getaddrinfo;
use regex::Match;
use std::{error::Error, fmt::Display, net::SocketAddr, str::FromStr};

const IPV6: i32 = 10;
const IPV4: i32 = 2;
const STREAM: i32 = 1;

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

#[derive(Debug)]
pub struct Subnet {
    pub family: i32,
    pub address: SocketAddr,
    pub cidr: u8,
    pub fport: Option<u16>,
    pub lport: Option<u16>,
}

fn parse_int<T: FromStr>(s: Match) -> Result<T, ParseError> {
    s.as_str().parse::<T>().map_err(|_| ParseError {
        message: format!("Could not parse '{}' as an integer", s.as_str()),
    })
}

#[derive(Debug)]
pub struct Subnets(Vec<Subnet>);

impl FromStr for Subnets {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rx = if s.matches(':').count() > 1 {
            r"^(?:\[?(?:\*\.)?([\w:]+)(?:/(\d+))?]?)(?::(\d+)(?:-(\d+))?)?$"
        } else {
            r"^((?:\*\.)?[\w\.\-]+)(?:/(\d+))?(?::(\d+)(?:-(\d+))?)?$"
        };

        let re = regex::Regex::new(rx).unwrap();
        let caps = re.captures(s).ok_or(ParseError {
            message: format!("Invalid subnet format: {}", s),
        })?;

        let host = caps[1].to_string();
        let cidr = caps.get(2).map(parse_int).transpose()?;
        let fport = caps.get(3).map(parse_int).transpose()?;
        let lport = caps.get(4).map(parse_int).transpose()?;

        let addrinfo: Vec<_> = getaddrinfo(Some(host.as_str()), None, None)
            .map_err(|err| ParseError {
                message: format!("Invalid hostname {host}: {err:?}"),
            })?
            .map(|x| x.unwrap())
            .filter(|a| a.socktype == STREAM)
            .collect();

        if let Some(cidr) = cidr {
            let addr_v6: Vec<_> = addrinfo.iter().filter(|a| a.address == IPV6).collect();
            let addr_v4: Vec<_> = addrinfo.iter().filter(|a| a.address == IPV4).collect();

            if !addr_v6.is_empty() && !addr_v4.is_empty() {
                return Err(ParseError {
                    message: format!(
                        "{host} has IPv4 and IPv6 addresses, so the mask \
                        of /{cidr} is not supported. Specify the IP \
                        addresses directly if you wish to specify \
                        a mask."
                    ),
                });
            }

            if addr_v6.len() > 1 || addr_v4.len() > 1 {
                println!(
                    "WARNING: {host} has multiple IP addresses. The \
                    mask of /{cidr} is applied to all of the addresses."
                );
            }
        }

        let rv: Vec<Subnet> = addrinfo
            .iter()
            .map(|a| {
                let max_cidr = if a.address == IPV4 { 32 } else { 128 };

                let cidr_to_use = match cidr {
                    Some(cidr) => cidr,
                    None => max_cidr,
                };

                if cidr_to_use > max_cidr {
                    return Err(ParseError {
                        message: format!(
                            "Invalid CIDR mask: {}. Valid CIDR masks \
                            are between 0 and {}.",
                            cidr_to_use, max_cidr
                        ),
                    });
                };

                Ok(Subnet {
                    family: a.address,
                    address: a.sockaddr,
                    cidr: cidr_to_use,
                    fport,
                    lport: lport.or(fport),
                })
            })
            .collect::<Result<_, ParseError>>()?;

        Ok(Subnets(rv))
    }
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Options {
    /// ssh hostname (and optional username and password) of remote server
    /// [USERNAME[:PASSWORD]@]ADDR[:PORT]
    #[clap(short, long, value_parser)]
    pub remote: String,

    /// capture and forward traffic to these subnets (whitespace separated)
    /// IP/MASK[:PORT[-PORT]]...
    pub subnets: Vec<Subnets>,
}

pub fn parse() -> Options {
    Options::parse()
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::options::*;

    #[test]
    fn test_parse_int() {
        let re = Regex::new("(.*)").unwrap();
        let caps = re.captures("123").unwrap().get(1).unwrap();
        assert_eq!(parse_int::<i32>(caps).unwrap(), 123);

        let re = Regex::new("(.*)").unwrap();
        let caps = re.captures("").unwrap().get(1).unwrap();
        assert!(matches!(parse_int::<i32>(caps), Err(_)));

        let re = Regex::new("(.*)").unwrap();
        let caps = re.captures("FOOD").unwrap().get(1).unwrap();
        assert!(matches!(parse_int::<i32>(caps), Err(_)));
    }

    const IP4_REPRS: [(&str, &str); 7] = [
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
        ("10.0", "10.0.0.0"),
        ("184.172.10.74", "184.172.10.74"),
        ("3098282570", "184.172.10.74"),
        ("0xb8.0xac.0x0a.0x4a", "184.172.10.74"),
        ("0270.0254.0012.0112", "184.172.10.74"),
    ];

    const IP4_SWIDTHS: [u8; 5] = [1, 8, 22, 27, 32];

    #[test]
    fn test_parse_subnetport_ip4() {
        for (s, ip4) in IP4_REPRS.into_iter() {
            let subnets = Subnets::from_str(s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV4);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].fport, None);
            assert_eq!(subnets.0[0].lport, None);
        }

        let s = "10.256.0.0";
        let subnets = Subnets::from_str(s);
        assert!(matches!(subnets, Err(_)));
    }

    #[test]
    fn test_parse_subnetport_ip4_with_mask() {
        for (s, ip4) in IP4_REPRS.into_iter() {
            for width in IP4_SWIDTHS {
                let s = format!("{s}/{width}");
                let subnets = Subnets::from_str(&s).unwrap();
                assert_eq!(subnets.0.len(), 1);
                assert_eq!(subnets.0[0].family, IPV4);
                assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
                assert_eq!(subnets.0[0].cidr, width);
                assert_eq!(subnets.0[0].fport, None);
                assert_eq!(subnets.0[0].lport, None);
            }
        }

        let s = "10.256.0.0";
        let subnets = Subnets::from_str(s);
        assert!(matches!(subnets, Err(_)));
    }

    #[test]
    fn test_parse_subnetport_ip4_with_port() {
        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV4);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(80));
        }

        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV4);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(90));
        }
    }

    #[test]
    fn test_parse_subnetport_ip4_with_port_and_mask() {
        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}/32:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV4);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(80));
        }

        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}/16:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV4);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 16);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(90));
        }
    }

    const IP6_REPRS: [(&str, &str); 4] = [
        ("::", "::"),
        ("::1", "::1"),
        ("fc00::", "fc00::"),
        ("2a01:7e00:e000:188::1", "2a01:7e00:e000:188::1"),
    ];

    const IP6_SWIDTHS: [u8; 5] = [48, 64, 96, 115, 128];

    #[test]
    fn test_parse_subnetport_ip6() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            let subnets = Subnets::from_str(s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV6);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].fport, None);
            assert_eq!(subnets.0[0].lport, None);
        }
    }

    #[test]
    fn test_parse_subnetport_ip6_with_mask() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            for width in IP6_SWIDTHS {
                let s = format!("{s}/{width}");
                let subnets = Subnets::from_str(&s).unwrap();
                assert_eq!(subnets.0.len(), 1);
                assert_eq!(subnets.0[0].family, IPV6);
                assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
                assert_eq!(subnets.0[0].cidr, width);
                assert_eq!(subnets.0[0].fport, None);
                assert_eq!(subnets.0[0].lport, None);
            }
        }

        let s = "10.256.0.0";
        let subnets = Subnets::from_str(s);
        assert!(matches!(subnets, Err(_)));
    }

    #[test]
    fn test_parse_subnetport_ip6_with_port() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}]:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV6);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(80));
        }

        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}]:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV6);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(90));
        }
    }

    #[test]
    fn test_parse_subnetport_ip6_with_port_and_mask() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}/128]:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV6);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(80));
        }

        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}/16]:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert_eq!(subnets.0[0].family, IPV6);
            assert_eq!(subnets.0[0].address.ip().to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 16);
            assert_eq!(subnets.0[0].fport, Some(80));
            assert_eq!(subnets.0[0].lport, Some(90));
        }
    }
}
