use std::{
    error::Error,
    fmt::{Display, Formatter},
    net::IpAddr,
    net::Ipv6Addr,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use dns_lookup::getaddrinfo;
use regex::Match;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

// fn parse_family(family: i32) -> Result<Family, NetworkError> {
//     match family {
//         IPV6 => Ok(Family::Ipv6),
//         IPV4 => Ok(Family::Ipv4),
//         _ => Err(NetworkError {
//             message: format!("Invalid family {}", family),
//         }),
//     }
// }

// const IPV6: i32 = 10;
// const IPV4: i32 = 2;
const STREAM: i32 = 1;

#[derive(Debug)]
pub struct NetworkParseError {
    message: String,
}

impl Display for NetworkParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for NetworkParseError {}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Ports {
    None,
    Single(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub address: IpAddr,
    pub cidr: u8,
    pub ports: Ports,
}

pub trait SubnetFamily {
    fn subnet_str(&self) -> String;
    fn ports(&self) -> Ports;
}

#[derive(Debug, Clone)]
pub struct SubnetV4 {
    pub address: Ipv4Addr,
    pub cidr: u8,
    pub ports: Ports,
}

impl SubnetFamily for SubnetV4 {
    fn subnet_str(&self) -> String {
        format!("{}/{}", self.address, self.cidr)
    }
    fn ports(&self) -> Ports {
        self.ports
    }
}

#[derive(Debug, Clone)]
pub struct SubnetV6 {
    pub address: Ipv6Addr,
    pub cidr: u8,
    pub ports: Ports,
}

impl SubnetFamily for SubnetV6 {
    fn subnet_str(&self) -> String {
        format!("{}/{}", self.address, self.cidr)
    }
    fn ports(&self) -> Ports {
        self.ports
    }
}

fn parse_int<T: FromStr>(s: Match) -> Result<T, NetworkParseError> {
    s.as_str().parse::<T>().map_err(|_| NetworkParseError {
        message: format!("Could not parse '{}' as an integer", s.as_str()),
    })
}

#[derive(Debug)]
pub struct Subnets(pub Vec<Subnet>);

#[derive(Debug, Default)]
pub struct SubnetsV4(pub Vec<SubnetV4>);

impl SubnetsV4 {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Default)]
pub struct SubnetsV6(pub Vec<SubnetV6>);

impl SubnetsV6 {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Subnets {
    pub fn new(subnets: Vec<Subnet>) -> Self {
        Subnets(subnets)
    }

    pub fn ipv4(&self) -> SubnetsV4 {
        let subnets: Vec<SubnetV4> = self
            .0
            .iter()
            .filter_map(|s| match s.address {
                IpAddr::V4(ip) => Some(SubnetV4 {
                    address: ip,
                    cidr: s.cidr,
                    ports: s.ports,
                }),
                _ => None,
            })
            .collect();
        SubnetsV4(subnets)
    }

    pub fn ipv6(&self) -> SubnetsV6 {
        let subnets: Vec<SubnetV6> = self
            .0
            .iter()
            .filter_map(|s| match s.address {
                IpAddr::V6(ip) => Some(SubnetV6 {
                    address: ip,
                    cidr: s.cidr,
                    ports: s.ports,
                }),
                _ => None,
            })
            .collect();
        SubnetsV6(subnets)
    }

    pub fn count_ipv4(&self) -> usize {
        self.ipv4().len()
    }
    pub fn count_ipv6(&self) -> usize {
        self.ipv6().len()
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromStr for Subnets {
    type Err = NetworkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rx = if s.matches(':').count() > 1 {
            r"^(?:\[?(?:\*\.)?([\w:]+)(?:/(\d+))?]?)(?::(\d+)(?:-(\d+))?)?$"
        } else {
            r"^((?:\*\.)?[\w\.\-]+)(?:/(\d+))?(?::(\d+)(?:-(\d+))?)?$"
        };

        let re = regex::Regex::new(rx).unwrap();
        let caps = re.captures(s).ok_or(NetworkParseError {
            message: format!("Invalid subnet format: {}", s),
        })?;

        let host = caps[1].to_string();
        let cidr = caps.get(2).map(parse_int).transpose()?;
        let fport = caps.get(3).map(parse_int).transpose()?;
        let lport = caps.get(4).map(parse_int).transpose()?;

        let addrinfo: Vec<_> = getaddrinfo(Some(host.as_str()), None, None)
            .map_err(|err| NetworkParseError {
                message: format!("Invalid hostname {host}: {err:?}"),
            })?
            .map(|x| x.unwrap())
            .filter(|a| a.socktype == STREAM)
            .collect();

        if let Some(cidr) = cidr {
            let addr_v6: Vec<_> = addrinfo.iter().filter(|a| a.sockaddr.is_ipv4()).collect();
            let addr_v4: Vec<_> = addrinfo.iter().filter(|a| a.sockaddr.is_ipv6()).collect();

            if !addr_v6.is_empty() && !addr_v4.is_empty() {
                return Err(NetworkParseError {
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
                let max_cidr = match a.sockaddr {
                    std::net::SocketAddr::V4(_) => 32,
                    std::net::SocketAddr::V6(_) => 128,
                };

                let cidr_to_use = match cidr {
                    Some(cidr) => cidr,
                    None => max_cidr,
                };

                if cidr_to_use > max_cidr {
                    return Err(NetworkParseError {
                        message: format!(
                            "Invalid CIDR mask: {}. Valid CIDR masks \
                            are between 0 and {}.",
                            cidr_to_use, max_cidr
                        ),
                    });
                };

                let ports = match (fport, lport) {
                    (None, None) => Ports::None,
                    (None, Some(port)) => Ports::Single(port),
                    (Some(port), None) => Ports::Single(port),
                    (Some(fport), Some(lport)) => Ports::Range(fport, lport),
                };

                Ok(Subnet {
                    address: a.sockaddr.ip(),
                    cidr: cidr_to_use,
                    ports,
                })
            })
            .collect::<Result<_, NetworkParseError>>()?;

        Ok(Subnets(rv))
    }
}

pub trait SubnetsFamily {
    type Subnet: SubnetFamily;
    fn family(&self) -> Family;
    fn iter(&self) -> std::slice::Iter<Self::Subnet>;
}

impl SubnetsFamily for SubnetsV4 {
    type Subnet = SubnetV4;

    fn family(&self) -> Family {
        Family::Ipv4
    }
    fn iter(&self) -> std::slice::Iter<Self::Subnet> {
        self.0.iter()
    }
}

impl FromStr for SubnetsV4 {
    type Err = NetworkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let subnets: Result<Vec<SubnetV4>, NetworkParseError> = Subnets::from_str(s)?
            .0
            .iter()
            .map(|s| match s.address {
                IpAddr::V4(ip) => Ok(SubnetV4 {
                    address: ip,
                    cidr: s.cidr,
                    ports: s.ports,
                }),
                _ => Err(NetworkParseError {
                    message: format!("Invalid family, expected IPv4: {:?}", s),
                }),
            })
            .collect();

        Ok(SubnetsV4(subnets?))
    }
}

impl SubnetsFamily for SubnetsV6 {
    type Subnet = SubnetV6;

    fn family(&self) -> Family {
        Family::Ipv6
    }

    fn iter(&self) -> std::slice::Iter<Self::Subnet> {
        self.0.iter()
    }
}

impl FromStr for SubnetsV6 {
    type Err = NetworkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let subnets: Result<Vec<SubnetV6>, NetworkParseError> = Subnets::from_str(s)?
            .0
            .iter()
            .map(|s| match s.address {
                IpAddr::V6(ip) => Ok(SubnetV6 {
                    address: ip,
                    cidr: s.cidr,
                    ports: s.ports,
                }),
                _ => Err(NetworkParseError {
                    message: format!("Invalid family, expected IPv6: {:?}", s),
                }),
            })
            .collect();

        Ok(SubnetsV6(subnets?))
    }
}

#[derive(Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone)]
pub struct ListenerAddr {
    pub protocol: Protocol,
    pub addr: SocketAddr,
}

impl ListenerAddr {
    pub fn ip(&self) -> IpAddr {
        self.addr.ip()
    }
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Display for ListenerAddr {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.addr)?;
        match self.protocol {
            Protocol::Tcp => write!(f, "/tcp"),
            Protocol::Udp => write!(f, "/udp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use regex::Regex;

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
            assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].ports, Ports::None);
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
                assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
                assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
                assert_eq!(subnets.0[0].cidr, width);
                assert_eq!(subnets.0[0].ports, Ports::None);
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
            assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].ports, Ports::Single(80));
        }

        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].ports, Ports::Range(80, 90));
        }
    }

    #[test]
    fn test_parse_subnetport_ip4_with_port_and_mask() {
        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}/32:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 32);
            assert_eq!(subnets.0[0].ports, Ports::Single(80));
        }

        for (s, ip4) in IP4_REPRS.into_iter() {
            let s = format!("{s}/16:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V4(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip4.to_string());
            assert_eq!(subnets.0[0].cidr, 16);
            assert_eq!(subnets.0[0].ports, Ports::Range(80, 90));
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
            assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].ports, Ports::None);
        }
    }

    #[test]
    fn test_parse_subnetport_ip6_with_mask() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            for width in IP6_SWIDTHS {
                let s = format!("{s}/{width}");
                let subnets = Subnets::from_str(&s).unwrap();
                assert_eq!(subnets.0.len(), 1);
                assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
                assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
                assert_eq!(subnets.0[0].cidr, width);
                assert_eq!(subnets.0[0].ports, Ports::None);
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
            assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].ports, Ports::Single(80));
        }

        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}]:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].ports, Ports::Range(80, 90));
        }
    }

    #[test]
    fn test_parse_subnetport_ip6_with_port_and_mask() {
        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}/128]:80");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 128);
            assert_eq!(subnets.0[0].ports, Ports::Single(80));
        }

        for (s, ip6) in IP6_REPRS.into_iter() {
            let s = format!("[{s}/16]:80-90");
            let subnets = Subnets::from_str(&s).unwrap();
            assert_eq!(subnets.0.len(), 1);
            assert!(matches!(subnets.0[0].address, IpAddr::V6(_)));
            assert_eq!(subnets.0[0].address.to_string(), ip6.to_string());
            assert_eq!(subnets.0[0].cidr, 16);
            assert_eq!(subnets.0[0].ports, Ports::Range(80, 90));
        }
    }
}
