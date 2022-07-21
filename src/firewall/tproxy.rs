use std::os::unix::prelude::AsRawFd;

use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt::IpTransparent;
use tokio::net::TcpListener;

use crate::network::Ports;
use crate::network::SubnetFamily;
use crate::network::SubnetsFamily;

use super::GetDstAddrMethod;
use super::{Commands, Firewall, FirewallConfig, FirewallError, FirewallSubnetConfig};

pub struct TProxyFirewall {}

impl TProxyFirewall {
    pub fn new() -> Self {
        TProxyFirewall {}
    }

    #[rustfmt::skip]
    fn setup_family<T: SubnetsFamily>(
        &self,
        config: &FirewallConfig,
        fconfig: &FirewallSubnetConfig<T>,
        commands: &mut Commands,
    ) -> Result<(), FirewallError> {
        let port = fconfig.port.to_string();
        let mark_chain = format!("sshuttle-m-{}", port);
        let tproxy_chain = format!("sshuttle-t-{}", port);
        let divert_chain = format!("sshuttle-d-{}", port);
        let family = fconfig.family();
        // FIXME
        let tmark = "0x01";

        macro_rules! ipm {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt(family, "mangle", &v);
            };
        }

        macro_rules! ipm_vec {
            ( $e:expr ) => {
                let v = $e;
                commands.ipt(family, "mangle", &v);
            };
        }

        ipm!("-N", &mark_chain);
        ipm!("-F", &mark_chain);
        ipm!("-N", &divert_chain);
        ipm!("-F", &divert_chain);
        ipm!("-N", &tproxy_chain);
        ipm!("-F", &tproxy_chain);

        if let Some(user) = &config.filter_from_user {
            ipm!("-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", user, "-j", "MARK", "set-mark", &port);

            ipm!("-I", "OUTPUT", "1", "-m", "mark", "--mark", &port, "-j", &mark_chain);
            ipm!("-I", "PREROUTING", "1", "-m", "mark","--mark", &port, "-j", &tproxy_chain);
        } else {
            ipm!("-I", "OUTPUT", "1", "-j", &mark_chain);
            ipm!("-I", "PREROUTING", "1", "-j", &tproxy_chain);
        }

        ipm!("-A", &mark_chain, "-j", "RETURN", "-m", "addrtype", "--dst-type", "LOCAL");
        ipm!("-A", &tproxy_chain, "-j", "RETURN", "-m", "addrtype", "--dst-type", "LOCAL");

        ipm!("-A", &divert_chain, "-j", "MARK", "--set-mark", tmark);
        ipm!("-A", &divert_chain, "-j", "ACCEPT");
        ipm!("-A", &tproxy_chain, "-m", "socket", "-j", &divert_chain, "-m", "tcp", "-p", "tcp");

        for subnet in fconfig.excludes.iter() {
            let subnet_str = subnet.subnet_str();
            let ports: Vec<String> = match subnet.ports() {
                Ports::Single(port) => vec!["--dport".to_string(), port.to_string()],
                Ports::Range(fport,lport) => vec!["--dport".to_string(), format!("{fport}:{lport}")],
                Ports::None => vec![],
            };
            let ports: Vec<_> = ports.iter().map(|p| p.as_str()).collect();

            {
                let mut cmd = vec!["-A", &mark_chain, "-j", "RETURN", "--dest", &subnet_str, "-m", "tcp", "-p", "tcp"];
                cmd.extend(ports.iter());
                ipm_vec!(cmd);
            }

            {
                let mut cmd = vec!["-A", &tproxy_chain, "-j", "RETURN", "--dest", &subnet_str, "-m", "tcp", "-p", "tcp"];
                cmd.extend(ports.iter());
                ipm_vec!(cmd);
            }
        }

        for subnet in fconfig.includes.iter() {
            let subnet_str = subnet.subnet_str();
            let ports: Vec<String> = match subnet.ports() {
                Ports::Single(port) => vec!["--dport".to_string(), port.to_string()],
                Ports::Range(fport,lport) => vec!["--dport".to_string(), format!("{fport}:{lport}")],
                Ports::None => vec![],
            };
            let ports: Vec<_> = ports.iter().map(|p| p.as_str()).collect();

            {
                let mut cmd = vec!["-A", &mark_chain, "-j", "MARK", "--set-mark", tmark, "--dest", &subnet_str, "-m", "tcp", "-p", "tcp"];
                cmd.extend(ports.iter());
                ipm_vec!(cmd);
            }

            {
                let mut cmd = vec!["-A", &tproxy_chain, "-j", "TPROXY", "--tproxy-mark", tmark, "--dest", &subnet_str, "-m", "tcp", "-p", "tcp", "--on-port", &port];
                cmd.extend(ports.iter());
                ipm_vec!(cmd);
            }
        }


        Ok(())
    }

    #[rustfmt::skip]
    fn restore_family<T: SubnetsFamily>(
        &self,
        config: &FirewallConfig,
        fconfig: &FirewallSubnetConfig<T>,
        commands: &mut Commands,
    ) -> Result<(), FirewallError> {
        let port = fconfig.port.to_string();
        let mark_chain = format!("sshuttle-m-{}", port);
        let tproxy_chain = format!("sshuttle-t-{}", port);
        let divert_chain = format!("sshuttle-d-{}", port);
        let family = fconfig.family();


        macro_rules! ipm {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt_ignore_errors(family, "mangle", &v);
            };
        }

        if let Some(user) = &config.filter_from_user {
            ipm!("-D", "OUTPUT", "-m", "owner", "--uid-owner", user, "-j", "MARK", "--set-mark", &port);
            ipm!("-D", "OUTPUT", "-m", "mark", "--mark", &port, "-j", &mark_chain);
            ipm!("-D", "PREROUTING", "1", "-m", "mark", "--mark", &port, "-j", &tproxy_chain);
        } else {
            ipm!("-D", "OUTPUT", "-j", &mark_chain);
            ipm!("-D", "PREROUTING", "-j", &tproxy_chain);
        }

        ipm!("-F", &mark_chain);
        ipm!("-X", &mark_chain);

        ipm!("-F", &tproxy_chain);
        ipm!("-X", &tproxy_chain);

        ipm!("-F", &divert_chain);
        ipm!("-X", &divert_chain);

        Ok(())
    }
}

impl Firewall for TProxyFirewall {
    fn setup_tcp_listener(&self, l: &TcpListener) -> Result<(), FirewallError> {
        setsockopt(l.as_raw_fd(), IpTransparent, &true)?;

        Ok(())
    }

    fn get_dst_addr_method(&self) -> GetDstAddrMethod {
        GetDstAddrMethod::SockName
    }

    fn setup_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError> {
        let mut commands: Commands = self.restore_firewall(config)?;

        for family in &config.listeners {
            match family {
                super::FirewallListenerConfig::Ipv4(ip) => {
                    self.setup_family(config, ip, &mut commands)?
                }
                super::FirewallListenerConfig::Ipv6(ip) => {
                    self.setup_family(config, ip, &mut commands)?
                }
            }
        }

        Ok(commands)
    }
    fn restore_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError> {
        let mut commands: Commands = Commands::default();

        for family in &config.listeners {
            match family {
                super::FirewallListenerConfig::Ipv4(ip) => {
                    self.restore_family(config, ip, &mut commands)?
                }
                super::FirewallListenerConfig::Ipv6(ip) => {
                    self.restore_family(config, ip, &mut commands)?
                }
            }
        }

        Ok(commands)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        command::CommandLine,
        network::{SubnetsV4, SubnetsV6},
    };

    use super::*;

    #[test]
    fn test_setup_family_v4() {
        let firewall = TProxyFirewall::new();
        let ipv4_family = FirewallSubnetConfig {
            enable: true,
            port: 1024,
            includes: "1.2.3.0/24:8000-9000".parse::<SubnetsV4>().unwrap(),
            excludes: "1.2.3.66:8080".parse::<SubnetsV4>().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            listeners: vec![],
        };

        let expected_ipv4: [&str; 17] = [
            "iptables -w -t mangle -N sshuttle-m-1024",
            "iptables -w -t mangle -F sshuttle-m-1024",
            "iptables -w -t mangle -N sshuttle-d-1024",
            "iptables -w -t mangle -F sshuttle-d-1024",
            "iptables -w -t mangle -N sshuttle-t-1024",
            "iptables -w -t mangle -F sshuttle-t-1024",
            "iptables -w -t mangle -I OUTPUT 1 -j sshuttle-m-1024",
            "iptables -w -t mangle -I PREROUTING 1 -j sshuttle-t-1024",
            "iptables -w -t mangle -A sshuttle-m-1024 -j RETURN -m addrtype --dst-type LOCAL",
            "iptables -w -t mangle -A sshuttle-t-1024 -j RETURN -m addrtype --dst-type LOCAL",
            "iptables -w -t mangle -A sshuttle-d-1024 -j MARK --set-mark 0x01",
            "iptables -w -t mangle -A sshuttle-d-1024 -j ACCEPT",
            "iptables -w -t mangle -A sshuttle-t-1024 -m socket -j sshuttle-d-1024 -m tcp -p tcp",
            // "iptables -w -t mangle -A sshuttle-t-1024 -m socket -j sshuttle-d-1024 -m udp -p udp",
            // "iptables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 1.2.3.33/32 -m udp -p udp --dport 53",
            // "iptables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 1.2.3.33/32 -m udp -p udp --dport 53 --on-port 1027",
            "iptables -w -t mangle -A sshuttle-m-1024 -j RETURN --dest 1.2.3.66/32 -m tcp -p tcp --dport 8080",
            "iptables -w -t mangle -A sshuttle-t-1024 -j RETURN --dest 1.2.3.66/32 -m tcp -p tcp --dport 8080",
            // "iptables -w -t mangle -A sshuttle-m-1024 -j RETURN --dest 1.2.3.66/32 -m udp -p udp --dport 8080",
            // "iptables -w -t mangle -A sshuttle-t-1024 -j RETURN --dest 1.2.3.66/32 -m udp -p udp --dport 8080",
            "iptables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 1.2.3.0/24 -m tcp -p tcp --dport 8000:9000",
            "iptables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 1.2.3.0/24 -m tcp -p tcp --on-port 1024 --dport 8000:9000",
            // "iptables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 1.2.3.0/24 -m udp -p udp --dport 8000:9000",
            // "iptables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 1.2.3.0/24 -m udp -p udp --on-port 1024 --dport 8000:9000",
        ];

        let mut commands = Commands::default();
        firewall
            .setup_family(&config, &ipv4_family, &mut commands)
            .unwrap();
        assert_eq!(commands.len(), expected_ipv4.len());
        for (command, expected_line) in commands.iter().zip(expected_ipv4.iter()) {
            let split: Vec<String> = expected_line.split(' ').map(|s| s.to_owned()).collect();
            let expected_command = CommandLine(split[0].clone(), split[1..].to_vec());
            assert_eq!(command.line, expected_command);
        }
    }

    #[test]
    fn test_setup_family_v6() {
        let firewall = TProxyFirewall::new();
        let ipv6_family = FirewallSubnetConfig {
            enable: true,
            port: 1024,
            includes: "[2404:6800:4004:80c::/64]:8000-9000"
                .parse::<SubnetsV6>()
                .unwrap(),
            excludes: "[2404:6800:4004:80c::101f]:8080".parse().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            listeners: vec![],
        };
        let expected_ipv6: [&str; 17] = [
            "ip6tables -w -t mangle -N sshuttle-m-1024",
            "ip6tables -w -t mangle -F sshuttle-m-1024",
            "ip6tables -w -t mangle -N sshuttle-d-1024",
            "ip6tables -w -t mangle -F sshuttle-d-1024",
            "ip6tables -w -t mangle -N sshuttle-t-1024",
            "ip6tables -w -t mangle -F sshuttle-t-1024",
            "ip6tables -w -t mangle -I OUTPUT 1 -j sshuttle-m-1024",
            "ip6tables -w -t mangle -I PREROUTING 1 -j sshuttle-t-1024",
            "ip6tables -w -t mangle -A sshuttle-m-1024 -j RETURN -m addrtype --dst-type LOCAL",
            "ip6tables -w -t mangle -A sshuttle-t-1024 -j RETURN -m addrtype --dst-type LOCAL",
            "ip6tables -w -t mangle -A sshuttle-d-1024 -j MARK --set-mark 0x01",
            "ip6tables -w -t mangle -A sshuttle-d-1024 -j ACCEPT",
            "ip6tables -w -t mangle -A sshuttle-t-1024 -m socket -j sshuttle-d-1024 -m tcp -p tcp",
            // "ip6tables -w -t mangle -A sshuttle-t-1024 -m socket -j sshuttle-d-1024 -m udp -p udp",
            // "ip6tables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 2404:6800:4004:80c::33/32 -m udp -p udp --dport 53",
            // "ip6tables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 2404:6800:4004:80c::33/32 -m udp -p udp --dport 53 --on-port 1026",
            "ip6tables -w -t mangle -A sshuttle-m-1024 -j RETURN --dest 2404:6800:4004:80c::101f/128 -m tcp -p tcp --dport 8080",
            "ip6tables -w -t mangle -A sshuttle-t-1024 -j RETURN --dest 2404:6800:4004:80c::101f/128 -m tcp -p tcp --dport 8080",
            // "ip6tables -w -t mangle -A sshuttle-m-1024 -j RETURN --dest 2404:6800:4004:80c::101f/128 -m udp -p udp --dport 8080",
            // "ip6tables -w -t mangle -A sshuttle-t-1024 -j RETURN --dest 2404:6800:4004:80c::101f/128 -m udp -p udp --dport 8080",
            "ip6tables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 2404:6800:4004:80c::/64 -m tcp -p tcp --dport 8000:9000",
            "ip6tables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 2404:6800:4004:80c::/64 -m tcp -p tcp --on-port 1024 --dport 8000:9000",
            // "ip6tables -w -t mangle -A sshuttle-m-1024 -j MARK --set-mark 0x01 --dest 2404:6800:4004:80c::/64 -m udp -p udp --dport 8000:9000",
            // "ip6tables -w -t mangle -A sshuttle-t-1024 -j TPROXY --tproxy-mark 0x01 --dest 2404:6800:4004:80c::/64 -m udp -p udp --on-port 102 --dport 8000:9000",
        ];
        let mut commands = Commands::default();
        firewall
            .setup_family(&config, &ipv6_family, &mut commands)
            .unwrap();
        assert_eq!(commands.len(), expected_ipv6.len());
        for (command, expected_line) in commands.iter().zip(expected_ipv6.iter()) {
            let split: Vec<String> = expected_line.split(' ').map(|s| s.to_owned()).collect();
            let expected_command = CommandLine(split[0].clone(), split[1..].to_vec());
            assert_eq!(command.line, expected_command);
        }
    }

    #[test]
    fn test_restore_family_v4() {
        let firewall = TProxyFirewall::new();
        let ipv4_family = FirewallSubnetConfig {
            enable: true,
            port: 1024,
            includes: "1.2.3.0/32".parse::<SubnetsV4>().unwrap(),
            excludes: "1.2.3.66".parse::<SubnetsV4>().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            listeners: vec![],
        };

        let expected_ipv4: [&str; 8] = [
            "iptables -w -t mangle -D OUTPUT -j sshuttle-m-1024",
            "iptables -w -t mangle -D PREROUTING -j sshuttle-t-1024",
            "iptables -w -t mangle -F sshuttle-m-1024",
            "iptables -w -t mangle -X sshuttle-m-1024",
            "iptables -w -t mangle -F sshuttle-t-1024",
            "iptables -w -t mangle -X sshuttle-t-1024",
            "iptables -w -t mangle -F sshuttle-d-1024",
            "iptables -w -t mangle -X sshuttle-d-1024",
        ];

        let mut commands = Commands::default();
        firewall
            .restore_family(&config, &ipv4_family, &mut commands)
            .unwrap();
        assert_eq!(commands.len(), expected_ipv4.len());
        for (command, expected_line) in commands.iter().zip(expected_ipv4.iter()) {
            let split: Vec<String> = expected_line.split(' ').map(|s| s.to_owned()).collect();
            let expected_command = CommandLine(split[0].clone(), split[1..].to_vec());
            assert_eq!(command.line, expected_command);
        }
    }

    #[test]
    fn test_restore_family_v6() {
        let firewall = TProxyFirewall::new();
        let ipv6_family = FirewallSubnetConfig {
            enable: true,
            port: 1024,
            includes: "2404:6800:4004:80c::/64".parse::<SubnetsV6>().unwrap(),
            excludes: "[2404:6800:4004:80c::101f]:80".parse().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            listeners: vec![],
        };
        let expected_ipv6: [&str; 8] = [
            "ip6tables -w -t mangle -D OUTPUT -j sshuttle-m-1024",
            "ip6tables -w -t mangle -D PREROUTING -j sshuttle-t-1024",
            "ip6tables -w -t mangle -F sshuttle-m-1024",
            "ip6tables -w -t mangle -X sshuttle-m-1024",
            "ip6tables -w -t mangle -F sshuttle-t-1024",
            "ip6tables -w -t mangle -X sshuttle-t-1024",
            "ip6tables -w -t mangle -F sshuttle-d-1024",
            "ip6tables -w -t mangle -X sshuttle-d-1024",
        ];

        let mut commands = Commands::default();
        firewall
            .restore_family(&config, &ipv6_family, &mut commands)
            .unwrap();
        assert_eq!(commands.len(), expected_ipv6.len());
        for (command, expected_line) in commands.iter().zip(expected_ipv6.iter()) {
            let split: Vec<String> = expected_line.split(' ').map(|s| s.to_owned()).collect();
            let expected_command = CommandLine(split[0].clone(), split[1..].to_vec());
            assert_eq!(command.line, expected_command);
        }
    }
}
