use crate::network::Ports;
use crate::network::SubnetFamily;
use crate::network::SubnetsFamily;

use super::{Commands, Firewall, FirewallConfig, FirewallError, FirewallFamilyConfig};

pub struct NatFirewall {}

impl NatFirewall {
    pub fn new() -> Self {
        NatFirewall {}
    }

    #[rustfmt::skip]
    fn setup_family<T: SubnetsFamily>(
        &self,
        config: &FirewallConfig,
        fconfig: &FirewallFamilyConfig<T>,
        commands: &mut Commands,
    ) -> Result<(), FirewallError> {
        let port = fconfig.port.to_string();
        let chain = format!("sshuttle-{}", port);
        let family = fconfig.family();

        macro_rules! ipt {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt(family, "nat", &v);
            };
        }

        macro_rules! ipt_vec {
            ( $e:expr ) => {
                let v = $e;
                commands.ipt(family, "nat", &v);
            };
        }

        macro_rules! ipm {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt(family, "mangle", &v);
            };
        }

        ipt!("-N", &chain);
        ipt!("-F", &chain);

        if let Some(user) = &config.filter_from_user {
            ipm!("-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", user, "-j", "MARK", "set-mark", &port);

            ipt!("-I", "OUTPUT", "1", "-m", "mark", "--mark", &port, "-j", &chain);
            ipt!("-I", "PREROUTING", "1", "-m", "mark","--mark", &port, "-j", &chain);
        } else {
            ipt!("-I", "OUTPUT", "1", "-j", &chain);
            ipt!("-I", "PREROUTING", "1", "-j", &chain);
        }

        ipt!("-A", &chain, "-j", "RETURN", "-m", "addrtype", "--dst-type", "LOCAL");

        for subnet in fconfig.excludes.iter() {
            let subnet_str = subnet.subnet_str();
            let ports: Vec<String> = match subnet.ports() {
                Ports::Single(port) => vec!["--dport".to_string(), port.to_string()],
                Ports::Range(fport,lport) => vec!["--dport".to_string(), format!("{fport}:{lport}")],
                Ports::None => vec![],
            };
            let mut ports = ports.iter().map(|p| p.as_str()).collect();
            let mut cmd = vec!["-A", &chain, "-j", "RETURN", "--dest", &subnet_str, "-p", "tcp"];
            cmd.append(&mut ports);
            ipt_vec!(cmd);
        }

        for subnet in fconfig.includes.iter() {
            let subnet_str = subnet.subnet_str();
            let ports: Vec<String> = match subnet.ports() {
                Ports::Single(port) => vec!["--dport".to_string(), port.to_string()],
                Ports::Range(fport,lport) => vec!["--dport".to_string(), format!("{fport}:{lport}")],
                Ports::None => vec![],
            };
            let mut ports = ports.iter().map(|p| p.as_str()).collect();
            let mut cmd = vec!["-A", &chain, "-j", "REDIRECT", "--dest", &subnet_str, "-p", "tcp"];
            cmd.append(&mut ports);
            cmd.append(&mut vec!["--to-ports", &port]);
            ipt_vec!(cmd);
        }

        Ok(())
    }

    #[rustfmt::skip]
    fn restore_family<T: SubnetsFamily>(
        &self,
        config: &FirewallConfig,
        fconfig: &FirewallFamilyConfig<T>,
        commands: &mut Commands,
    ) -> Result<(), FirewallError> {
        let port = fconfig.port.to_string();
        let chain = format!("sshuttle-{}", fconfig.port);
        let family = fconfig.family();

        macro_rules! ipt {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt_ignore_errors(family, "nat", &v);
            };
        }

        macro_rules! ipm {
            ( $( $e:expr),* ) => {
                let v = vec![ $( $e ),* ];
                commands.ipt_ignore_errors(family, "mangle", &v);
            };
        }

        if let Some(user) = &config.filter_from_user {
            ipm!("-D", "OUTPUT", "-m", "owner", "--uid-owner", user, "-j", "MARK", "--set-mark", &port);
            ipt!("-D", "OUTPUT", "-m", "mark", "--mark", &port, "-j", &chain);
            ipt!("-D", "PREROUTING", "1", "-m", "mark","--mark", &port, "-j", &chain);
        } else {
            ipt!("-D", "OUTPUT", "-j", &chain);
            ipt!("-D", "PREROUTING", "-j", &chain);
        }

        ipt!("-F", &chain);
        ipt!("-X", &chain);
        Ok(())
    }
}

impl Firewall for NatFirewall {
    fn setup_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError> {
        let mut commands: Commands = self.restore_firewall(config)?;

        for family in &config.familys {
            match family {
                super::FirewallAnyConfig::Ipv4(ip) => {
                    self.setup_family(config, ip, &mut commands)?
                }
                super::FirewallAnyConfig::Ipv6(ip) => {
                    self.setup_family(config, ip, &mut commands)?
                }
            }
        }

        Ok(commands)
    }
    fn restore_firewall(&self, config: &FirewallConfig) -> Result<Commands, FirewallError> {
        let mut commands: Commands = Commands::default();

        for family in &config.familys {
            match family {
                super::FirewallAnyConfig::Ipv4(ip) => {
                    self.restore_family(config, ip, &mut commands)?
                }
                super::FirewallAnyConfig::Ipv6(ip) => {
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
        let firewall = NatFirewall::new();
        let ipv4_family = FirewallFamilyConfig {
            enable: true,
            port: 1025,
            includes: "1.2.3.0/24:8000-9000".parse::<SubnetsV4>().unwrap(),
            excludes: "1.2.3.66:8080".parse::<SubnetsV4>().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            familys: vec![],
        };

        let expected_ipv4: [&str; 7] = [
            "iptables -w -t nat -N sshuttle-1025",
            "iptables -w -t nat -F sshuttle-1025",
            "iptables -w -t nat -I OUTPUT 1 -j sshuttle-1025",
            "iptables -w -t nat -I PREROUTING 1 -j sshuttle-1025",
            "iptables -w -t nat -A sshuttle-1025 -j RETURN -m addrtype --dst-type LOCAL",
            "iptables -w -t nat -A sshuttle-1025 -j RETURN --dest 1.2.3.66/32 -p tcp --dport 8080",
            "iptables -w -t nat -A sshuttle-1025 -j REDIRECT --dest 1.2.3.0/24 -p tcp --dport 8000:9000 --to-ports 1025",
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
        let firewall = NatFirewall::new();
        let ipv6_family = FirewallFamilyConfig {
            enable: true,
            port: 1024,
            includes: "2404:6800:4004:80c::/64".parse::<SubnetsV6>().unwrap(),
            excludes: "[2404:6800:4004:80c::101f]:80".parse().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            familys: vec![],
        };
        let expected_ipv6: [&str; 7] = [
            "ip6tables -w -t nat -N sshuttle-1024",
            "ip6tables -w -t nat -F sshuttle-1024",
            "ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-1024",
            "ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-1024",
            "ip6tables -w -t nat -A sshuttle-1024 -j RETURN -m addrtype --dst-type LOCAL",
            "ip6tables -w -t nat -A sshuttle-1024 -j RETURN --dest 2404:6800:4004:80c::101f/128 -p tcp --dport 80",
            "ip6tables -w -t nat -A sshuttle-1024 -j REDIRECT --dest 2404:6800:4004:80c::/64 -p tcp --to-ports 1024",
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
        let firewall = NatFirewall::new();
        let ipv4_family = FirewallFamilyConfig {
            enable: true,
            port: 1024,
            includes: "1.2.3.0/32".parse::<SubnetsV4>().unwrap(),
            excludes: "1.2.3.66".parse::<SubnetsV4>().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            familys: vec![],
        };

        let expected_ipv4: [&str; 4] = [
            "iptables -w -t nat -D OUTPUT -j sshuttle-1024",
            "iptables -w -t nat -D PREROUTING -j sshuttle-1024",
            "iptables -w -t nat -F sshuttle-1024",
            "iptables -w -t nat -X sshuttle-1024",
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
        let firewall = NatFirewall::new();
        let ipv6_family = FirewallFamilyConfig {
            enable: true,
            port: 1024,
            includes: "2404:6800:4004:80c::/64".parse::<SubnetsV6>().unwrap(),
            excludes: "[2404:6800:4004:80c::101f]:80".parse().unwrap(),
        };
        let config = FirewallConfig {
            filter_from_user: None,
            familys: vec![],
        };
        let expected_ipv6: [&str; 4] = [
            "ip6tables -w -t nat -D OUTPUT -j sshuttle-1024",
            "ip6tables -w -t nat -D PREROUTING -j sshuttle-1024",
            "ip6tables -w -t nat -F sshuttle-1024",
            "ip6tables -w -t nat -X sshuttle-1024",
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
