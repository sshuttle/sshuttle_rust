use crate::{command::CommandLine, commands::Commands, network::Family};

impl Commands {
    pub fn ipt(&mut self, family: Family, table: &str, extra: &[&str]) {
        let cmd = match family {
            Family::Ipv4 => "iptables",
            Family::Ipv6 => "ip6tables",
        }
        .to_string();

        let mut args = vec!["-w".to_string(), "-t".to_string(), table.to_string()];
        let iter = extra.iter().map(ToString::to_string);
        args.extend(iter);

        self.push(CommandLine(cmd, args));
    }

    pub fn ipt_ignore_errors(&mut self, family: Family, table: &str, extra: &[&str]) {
        let cmd = match family {
            Family::Ipv4 => "iptables",
            Family::Ipv6 => "ip6tables",
        }
        .to_string();

        let mut args = vec!["-w".to_string(), "-t".to_string(), table.to_string()];
        let iter = extra.iter().map(ToString::to_string);
        args.extend(iter);

        self.push_ignore_errors(CommandLine(cmd, args));
    }
}
