use crate::{command::Line, commands::Commands, network::Family};

impl Commands {
    pub fn ipt(&mut self, family: Family, table: &str, extra: &[&str]) {
        let cmd = match family {
            Family::Ipv4 => "iptables",
            Family::Ipv6 => "ip6tables",
        }
        .to_string();

        let mut args = vec!["-w", "-t", table];
        args.extend(extra);

        self.push(Line::new(cmd, args));
    }

    pub fn ipt_ignore_errors(&mut self, family: Family, table: &str, extra: &[&str]) {
        let cmd = match family {
            Family::Ipv4 => "iptables",
            Family::Ipv6 => "ip6tables",
        }
        .to_string();

        let mut args = vec!["-w", "-t", table];
        args.extend(extra);

        self.push_ignore_errors(Line::new(cmd, args));
    }
}
