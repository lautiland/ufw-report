use std::net::IpAddr;
use std::str::FromStr;

use anyhow::Context;
use ipnet::IpNet;

/// CIDR ranges whose sources are excluded from findings and scores.
///
/// Allowlisted sources still appear in the raw data and in the coverage
/// counters; only the threat ranking ignores them.
#[derive(Debug, Clone, Default)]
pub(crate) struct Allowlist {
    nets: Vec<IpNet>,
}

impl Allowlist {
    pub(crate) fn parse(cidrs: &[String]) -> anyhow::Result<Self> {
        let mut nets = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let net = IpNet::from_str(cidr)
                .with_context(|| format!("Invalid allowlist CIDR: '{cidr}'"))?;
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub(crate) fn contains(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>()
            .is_ok_and(|address| self.nets.iter().any(|net| net.contains(&address)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_matches_ipv4_and_ipv6() {
        let allowlist =
            Allowlist::parse(&["192.0.2.0/24".to_string(), "2001:db8::/32".to_string()]).unwrap();

        assert!(allowlist.contains("192.0.2.10"));
        assert!(allowlist.contains("2001:db8::1"));
        assert!(!allowlist.contains("198.51.100.10"));
        assert!(!allowlist.contains("not-an-ip"));
    }

    #[test]
    fn test_empty_allowlist_never_matches() {
        let allowlist = Allowlist::default();
        assert!(!allowlist.contains("192.0.2.10"));
    }

    #[test]
    fn test_invalid_cidr_is_rejected() {
        assert!(Allowlist::parse(&["10.0.0.0/33".to_string()]).is_err());
    }
}
