//! Address ranges for Tunnelik's own subnet triggers: `10.0.0.0/8`, `fd00::/64`, or a single
//! address. Plain Rust, so it is tested anywhere.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    addr: IpAddr,
    prefix: u8,
}

impl Subnet {
    /// Parses `addr/prefix`; a bare address is a range of one. Bits set past the prefix are
    /// refused rather than silently dropped, with the range the user probably meant.
    pub fn parse(text: &str) -> Result<Subnet, String> {
        let text = text.trim();
        let (host, prefix) = match text.split_once('/') {
            Some((host, prefix)) => (host, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = host
            .parse()
            .map_err(|_| format!("`{text}` is not a subnet; use one like 10.0.0.0/8"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| {
                    format!(
                        "`{text}` has a prefix length that is out of range; it goes up to /{max}"
                    )
                })?,
        };
        let subnet = Subnet { addr, prefix };
        let network = subnet.network();
        if network != addr {
            return Err(format!(
                "`{text}` has bits set past its prefix; did you mean {}?",
                Subnet {
                    addr: network,
                    prefix
                }
            ));
        }
        Ok(subnet)
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => mask4(u32::from(*a), self.prefix) == u32::from(net),
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                mask6(u128::from(*a), self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }

    fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(mask4(u32::from(a), self.prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(mask6(u128::from(a), self.prefix))),
        }
    }
}

fn mask4(bits: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask6(bits: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - u32::from(prefix)))
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_and_prints_canonically() {
        assert_eq!(
            Subnet::parse(" 10.0.0.0/8 ").unwrap().to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            Subnet::parse("192.168.11.0/24").unwrap().to_string(),
            "192.168.11.0/24"
        );
        assert_eq!(
            Subnet::parse("10.0.2.137").unwrap().to_string(),
            "10.0.2.137/32"
        );
        assert_eq!(Subnet::parse("0.0.0.0/0").unwrap().to_string(), "0.0.0.0/0");
        assert_eq!(Subnet::parse("fd00::/64").unwrap().to_string(), "fd00::/64");
        assert_eq!(Subnet::parse("fd00::1").unwrap().to_string(), "fd00::1/128");
    }

    #[test]
    fn contains_addresses_in_range_only() {
        let net = Subnet::parse("10.0.0.0/8").unwrap();
        assert!(net.contains(&ip("10.0.2.137")));
        assert!(net.contains(&ip("10.255.255.255")));
        assert!(!net.contains(&ip("11.0.0.1")));
        assert!(!net.contains(&ip("fd00::1")), "no mixing of families");
        let small = Subnet::parse("192.168.11.0/24").unwrap();
        assert!(small.contains(&ip("192.168.11.9")));
        assert!(!small.contains(&ip("192.168.12.9")));
        let one = Subnet::parse("10.0.2.137").unwrap();
        assert!(one.contains(&ip("10.0.2.137")));
        assert!(!one.contains(&ip("10.0.2.138")));
        let v6 = Subnet::parse("fd00::/64").unwrap();
        assert!(v6.contains(&ip("fd00::1234")));
        assert!(!v6.contains(&ip("fd00:0:0:1::1")));
        assert!(Subnet::parse("0.0.0.0/0").unwrap().contains(&ip("8.8.8.8")));
    }

    #[test]
    fn refuses_what_is_not_a_subnet() {
        for (bad, hint) in [
            ("", "not a subnet"),
            ("corp.example", "not a subnet"),
            ("10.0.0.0/33", "out of range"),
            ("10.0.0.0/x", "out of range"),
            ("fd00::/129", "out of range"),
            ("10.0.0.5/8", "did you mean 10.0.0.0/8?"),
            ("192.168.11.9/24", "did you mean 192.168.11.0/24?"),
        ] {
            let err = Subnet::parse(bad).unwrap_err();
            assert!(err.contains(hint), "{bad}: {err}");
        }
    }
}
