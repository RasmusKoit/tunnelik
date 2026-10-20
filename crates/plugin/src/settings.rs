//! Turns a WireGuard config into the values Windows needs to bring the VPN interface up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wgconf::{Config, Endpoint, Interface, IpNet, Peer};

/// Same default as the official WireGuard clients.
pub const DEFAULT_MTU: u16 = 1420;
/// Encrypted packets are the inner packet plus 32 bytes; leave some slack.
pub const FRAME_OVERHEAD: u32 = 64;
/// Unique local address for tunnels without IPv6 (fd77:6731:3100::/48, picked at random).
pub const PLACEHOLDER_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0x6731, 0x3100, 0, 0, 0, 0, 1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSettings {
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub ipv6_addresses: Vec<Ipv6Addr>,
    /// Networks routed into the tunnel, from the peer's AllowedIPs.
    pub ipv4_routes: Vec<(Ipv4Addr, u8)>,
    pub ipv6_routes: Vec<(Ipv6Addr, u8)>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: u32,
    pub max_frame_size: u32,
    pub endpoint: Endpoint,
}

/// The parts of a config the plugin works with.
pub struct TunnelSetup<'a> {
    pub interface: &'a Interface,
    pub peer: &'a Peer,
    pub settings: ChannelSettings,
}

pub fn from_config(config: &Config) -> Result<TunnelSetup<'_>, String> {
    let [peer] = config.peers.as_slice() else {
        return Err("only one [Peer] per tunnel is supported".into());
    };
    let endpoint = peer.endpoint.clone().ok_or("[Peer] is missing Endpoint")?;
    let interface = &config.interface;

    let mut settings = ChannelSettings {
        ipv4_addresses: Vec::new(),
        ipv6_addresses: Vec::new(),
        ipv4_routes: Vec::new(),
        ipv6_routes: Vec::new(),
        dns_servers: interface.dns_servers.clone(),
        dns_search: interface.dns_search.clone(),
        mtu: interface.mtu.unwrap_or(DEFAULT_MTU).into(),
        max_frame_size: 0,
        endpoint,
    };
    settings.max_frame_size = settings.mtu + FRAME_OVERHEAD;

    for address in &interface.addresses {
        match address.addr {
            IpAddr::V4(a) => settings.ipv4_addresses.push(a),
            IpAddr::V6(a) => settings.ipv6_addresses.push(a),
        }
    }
    // Windows won't start a VPN channel without an IPv6 address, so IPv4-only tunnels get a
    // private one. Nothing is routed to it.
    if settings.ipv6_addresses.is_empty() {
        settings.ipv6_addresses.push(PLACEHOLDER_IPV6);
    }
    for net in &peer.allowed_ips {
        match network(net) {
            (IpAddr::V4(a), prefix) => push_unique(&mut settings.ipv4_routes, (a, prefix)),
            (IpAddr::V6(a), prefix) => push_unique(&mut settings.ipv6_routes, (a, prefix)),
        }
    }

    Ok(TunnelSetup {
        interface,
        peer,
        settings,
    })
}

/// Clears host bits, since Windows expects routes as network addresses (10.1.2.3/8 → 10.0.0.0/8).
fn network(net: &IpNet) -> (IpAddr, u8) {
    let addr = match net.addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(net.prefix))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(net.prefix))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    };
    (addr, net.prefix)
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wgconf::Key;

    fn config(allowed: &str, endpoint: Option<&str>) -> Config {
        Config {
            interface: Interface {
                private_key: Key([1; 32]),
                listen_port: Some(51820),
                addresses: vec![
                    "10.1.254.3/32".parse().unwrap(),
                    "fd00::3/128".parse().unwrap(),
                ],
                dns_servers: vec!["10.1.254.1".parse().unwrap()],
                dns_search: vec!["corp.example".into()],
                mtu: None,
            },
            peers: vec![Peer {
                public_key: Key([2; 32]),
                preshared_key: None,
                allowed_ips: allowed
                    .split(',')
                    .map(|s| s.trim().parse().unwrap())
                    .collect(),
                endpoint: endpoint.map(|e| e.parse().unwrap()),
                persistent_keepalive: None,
            }],
        }
    }

    #[test]
    fn maps_typical_config() {
        let config = config("10.0.0.0/8, 192.168.11.0/24", Some("203.0.113.10:13232"));
        let s = from_config(&config).unwrap().settings;
        assert_eq!(s.ipv4_addresses, vec![Ipv4Addr::new(10, 1, 254, 3)]);
        assert_eq!(
            s.ipv6_addresses,
            vec!["fd00::3".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(
            s.ipv4_routes,
            vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(192, 168, 11, 0), 24)
            ]
        );
        assert!(s.ipv6_routes.is_empty());
        assert_eq!(s.dns_servers, vec!["10.1.254.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(s.dns_search, vec!["corp.example".to_string()]);
        assert_eq!(s.mtu, 1420);
        assert_eq!(s.max_frame_size, 1484);
        assert_eq!(
            s.endpoint,
            Endpoint {
                host: "203.0.113.10".into(),
                port: 13232
            }
        );
    }

    #[test]
    fn normalizes_and_dedups_routes() {
        let config = config(
            "10.1.2.3/8, 10.0.0.0/8, 0.0.0.0/0, 2001:db8::1/32, ::/0",
            Some("vpn.example:1"),
        );
        let s = from_config(&config).unwrap().settings;
        assert_eq!(
            s.ipv4_routes,
            vec![(Ipv4Addr::new(10, 0, 0, 0), 8), (Ipv4Addr::UNSPECIFIED, 0)]
        );
        assert_eq!(
            s.ipv6_routes,
            vec![
                ("2001:db8::".parse().unwrap(), 32),
                (Ipv6Addr::UNSPECIFIED, 0)
            ]
        );
    }

    #[test]
    fn host_routes_stay_intact() {
        let config = config("10.9.8.7/32, 2001:db8::7/128", Some("vpn.example:1"));
        let s = from_config(&config).unwrap().settings;
        assert_eq!(s.ipv4_routes, vec![(Ipv4Addr::new(10, 9, 8, 7), 32)]);
        assert_eq!(s.ipv6_routes, vec![("2001:db8::7".parse().unwrap(), 128)]);
    }

    #[test]
    fn ipv4_only_gets_placeholder_ipv6() {
        let mut config = config("10.0.0.0/8", Some("vpn.example:1"));
        config.interface.addresses = vec!["10.1.254.3/32".parse().unwrap()];
        let s = from_config(&config).unwrap().settings;
        assert_eq!(s.ipv6_addresses, vec![PLACEHOLDER_IPV6]);
        assert!(s.ipv6_routes.is_empty());
    }

    #[test]
    fn custom_mtu() {
        let mut config = config("10.0.0.0/8", Some("vpn.example:1"));
        config.interface.mtu = Some(1280);
        let s = from_config(&config).unwrap().settings;
        assert_eq!((s.mtu, s.max_frame_size), (1280, 1344));
    }

    #[test]
    fn requires_endpoint_and_single_peer() {
        let no_endpoint = config("10.0.0.0/8", None);
        assert!(
            from_config(&no_endpoint)
                .err()
                .unwrap()
                .contains("Endpoint")
        );

        let mut two_peers = config("10.0.0.0/8", Some("vpn.example:1"));
        two_peers.peers.push(two_peers.peers[0].clone());
        assert!(
            from_config(&two_peers)
                .err()
                .unwrap()
                .contains("one [Peer]")
        );
    }
}
