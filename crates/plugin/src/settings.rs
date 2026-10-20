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
    /// Networks routed into the tunnel: all peers' AllowedIPs together.
    pub ipv4_routes: Vec<(Ipv4Addr, u8)>,
    pub ipv6_routes: Vec<(Ipv6Addr, u8)>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: u32,
    pub max_frame_size: u32,
    /// One per peer, in the config's order. Each gets its own UDP connection.
    pub endpoints: Vec<Endpoint>,
}

/// The parts of a config the plugin works with.
pub struct TunnelSetup<'a> {
    pub interface: &'a Interface,
    pub peers: &'a [Peer],
    pub settings: ChannelSettings,
}

pub fn from_config(config: &Config) -> Result<TunnelSetup<'_>, String> {
    let peers = config.peers.as_slice();
    // Windows only lets the plugin send to the servers it connected to, so a peer without an
    // Endpoint could never be reached.
    let endpoints = peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            p.endpoint.clone().ok_or_else(|| match peers.len() {
                1 => "[Peer] is missing Endpoint".to_string(),
                _ => format!("[Peer] number {} is missing Endpoint", i + 1),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
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
        endpoints,
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
    // Windows expects routes as network addresses (10.1.2.3/8 → 10.0.0.0/8).
    for net in peers
        .iter()
        .flat_map(|p| &p.allowed_ips)
        .map(IpNet::network)
    {
        match net.addr {
            IpAddr::V4(a) => push_unique(&mut settings.ipv4_routes, (a, net.prefix)),
            IpAddr::V6(a) => push_unique(&mut settings.ipv6_routes, (a, net.prefix)),
        }
    }

    Ok(TunnelSetup {
        interface,
        peers,
        settings,
    })
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
                    "10.0.0.2/32".parse().unwrap(),
                    "fd00::3/128".parse().unwrap(),
                ],
                dns_servers: vec!["10.0.0.1".parse().unwrap()],
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
        let config = config("10.0.0.0/8, 192.168.50.0/24", Some("203.0.113.10:51821"));
        let s = from_config(&config).unwrap().settings;
        assert_eq!(s.ipv4_addresses, vec![Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(
            s.ipv6_addresses,
            vec!["fd00::3".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(
            s.ipv4_routes,
            vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(192, 168, 50, 0), 24)
            ]
        );
        assert!(s.ipv6_routes.is_empty());
        assert_eq!(s.dns_servers, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(s.dns_search, vec!["corp.example".to_string()]);
        assert_eq!(s.mtu, 1420);
        assert_eq!(s.max_frame_size, 1484);
        assert_eq!(
            s.endpoints,
            vec![Endpoint {
                host: "203.0.113.10".into(),
                port: 51821
            }]
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
        config.interface.addresses = vec!["10.0.0.2/32".parse().unwrap()];
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
    fn requires_an_endpoint_per_peer() {
        let no_endpoint = config("10.0.0.0/8", None);
        let e = from_config(&no_endpoint).err().unwrap();
        assert_eq!(e, "[Peer] is missing Endpoint");

        let mut two = config("10.0.0.0/8", Some("vpn.example:1"));
        let mut second = two.peers[0].clone();
        second.endpoint = None;
        two.peers.push(second);
        let e = from_config(&two).err().unwrap();
        assert_eq!(e, "[Peer] number 2 is missing Endpoint");
    }

    #[test]
    fn several_peers_combine_routes() {
        let mut two = config("10.0.0.0/8, 192.168.50.0/24", Some("a.example:1"));
        let mut second = two.peers[0].clone();
        second.allowed_ips = vec![
            "172.16.0.0/12".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        second.endpoint = Some("b.example:2".parse().unwrap());
        two.peers.push(second);

        let setup = from_config(&two).unwrap();
        assert_eq!(setup.peers.len(), 2);
        let s = setup.settings;
        assert_eq!(
            s.ipv4_routes,
            vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(192, 168, 50, 0), 24),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
            ]
        );
        let hosts: Vec<_> = s.endpoints.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(hosts, vec!["a.example", "b.example"]);
    }
}
