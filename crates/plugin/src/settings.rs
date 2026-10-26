//! Turns a WireGuard config into the values Windows needs to bring the VPN interface up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use boringtun::noise::amnezia::{AmneziaConfig, AwgTimers};
use boringtun::noise::handshake::ObfuscationRanges;
use wgconf::{Amnezia, Config, Endpoint, Interface, IpNet, Peer, Range};

/// Same default as the official WireGuard clients.
pub const DEFAULT_MTU: u16 = 1420;
/// Encrypted packets are the inner packet plus 32 bytes; leave some slack.
pub const FRAME_OVERHEAD: u32 = 64;
/// The most an AmneziaWG random trailer adds to a datagram: the engine keeps the trailer
/// within this UDP window.
pub const TRAILER_WINDOW: u32 = 500;
/// The sizes of the four WireGuard messages before any padding: handshake initiation,
/// handshake response, cookie reply, and the least a data message takes (a keepalive).
pub const BASE_SIZES: [u16; 4] = [148, 92, 64, 32];
/// The largest junk packet the engine sends when `Jc` is set but `Jmin`/`Jmax` are not.
const DEFAULT_JUNK_MAX: u16 = 1000;
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
    pub obfuscation: Obfuscation,
}

/// What the engine needs to speak AmneziaWG; the default speaks plain WireGuard.
#[derive(Debug, Clone, Default)]
pub struct Obfuscation {
    /// The message types H1–H4.
    pub ranges: ObfuscationRanges,
    /// Everything else: junk, paddings, header protection, content padding, timers, trailers.
    pub config: AmneziaConfig,
    /// S1–S4, which `config` keeps to itself: how many bytes precede each kind of message.
    pub paddings: [u16; 4],
    /// Whether the message type field is encrypted, so nothing about a datagram can be read.
    pub header_protection: bool,
    /// Whether datagrams carry a random trailer, so their length tells less.
    pub trailers: bool,
    /// The most `ContentPaddingAddition` adds to a data packet.
    pub content_padding: u32,
    /// The largest datagram other than data the engine can produce: a padded handshake
    /// message, a junk packet or a signature packet, before any trailer.
    pub largest_control: u32,
}

impl Obfuscation {
    /// The largest datagram the tunnel sends or receives for an inner packet of `mtu` bytes,
    /// which is what Windows sizes its packet buffers for: a datagram that does not fit one is
    /// lost, and before any handshake that is the junk and the initiation themselves.
    pub fn max_frame_size(&self, mtu: u32) -> u32 {
        let data = mtu + FRAME_OVERHEAD + u32::from(self.paddings[3]) + self.content_padding;
        let trailer = if self.trailers { TRAILER_WINDOW } else { 0 };
        data.max(self.largest_control) + trailer
    }
}

/// The engine's settings for a config's AmneziaWG keys, checked the way the engine checks them.
pub fn obfuscation(a: &Amnezia, mtu: u16) -> Result<Obfuscation, String> {
    // The engine reads `(0, 0)` as WireGuard's own type and `(v, 0)` as the single value v.
    let h = |i: usize| -> (u32, u32) {
        match a.headers[i] {
            None => (0, 0),
            Some(r) if r.is_single() => (r.lo, 0),
            Some(r) => (r.lo, r.hi),
        }
    };
    let ranges = ObfuscationRanges::new(
        h(0).0,
        h(0).1,
        h(1).0,
        h(1).1,
        h(2).0,
        h(2).1,
        h(3).0,
        h(3).1,
    )
    .map_err(|e| format!("AmneziaWG header types: {e}"))?;

    let [s1, s2, s3, s4] = a.paddings;
    let mut config = AmneziaConfig::new(s1, s2, s3, s4);
    if a.junk_count > 0 {
        // The engine keeps Jmin/Jmax only when 0 < Jmin <= Jmax and otherwise sends its own
        // 50-1000 bytes; amneziawg-go takes Jmin = 0, so lift it to 1 to keep the asked sizes.
        let junk_min = if a.junk_max > 0 { a.junk_min.max(1) } else { 0 };
        config = config.with_pre_handshake_junk(a.junk_count, junk_min, a.junk_max, 0);
    }
    if let Some(key) = &a.header_protection_key {
        config = config.with_header_protection(key.0);
    }
    if let Some(r) = a.content_padding_addition {
        config = config.with_content_padding_addition(r.lo, r.hi, mtu);
    }
    if a.has_timers() {
        let t = |r: Option<Range<u32>>| r.map_or((0, 0), |r| (r.lo, r.hi));
        config = config.with_tunable_timers(AwgTimers {
            rekey_after_time: t(a.rekey_after_time),
            rekey_timeout: t(a.rekey_timeout),
            reject_after_time: t(a.reject_after_time),
            keepalive_timeout: t(a.keepalive_timeout),
            max_handshake_attempts: t(a.max_handshake_attempts),
        });
    }
    config = config
        .with_random_trailers(a.random_trailers)
        .with_disable_cookies(a.disable_cookies);
    // I1–I5 as written in the config; the engine parses the tag language.
    let specs: [Option<&str>; 5] = std::array::from_fn(|i| a.signature_packets[i].as_deref());
    config = config
        .with_signature_packets(specs)
        .map_err(|e| format!("AmneziaWG signature packets: {e}"))?;
    config
        .validate()
        .map_err(|e| format!("AmneziaWG settings: {e}"))?;

    let junk = match (a.junk_count, a.junk_max) {
        (0, _) => 0,
        (_, 0) => DEFAULT_JUNK_MAX,
        (_, max) => max,
    };
    let signature = config
        .signature_packets()
        .iter()
        .flatten()
        .map(|p| p.max_len() as u32)
        .max()
        .unwrap_or(0);
    let padded = |k: usize| u32::from(a.paddings[k]) + u32::from(BASE_SIZES[k]);
    let largest_control = [padded(0), padded(1), padded(2), u32::from(junk), signature]
        .into_iter()
        .max()
        .unwrap_or(0);
    Ok(Obfuscation {
        ranges,
        config,
        paddings: a.paddings,
        header_protection: a.header_protection_key.is_some(),
        trailers: a.random_trailers,
        content_padding: a.content_padding_addition.map_or(0, |r| r.hi),
        largest_control,
    })
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
    let obfuscation = obfuscation(&interface.amnezia, interface.mtu.unwrap_or(DEFAULT_MTU))?;
    settings.max_frame_size = obfuscation.max_frame_size(settings.mtu);

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
        obfuscation,
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
                amnezia: Amnezia::default(),
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

    #[test]
    fn plain_config_has_no_obfuscation() {
        let config = config("10.0.0.0/8", Some("a.example:1"));
        let setup = from_config(&config).unwrap();
        assert_eq!(setup.obfuscation.ranges, ObfuscationRanges::default());
        assert_eq!(setup.obfuscation.config, AmneziaConfig::default());
        assert!(!setup.obfuscation.header_protection && !setup.obfuscation.trailers);
    }

    #[test]
    fn amnezia_settings_reach_the_engine() {
        let mut config = config("10.0.0.0/8", Some("a.example:1"));
        config.interface.amnezia = Amnezia {
            junk_count: 3,
            junk_min: 60,
            junk_max: 120,
            paddings: [16, 24, 20, 12],
            headers: [
                Some(Range {
                    lo: 100000,
                    hi: 200000,
                }),
                Some(Range::single(300000)),
                None,
                Some(Range {
                    lo: 700000,
                    hi: 800000,
                }),
            ],
            header_protection_key: Some(Key([5; 32])),
            content_padding_addition: Some(Range { lo: 0, hi: 64 }),
            max_handshake_attempts: Some(Range { lo: 3, hi: 5 }),
            random_trailers: true,
            disable_cookies: true,
            ..Default::default()
        };
        let setup = from_config(&config).unwrap();
        let expected = AmneziaConfig::new(16, 24, 20, 12)
            .with_pre_handshake_junk(3, 60, 120, 0)
            .with_header_protection([5; 32])
            .with_content_padding_addition(0, 64, 1420)
            .with_tunable_timers(AwgTimers {
                max_handshake_attempts: (3, 5),
                ..Default::default()
            })
            .with_random_trailers(true)
            .with_disable_cookies(true);
        assert_eq!(setup.obfuscation.config, expected);
        assert_eq!(
            setup.obfuscation.ranges,
            ObfuscationRanges::new(100000, 200000, 300000, 0, 0, 0, 700000, 800000).unwrap()
        );
        assert_eq!(setup.obfuscation.paddings, [16, 24, 20, 12]);
        assert!(setup.obfuscation.header_protection && setup.obfuscation.trailers);
        // S4, the content padding and a trailer all grow a data packet.
        assert_eq!(setup.settings.max_frame_size, 1420 + 64 + 12 + 64 + 500);
    }

    #[test]
    fn frames_fit_the_handshake_burst() {
        // The buffers must hold the largest datagram of all, not only data: a padded
        // initiation, a junk packet or a signature packet can all be bigger.
        let mut config = config("10.0.0.0/8", Some("a.example:1"));
        config.interface.mtu = Some(1280);
        config.interface.amnezia.paddings = [1300, 0, 0, 0];
        let setup = from_config(&config).unwrap();
        assert_eq!(setup.obfuscation.largest_control, 1300 + 148);
        assert_eq!(setup.settings.max_frame_size, 1300 + 148);

        config.interface.mtu = Some(576);
        config.interface.amnezia = Amnezia {
            junk_count: 2,
            junk_min: 100,
            junk_max: 1280,
            ..Default::default()
        };
        let setup = from_config(&config).unwrap();
        assert_eq!(setup.settings.max_frame_size, 1280);

        // Jc without sizes means the engine's default of up to 1000 bytes.
        config.interface.amnezia = Amnezia {
            junk_count: 2,
            ..Default::default()
        };
        assert_eq!(from_config(&config).unwrap().settings.max_frame_size, 1000);

        config.interface.amnezia = Amnezia {
            signature_packets: [Some("<r 1200>".into()), None, None, None, None],
            random_trailers: true,
            ..Default::default()
        };
        assert_eq!(
            from_config(&config).unwrap().settings.max_frame_size,
            1200 + 500
        );

        // Small settings change nothing about a plain tunnel's frames.
        config.interface.amnezia = Amnezia {
            paddings: [15, 40, 0, 0],
            ..Default::default()
        };
        assert_eq!(from_config(&config).unwrap().settings.max_frame_size, 640);
    }

    #[test]
    fn signature_packets_reach_the_engine() {
        let mut config = config("10.0.0.0/8", Some("a.example:1"));
        config.interface.amnezia.signature_packets[0] = Some("<b 0xf6ab><r 8><t>".into());
        config.interface.amnezia.signature_packets[2] = Some("<rc 12><rd 6>".into());
        let setup = from_config(&config).unwrap();
        let packets = setup.obfuscation.config.signature_packets();
        assert!(packets[0].is_some() && packets[1].is_none() && packets[2].is_some());

        config.interface.amnezia.signature_packets[1] = Some("<x 1>".into());
        let e = from_config(&config).err().unwrap();
        assert!(e.contains("signature packets") && e.contains("I2"), "{e}");
    }

    #[test]
    fn engine_refusals_are_reported() {
        let mut config = config("10.0.0.0/8", Some("a.example:1"));
        config.interface.amnezia.headers[0] = Some(Range { lo: 10, hi: 20 });
        config.interface.amnezia.headers[1] = Some(Range { lo: 15, hi: 25 });
        let e = from_config(&config).err().unwrap();
        assert!(e.contains("header types"), "{e}");
    }
}
