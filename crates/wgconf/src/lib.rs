//! Parser for WireGuard tunnel configs in the standard `wg-quick` format, as used by the
//! official WireGuard apps.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub const KEY_LEN: usize = 32;
/// Smallest MTU IPv4 requires; below it nothing works, and the error only shows at connect.
pub const MIN_MTU: u16 = 576;
pub const MAX_MTU: u16 = u16::MAX;

/// A Curve25519 key or preshared key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub [u8; KEY_LEN]);

impl Key {
    pub fn from_base64(s: &str) -> Option<Key> {
        let bytes = STANDARD.decode(s.trim()).ok()?;
        let bytes: [u8; KEY_LEN] = bytes.try_into().ok()?;
        Some(Key(bytes))
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
}

// Never print key material, so configs can be logged safely.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// An address with a prefix length, e.g. `10.0.0.0/8`. A bare address gets the full length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl FromStr for IpNet {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| ())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| ())?,
            None => max,
        };
        if prefix > max {
            return Err(());
        }
        Ok(IpNet { addr, prefix })
    }
}

impl IpNet {
    /// Whether `addr` falls inside this network. An IPv4 network never contains an IPv6
    /// address, and the other way round.
    pub fn contains(&self, addr: IpAddr) -> bool {
        addr.is_ipv4() == self.addr.is_ipv4() && masked(addr, self.prefix) == self.network().addr
    }

    /// The same network with its host bits cleared: 10.1.2.3/8 becomes 10.0.0.0/8.
    pub fn network(&self) -> IpNet {
        IpNet {
            addr: masked(self.addr, self.prefix),
            prefix: self.prefix,
        }
    }
}

/// `addr` with everything after the first `prefix` bits cleared.
fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(a) & mask).into())
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(a) & mask).into())
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A peer endpoint. The host is kept as written, since it may be a DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.host.contains(':') {
            true => write!(f, "[{}]:{}", self.host, self.port),
            false => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

impl FromStr for Endpoint {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            // IPv6 literal: [2001:db8::1]:51820
            rest.split_once("]:").ok_or(())?
        } else {
            let (host, port) = s.rsplit_once(':').ok_or(())?;
            // An unbracketed IPv6 address is ambiguous.
            if host.contains(':') {
                return Err(());
            }
            (host, port)
        };
        if host.is_empty() {
            return Err(());
        }
        let port = port.parse().map_err(|_| ())?;
        Ok(Endpoint {
            host: host.to_string(),
            port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub private_key: Key,
    pub listen_port: Option<u16>,
    pub addresses: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number, if the error belongs to a line.
    pub line: Option<usize>,
    pub message: String,
}

impl ParseError {
    fn at(line: usize, message: impl Into<String>) -> Self {
        ParseError {
            line: Some(line),
            message: message.into(),
        }
    }

    fn general(message: impl Into<String>) -> Self {
        ParseError {
            line: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {line}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for ParseError {}

impl FromStr for Config {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        parse(s)
    }
}

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<Key>,
    listen_port: Option<u16>,
    addresses: Vec<IpNet>,
    dns_servers: Vec<IpAddr>,
    dns_search: Vec<String>,
    mtu: Option<u16>,
}

struct PeerBuilder {
    line: usize,
    public_key: Option<Key>,
    preshared_key: Option<Key>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<Endpoint>,
    persistent_keepalive: Option<u16>,
}

enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse(text: &str) -> Result<Config, ParseError> {
    // Notepad and PowerShell like to write a byte order mark, which isn't whitespace to trim().
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut section = Section::None;
    let mut interface: Option<InterfaceBuilder> = None;
    let mut peers: Vec<PeerBuilder> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }

        if let Some(name) = content.strip_prefix('[').and_then(|c| c.strip_suffix(']')) {
            match name.trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    if interface.is_some() {
                        return Err(ParseError::at(line, "duplicate [Interface] section"));
                    }
                    interface = Some(InterfaceBuilder::default());
                    section = Section::Interface;
                }
                "peer" => {
                    peers.push(PeerBuilder {
                        line,
                        public_key: None,
                        preshared_key: None,
                        allowed_ips: Vec::new(),
                        endpoint: None,
                        persistent_keepalive: None,
                    });
                    section = Section::Peer;
                }
                _ => {
                    return Err(ParseError::at(
                        line,
                        format!("unknown section [{}]", name.trim()),
                    ));
                }
            }
            continue;
        }

        let Some((key, value)) = content.split_once('=') else {
            return Err(ParseError::at(line, "expected `Key = Value`"));
        };
        let key = key.trim();
        let value = value.trim();

        match section {
            Section::None => {
                return Err(ParseError::at(line, "setting outside of a section"));
            }
            Section::Interface => {
                let iface = interface.as_mut().expect("in Interface section");
                match key.to_ascii_lowercase().as_str() {
                    "privatekey" => {
                        set_once(&mut iface.private_key, parse_key(value, line)?, key, line)?
                    }
                    "listenport" => set_once(
                        &mut iface.listen_port,
                        parse_num(value, key, line)?,
                        key,
                        line,
                    )?,
                    "mtu" => {
                        let mtu: u16 = parse_num(value, key, line)?;
                        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                            return Err(ParseError::at(
                                line,
                                format!("MTU must be between {MIN_MTU} and {MAX_MTU}"),
                            ));
                        }
                        set_once(&mut iface.mtu, mtu, key, line)?
                    }
                    "address" => {
                        for item in list(value) {
                            iface.addresses.push(parse_net(item, line)?);
                        }
                    }
                    "dns" => {
                        // Entries that are not IP addresses are search domains.
                        for item in list(value) {
                            match item.parse::<IpAddr>() {
                                Ok(addr) => iface.dns_servers.push(addr),
                                Err(_) => iface.dns_search.push(item.to_string()),
                            }
                        }
                    }
                    // wg-quick settings for Linux routing tables and firewall marks; on Windows
                    // there's nothing to apply them to.
                    "fwmark" | "saveconfig" => {}
                    "table" => {
                        if value.eq_ignore_ascii_case("off") {
                            return Err(ParseError::at(
                                line,
                                "`Table = off` (adding no routes) is not supported",
                            ));
                        }
                    }
                    // Scripts often set up routes or firewall rules the tunnel relies on, so
                    // silently skipping them would be worse than refusing.
                    "preup" | "postup" | "predown" | "postdown" => {
                        return Err(ParseError::at(
                            line,
                            format!(
                                "`{key}` scripts are not supported; remove the line to use this config"
                            ),
                        ));
                    }
                    _ => {
                        return Err(ParseError::at(
                            line,
                            format!("unknown [Interface] setting `{key}`"),
                        ));
                    }
                }
            }
            Section::Peer => {
                let peer = peers.last_mut().expect("in Peer section");
                match key.to_ascii_lowercase().as_str() {
                    "publickey" => {
                        set_once(&mut peer.public_key, parse_key(value, line)?, key, line)?
                    }
                    "presharedkey" => {
                        set_once(&mut peer.preshared_key, parse_key(value, line)?, key, line)?
                    }
                    "endpoint" => {
                        let endpoint = value.parse().map_err(|_| {
                            ParseError::at(
                                line,
                                format!("invalid endpoint `{value}`, expected host:port"),
                            )
                        })?;
                        set_once(&mut peer.endpoint, endpoint, key, line)?;
                    }
                    "persistentkeepalive" => {
                        let interval = if value.eq_ignore_ascii_case("off") {
                            0
                        } else {
                            parse_num(value, key, line)?
                        };
                        set_once(&mut peer.persistent_keepalive, interval, key, line)?;
                    }
                    "allowedips" => {
                        for item in list(value) {
                            peer.allowed_ips.push(parse_net(item, line)?);
                        }
                    }
                    _ => {
                        return Err(ParseError::at(
                            line,
                            format!("unknown [Peer] setting `{key}`"),
                        ));
                    }
                }
            }
        }
    }

    let iface = interface.ok_or_else(|| ParseError::general("missing [Interface] section"))?;
    let private_key = iface
        .private_key
        .ok_or_else(|| ParseError::general("[Interface] is missing PrivateKey"))?;
    if iface.addresses.is_empty() {
        return Err(ParseError::general("[Interface] is missing Address"));
    }
    if peers.is_empty() {
        return Err(ParseError::general("missing [Peer] section"));
    }

    let peers = peers
        .into_iter()
        .map(|p| {
            Ok(Peer {
                public_key: p
                    .public_key
                    .ok_or_else(|| ParseError::at(p.line, "[Peer] is missing PublicKey"))?,
                preshared_key: p.preshared_key,
                allowed_ips: p.allowed_ips,
                endpoint: p.endpoint,
                // 0 means off.
                persistent_keepalive: p.persistent_keepalive.filter(|&s| s != 0),
            })
        })
        .collect::<Result<Vec<_>, ParseError>>()?;

    Ok(Config {
        interface: Interface {
            private_key,
            listen_port: iface.listen_port,
            addresses: iface.addresses,
            dns_servers: iface.dns_servers,
            dns_search: iface.dns_search,
            mtu: iface.mtu,
        },
        peers,
    })
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str, line: usize) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::at(line, format!("duplicate `{key}`")));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_key(value: &str, line: usize) -> Result<Key, ParseError> {
    Key::from_base64(value)
        .ok_or_else(|| ParseError::at(line, "invalid key, expected 32 bytes of base64"))
}

fn parse_num<T: FromStr>(value: &str, key: &str, line: usize) -> Result<T, ParseError> {
    value
        .parse()
        .map_err(|_| ParseError::at(line, format!("invalid number `{value}` for `{key}`")))
}

fn parse_net(value: &str, line: usize) -> Result<IpNet, ParseError> {
    value
        .parse()
        .map_err(|_| ParseError::at(line, format!("invalid address `{value}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(byte: u8) -> Key {
        Key([byte; KEY_LEN])
    }

    fn sample() -> String {
        format!(
            "[Interface]
ListenPort = 51820
PrivateKey = {}
Address = 10.0.0.2/32
DNS = 10.0.0.1

[Peer]
PublicKey = {}
AllowedIPs = 10.0.0.0/8, 192.168.50.0/24
Endpoint = 203.0.113.10:51821
",
            key(1).to_base64(),
            key(2).to_base64(),
        )
    }

    fn err(text: &str) -> ParseError {
        parse(text).expect_err("should fail")
    }

    #[test]
    fn parses_typical_config() {
        let config = parse(&sample()).unwrap();
        let iface = &config.interface;
        assert_eq!(iface.private_key, key(1));
        assert_eq!(iface.listen_port, Some(51820));
        assert_eq!(iface.addresses, vec!["10.0.0.2/32".parse().unwrap()]);
        assert_eq!(
            iface.dns_servers,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert!(iface.dns_search.is_empty());

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.public_key, key(2));
        assert_eq!(
            peer.allowed_ips,
            vec![
                IpNet::from_str("10.0.0.0/8").unwrap(),
                IpNet::from_str("192.168.50.0/24").unwrap()
            ]
        );
        assert_eq!(
            peer.endpoint,
            Some(Endpoint {
                host: "203.0.113.10".into(),
                port: 51821
            })
        );
        assert_eq!(peer.persistent_keepalive, None);
    }

    #[test]
    fn ignores_comments_and_case() {
        let text = sample()
            .replace("[Interface]", "# my tunnel\n[interface]  # comment")
            .replace("DNS", "dns");
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn dns_search_domains() {
        let text = sample().replace(
            "DNS = 10.0.0.1",
            "DNS = 10.0.0.1, corp.example, 2001:db8::53",
        );
        let iface = parse(&text).unwrap().interface;
        assert_eq!(
            iface.dns_servers,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53)),
            ]
        );
        assert_eq!(iface.dns_search, vec!["corp.example".to_string()]);
    }

    #[test]
    fn mtu_range() {
        let with = |mtu: &str| {
            parse(&format!(
                "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2\nMTU = {mtu}\n[Peer]\nPublicKey = {}\n",
                key(1).to_base64(),
                key(2).to_base64()
            ))
        };
        assert_eq!(with("1280").unwrap().interface.mtu, Some(1280));
        assert!(with("100").unwrap_err().message.contains("between"));
        assert!(
            with("70000")
                .unwrap_err()
                .message
                .contains("invalid number")
        );
    }

    #[test]
    fn network_clears_host_bits() {
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(net("10.1.2.3/8").network(), net("10.0.0.0/8"));
        assert_eq!(net("10.1.2.3/0").network(), net("0.0.0.0/0"));
        assert_eq!(net("2001:db8::1/32").network(), net("2001:db8::/32"));
        assert_eq!(net("10.9.8.7/32").network(), net("10.9.8.7/32"));
        assert!(net("10.1.2.3/8").contains("10.200.0.1".parse().unwrap()));
        assert!(!net("10.1.2.3/8").contains("11.0.0.1".parse().unwrap()));
        assert!(!net("10.1.2.3/8").contains("::1".parse().unwrap()));
    }

    #[test]
    fn endpoints_round_trip() {
        for text in [
            "[2001:db8::1]:51820",
            "vpn.example.com:443",
            "203.0.113.10:51821",
        ] {
            assert_eq!(text.parse::<Endpoint>().unwrap().to_string(), text);
        }
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            "[2001:db8::1]:51820".parse::<Endpoint>(),
            Ok(Endpoint {
                host: "2001:db8::1".into(),
                port: 51820
            })
        );
        assert_eq!(
            "vpn.example.com:443".parse::<Endpoint>(),
            Ok(Endpoint {
                host: "vpn.example.com".into(),
                port: 443
            })
        );
        assert!("2001:db8::1:51820".parse::<Endpoint>().is_err());
        assert!("vpn.example.com".parse::<Endpoint>().is_err());
        assert!(":51820".parse::<Endpoint>().is_err());
        assert!("host:99999".parse::<Endpoint>().is_err());
    }

    #[test]
    fn ip_nets() {
        assert_eq!(
            IpNet::from_str("10.0.0.1"),
            Ok(IpNet {
                addr: "10.0.0.1".parse().unwrap(),
                prefix: 32
            })
        );
        assert_eq!(IpNet::from_str("::/0").map(|n| n.prefix), Ok(0));
        assert!(IpNet::from_str("10.0.0.0/33").is_err());
        assert!(IpNet::from_str("10.0.0/8").is_err());
    }

    #[test]
    fn strips_byte_order_mark() {
        assert!(parse(&format!("\u{feff}{}", sample())).is_ok());
    }

    #[test]
    fn wg_quick_extras() {
        let with = |extra: &str| sample().replace("ListenPort", &format!("{extra}\nListenPort"));
        assert!(parse(&with("Table = auto")).is_ok());
        assert!(parse(&with("Table = 1234")).is_ok());
        assert!(parse(&with("FwMark = 0x1234")).is_ok());
        assert!(parse(&with("SaveConfig = true")).is_ok());

        let e = err(&with("Table = off"));
        assert!(e.message.contains("Table = off"), "{e}");
        let e = err(&with("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT"));
        assert_eq!(e.line, Some(2));
        assert!(
            e.message.contains("`PostUp` scripts are not supported"),
            "{e}"
        );
    }

    #[test]
    fn ip_net_contains() {
        let net = |s: &str| IpNet::from_str(s).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(net("10.0.0.0/8").contains(ip("10.255.1.2")));
        assert!(!net("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(net("192.168.50.0/24").contains(ip("192.168.50.254")));
        assert!(!net("192.168.50.0/24").contains(ip("192.168.51.1")));
        assert!(net("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!(net("10.9.8.7/32").contains(ip("10.9.8.7")));
        assert!(!net("10.9.8.7/32").contains(ip("10.9.8.6")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
        assert!(net("2001:db8::/32").contains(ip("2001:db8:ffff::1")));
        // Address families never mix.
        assert!(!net("0.0.0.0/0").contains(ip("::1")));
        assert!(!net("::/0").contains(ip("10.0.0.1")));
    }

    #[test]
    fn persistent_keepalive() {
        let with = |v: &str| {
            let text =
                sample().replace("Endpoint", &format!("PersistentKeepalive = {v}\nEndpoint"));
            parse(&text).unwrap().peers[0].persistent_keepalive
        };
        assert_eq!(with("25"), Some(25));
        assert_eq!(with("0"), None);
        assert_eq!(with("off"), None);
    }

    #[test]
    fn rejects_invalid_key() {
        let text = sample().replace(&key(1).to_base64(), "PrivateKeyEntry=");
        let e = err(&text);
        assert_eq!(e.line, Some(3));
        assert!(e.message.contains("invalid key"));
    }

    #[test]
    fn rejects_missing_parts() {
        let no_private = sample().replace(&format!("PrivateKey = {}\n", key(1).to_base64()), "");
        assert!(err(&no_private).message.contains("PrivateKey"));

        let no_address = sample().replace("Address = 10.0.0.2/32\n", "");
        assert!(err(&no_address).message.contains("Address"));

        let no_peer = sample().split("[Peer]").next().unwrap().to_string();
        assert!(err(&no_peer).message.contains("[Peer]"));

        let no_public = sample().replace(&format!("PublicKey = {}\n", key(2).to_base64()), "");
        assert_eq!(err(&no_public).line, Some(7));
    }

    #[test]
    fn rejects_unknown_and_duplicate_settings() {
        let unknown = sample().replace("ListenPort", "ListenPrt");
        assert!(
            err(&unknown)
                .message
                .contains("unknown [Interface] setting")
        );

        let duplicate =
            sample().replace("ListenPort = 51820", "ListenPort = 51820\nListenPort = 1");
        assert!(err(&duplicate).message.contains("duplicate"));

        assert!(
            err("PrivateKey = x")
                .message
                .contains("outside of a section")
        );
        assert!(err("[Wat]").message.contains("unknown section"));
    }

    #[test]
    fn debug_hides_keys() {
        let config = parse(&sample()).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(&key(1).to_base64()));
        assert!(debug.contains("Key(..)"));
    }
}
