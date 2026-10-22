//! WireGuard sessions with a tunnel's peers, on top of BoringTun. Nothing here depends on
//! Windows, so the packet flow can be tested anywhere.

use std::net::IpAddr;
use std::time::Duration;

use boringtun::noise::amnezia::AmneziaConfig;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::ObfuscationRanges;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::settings::{Obfuscation, TRAILER_WINDOW};

/// Scratch space for one datagram. BoringTun needs at least packet length + 32 bytes.
const BUF_LEN: usize = 65536 + 32;

pub struct Tunnel {
    peers: Vec<PeerSession>,
    buf: Vec<u8>,
    wire: Wire,
}

/// What this tunnel's datagrams look like on the wire, for telling them apart without the
/// engine: plain WireGuard, or AmneziaWG with its paddings and message types.
struct Wire {
    ranges: ObfuscationRanges,
    paddings: [u16; 4],
    /// Whether the message type is encrypted; `config` then knows how to read it.
    header_protection: bool,
    trailers: bool,
    config: AmneziaConfig,
}

/// What a datagram is, as far as its framing shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    Data,
    Other,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::HandshakeInitiation => "handshake initiation",
            Kind::HandshakeResponse => "handshake response",
            Kind::CookieReply => "cookie reply",
            Kind::Data => "data",
            Kind::Other => "unrecognised",
        }
    }
}

/// The sizes of the four WireGuard messages before any padding; data is at least this long.
const BASE_SIZES: [usize; 4] = [148, 92, 64, 32];

/// A keepalive interval from its range, drawn once per connect like AmneziaWG does.
fn pick(range: wgconf::Range<u16>) -> u16 {
    if range.is_single() {
        return range.lo;
    }
    let mut bytes = [0u8; 2];
    if getrandom::fill(&mut bytes).is_err() {
        return range.lo;
    }
    let span = u32::from(range.hi - range.lo) + 1;
    range.lo + (u32::from(u16::from_le_bytes(bytes)) % span) as u16
}

/// After the first datagram of a burst (junk and signature packets before a handshake, packets
/// queued during one) the engine hands out the rest one call at a time until it is done.
fn drain(tunn: &mut Tunn, buf: &mut [u8], out: &mut Vec<Vec<u8>>) {
    // Only the handshake call advances a burst; asked with nothing pending it would start a
    // handshake of its own, hence the check first.
    while tunn.has_pending_pre_handshake() {
        match tunn.format_handshake_initiation(buf, false) {
            TunnResult::WriteToNetwork(datagram) => out.push(datagram.to_vec()),
            _ => break,
        }
    }
}

struct PeerSession {
    tunn: Tunn,
    public_key: wgconf::Key,
    /// Decrypted packets must come from inside these, and outgoing packets to them go here.
    allowed_ips: Vec<wgconf::IpNet>,
}

/// One peer's counters, for the app's overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStats {
    pub public_key: wgconf::Key,
    pub last_handshake: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The public key belonging to a private key, which is what peers know this tunnel by.
pub fn public_key(private: &wgconf::Key) -> wgconf::Key {
    wgconf::Key(PublicKey::from(&StaticSecret::from(private.0)).to_bytes())
}

/// A fresh private key from the OS's random source, clamped the way `wg genkey` does.
pub fn generate_private_key() -> Result<wgconf::Key, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("reading random bytes: {e}"))?;
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    Ok(wgconf::Key(bytes))
}

/// WireGuard's cryptokey routing: a peer may only send from addresses in its AllowedIPs.
/// BoringTun leaves this check to the caller. Without it a peer could inject packets that look
/// like they came from, say, the local network's DNS server.
fn accept(allowed_ips: &[wgconf::IpNet], packet: &[u8], src: IpAddr, out: &mut Decapsulated) {
    // An empty packet is a keepalive.
    if packet.is_empty() {
        return;
    }
    if allowed_ips.iter().any(|net| net.contains(src)) {
        out.to_tunnel.push(packet.to_vec());
    } else {
        out.rejected += 1;
    }
}

/// Output of feeding one datagram from a peer into the tunnel.
#[derive(Debug, Default)]
pub struct Decapsulated {
    /// Decrypted IP packets to hand to Windows.
    pub to_tunnel: Vec<Vec<u8>>,
    /// Datagrams to send back to the same peer (handshake replies, queued packets).
    pub to_network: Vec<Vec<u8>>,
    pub error: Option<WireGuardError>,
    /// Decrypted packets dropped because their source is outside the peer's AllowedIPs.
    pub rejected: usize,
}

impl Tunnel {
    /// `index` seeds the WireGuard session indexes; the engine uses its low 24 bits per peer.
    /// `obfuscation` is the config's AmneziaWG settings, or the default for plain WireGuard.
    pub fn new(
        interface: &wgconf::Interface,
        peers: &[wgconf::Peer],
        index: u32,
        obfuscation: &Obfuscation,
    ) -> Result<Tunnel, String> {
        let peers = peers
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                let tunn = Tunn::new_with_obfuscation(
                    StaticSecret::from(interface.private_key.0),
                    PublicKey::from(peer.public_key.0),
                    peer.preshared_key.as_ref().map(|k| k.0),
                    peer.persistent_keepalive.map(pick),
                    index.wrapping_add(i as u32) & 0x00FF_FFFF,
                    None,
                    obfuscation.ranges,
                    obfuscation.config.clone(),
                )
                .map_err(|e| format!("peer {}: {e}", i + 1))?;
                Ok(PeerSession {
                    tunn,
                    public_key: peer.public_key.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Tunnel {
            peers,
            buf: vec![0; BUF_LEN],
            wire: Wire {
                ranges: obfuscation.ranges,
                paddings: obfuscation.paddings,
                header_protection: obfuscation.header_protection,
                trailers: obfuscation.trailers,
                config: obfuscation.config.clone(),
            },
        })
    }

    /// What `datagram` is, judged by its length and its message type under the padding, read
    /// through the header protection key when there is one. For the log and for spotting
    /// handshakes.
    pub fn kind(&self, datagram: &[u8]) -> Kind {
        let w = &self.wire;
        let slack = if w.trailers {
            TRAILER_WINDOW as usize
        } else {
            0
        };
        let mask = if w.header_protection {
            match w.config.header_type_mask(datagram) {
                Some(mask) => mask,
                None => return Kind::Other,
            }
        } else {
            [0; 4]
        };
        let kinds = [
            Kind::HandshakeInitiation,
            Kind::HandshakeResponse,
            Kind::CookieReply,
            Kind::Data,
        ];
        for (k, kind) in kinds.into_iter().enumerate() {
            let prefix = w.paddings[k] as usize;
            let base = prefix + BASE_SIZES[k];
            let fits = match kind {
                Kind::Data => datagram.len() >= base,
                _ => (base..=base + slack).contains(&datagram.len()),
            };
            if !fits {
                continue;
            }
            let Some(bytes) = datagram.get(prefix..prefix + 4) else {
                continue;
            };
            let mut bytes: [u8; 4] = bytes.try_into().expect("four bytes");
            for (b, m) in bytes.iter_mut().zip(mask) {
                *b ^= m;
            }
            let message_type = u32::from_le_bytes(bytes);
            let matches = match k {
                0 => w.ranges.matches_h1(message_type),
                1 => w.ranges.matches_h2(message_type),
                2 => w.ranges.matches_h3(message_type),
                _ => w.ranges.matches_h4(message_type),
            };
            if matches {
                return kind;
            }
        }
        Kind::Other
    }

    /// `datagram` for a log line.
    pub fn describe(&self, datagram: &[u8]) -> String {
        match self.kind(datagram) {
            Kind::Data if !self.wire.header_protection => {
                let at = self.wire.paddings[3] as usize + 4;
                let index = u32::from_le_bytes(datagram[at..at + 4].try_into().expect("in range"));
                format!(
                    "data for our session index {index:#x}, {} bytes",
                    datagram.len()
                )
            }
            Kind::Data => format!("data, {} bytes", datagram.len()),
            Kind::Other => format!("unrecognised, {} bytes", datagram.len()),
            kind => kind.name().to_string(),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The peer an outgoing packet goes to: with one peer always that one, otherwise the peer
    /// whose AllowedIPs match the destination most specifically, like WireGuard does.
    fn route(&self, packet: &[u8]) -> Option<usize> {
        if self.peers.len() == 1 {
            return Some(0);
        }
        let dst = Tunn::dst_address(packet)?;
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.allowed_ips.iter().map(move |net| (i, net)))
            .filter(|(_, net)| net.contains(dst))
            .max_by_key(|(_, net)| net.prefix)
            .map(|(i, _)| i)
    }

    /// Encrypts an IP packet and returns which peer it goes to and the datagrams to send, in
    /// order. Without a session yet, the packet is queued and a handshake burst (any junk,
    /// then the initiation) is returned instead. Packets no peer's AllowedIPs cover are
    /// dropped (`Ok(None)`).
    #[allow(clippy::type_complexity)]
    pub fn encapsulate(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<(usize, Vec<Vec<u8>>)>, WireGuardError> {
        let Some(peer) = self.route(packet) else {
            return Ok(None);
        };
        let session = &mut self.peers[peer];
        let first = match session.tunn.encapsulate(packet, &mut self.buf) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            TunnResult::Err(e) => return Err(e),
            _ => return Ok(None),
        };
        let mut out = vec![first];
        drain(&mut session.tunn, &mut self.buf, &mut out);
        Ok(Some((peer, out)))
    }

    /// Decrypts a datagram that arrived from `peer`.
    pub fn decapsulate(&mut self, peer: usize, datagram: &[u8]) -> Decapsulated {
        let mut out = Decapsulated::default();
        let Some(session) = self.peers.get_mut(peer) else {
            out.error = Some(WireGuardError::WrongIndex);
            return out;
        };
        let mut input = datagram;
        loop {
            match session.tunn.decapsulate(None, input, &mut self.buf) {
                // BoringTun wants to be called again with an empty datagram until it is Done,
                // to flush packets that were queued during the handshake.
                TunnResult::WriteToNetwork(datagram) => {
                    out.to_network.push(datagram.to_vec());
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(packet, src) => {
                    accept(&session.allowed_ips, packet, src.into(), &mut out);
                    break;
                }
                TunnResult::WriteToTunnelV6(packet, src) => {
                    accept(&session.allowed_ips, packet, src.into(), &mut out);
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    out.error = Some(e);
                    break;
                }
            }
        }
        out
    }

    /// Starts a handshake with `peer` right away, so it is up before the first packet: the
    /// datagrams to send, in order, which is any junk and then the initiation. Empty when the
    /// engine has nothing to send.
    pub fn handshake(&mut self, peer: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(session) = self.peers.get_mut(peer) else {
            return out;
        };
        // Windows may have handed over packets before this call, and the first of them
        // started the handshake; on a fast link it has completed by now, and starting another
        // would make the peer refuse it as a flood. One still in progress is left alone by the
        // engine itself.
        if session.tunn.time_since_last_handshake().is_some() {
            return out;
        }
        if let TunnResult::WriteToNetwork(datagram) = session
            .tunn
            .format_handshake_initiation(&mut self.buf, false)
        {
            out.push(datagram.to_vec());
            drain(&mut session.tunn, &mut self.buf, &mut out);
        }
        out
    }

    /// Time since the most recent handshake with any peer, if there was one.
    pub fn last_handshake(&self) -> Option<Duration> {
        self.peers
            .iter()
            .filter_map(|p| p.tunn.time_since_last_handshake())
            .min()
    }

    pub fn peer_stats(&self) -> Vec<PeerStats> {
        self.peers
            .iter()
            .map(|p| {
                let (last_handshake, tx, rx, _, _) = p.tunn.stats();
                PeerStats {
                    public_key: p.public_key.clone(),
                    last_handshake,
                    rx_bytes: rx as u64,
                    tx_bytes: tx as u64,
                }
            })
            .collect()
    }

    /// Drives rekeying and keepalives for every peer, returning what to send to whom. Call a
    /// few times per second.
    pub fn tick(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut out = Vec::new();
        for (i, session) in self.peers.iter_mut().enumerate() {
            if let TunnResult::WriteToNetwork(datagram) = session.tunn.update_timers(&mut self.buf)
            {
                let mut burst = vec![datagram.to_vec()];
                drain(&mut session.tunn, &mut self.buf, &mut burst);
                out.extend(burst.into_iter().map(|d| (i, d)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_clamped_and_distinct() {
        let a = generate_private_key().unwrap();
        let b = generate_private_key().unwrap();
        assert_ne!(a.0, b.0);
        for k in [&a, &b] {
            assert_eq!(k.0[0] & 7, 0);
            assert_eq!(k.0[31] & 128, 0);
            assert_eq!(k.0[31] & 64, 64);
            let public = public_key(k);
            assert_eq!(wgconf::Key::from_base64(&public.to_base64()), Some(public));
        }
    }
    use wgconf::{Amnezia, Interface, Key, Peer, Range};

    fn interface(private: [u8; 32]) -> Interface {
        Interface {
            private_key: Key(private),
            listen_port: None,
            addresses: vec!["10.0.0.2/32".parse().unwrap()],
            dns_servers: vec![],
            dns_search: vec![],
            mtu: None,
            amnezia: Amnezia::default(),
        }
    }

    /// A plain WireGuard tunnel.
    fn tunnel(private: [u8; 32], peers: &[Peer], index: u32) -> Tunnel {
        tunnel_with(private, peers, index, &Obfuscation::default())
    }

    fn tunnel_with(private: [u8; 32], peers: &[Peer], index: u32, obf: &Obfuscation) -> Tunnel {
        Tunnel::new(&interface(private), peers, index, obf).unwrap()
    }

    /// The one datagram a plain handshake produces.
    fn init(t: &mut Tunnel, peer: usize) -> Vec<u8> {
        let mut burst = t.handshake(peer);
        assert_eq!(burst.len(), 1, "a plain handshake is one datagram");
        burst.remove(0)
    }

    /// Encrypts `packet`, expecting one datagram for one peer.
    fn one(t: &mut Tunnel, packet: &[u8]) -> (usize, Vec<u8>) {
        let (peer, mut datagrams) = t.encapsulate(packet).unwrap().expect("a datagram");
        assert_eq!(datagrams.len(), 1, "one datagram");
        (peer, datagrams.remove(0))
    }

    fn peer(private_of_peer: [u8; 32]) -> Peer {
        peer_with(private_of_peer, "0.0.0.0/0")
    }

    fn peer_with(private_of_peer: [u8; 32], allowed: &str) -> Peer {
        let public = PublicKey::from(&StaticSecret::from(private_of_peer));
        Peer {
            public_key: Key(public.to_bytes()),
            preshared_key: Some(Key([7; 32])),
            allowed_ips: allowed
                .split(',')
                .map(|s| s.trim().parse().unwrap())
                .collect(),
            endpoint: None,
            persistent_keepalive: None,
        }
    }

    /// Client and server tunnels that trust each other.
    fn pair() -> (Tunnel, Tunnel) {
        let (a, b) = ([1; 32], [2; 32]);
        (tunnel(a, &[peer(b)], 1), tunnel(b, &[peer(a)], 2))
    }

    /// Minimal IPv4/UDP packet; BoringTun only checks the header length fields.
    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        ipv4([10, 0, 0, 2], [10, 0, 0, 1], payload)
    }

    fn ipv4_packet_from(src: [u8; 4], payload: &[u8]) -> Vec<u8> {
        ipv4(src, [10, 0, 0, 1], payload)
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            17,
            0,
            0,
        ];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    /// Runs a full handshake between `client`'s peer `peer` and `server`'s only peer.
    fn connect(client: &mut Tunnel, peer: usize, server: &mut Tunnel) {
        let reply = server.decapsulate(0, &init(client, peer));
        client.decapsulate(peer, &reply.to_network[0]);
        let (_, first) = one(client, &ipv4_packet(b"hi"));
        server.decapsulate(0, &first);
    }

    #[test]
    fn drops_packets_from_outside_allowed_ips() {
        let (a, b) = ([1; 32], [2; 32]);
        let mut client = tunnel(a, &[peer_with(b, "10.0.0.0/8")], 1);
        let mut server = tunnel(b, &[peer(a)], 2);
        connect(&mut client, 0, &mut server);

        let inside = ipv4_packet_from([10, 9, 9, 9], b"ok");
        let (_, datagram) = one(&mut server, &inside);
        let out = client.decapsulate(0, &datagram);
        assert_eq!((out.to_tunnel, out.rejected), (vec![inside], 0));

        // A packet claiming to come from the LAN's DNS server must not get through.
        let spoofed = ipv4_packet_from([192, 168, 1, 1], b"evil");
        let (_, datagram) = one(&mut server, &spoofed);
        let out = client.decapsulate(0, &datagram);
        assert!(out.to_tunnel.is_empty());
        assert_eq!(out.rejected, 1);
    }

    #[test]
    fn handshake_then_data_both_ways() {
        let (mut client, mut server) = pair();
        let packet = ipv4_packet(b"hello");

        // No session yet: the packet is queued and a handshake initiation goes out.
        let (peer, init) = one(&mut client, &packet);
        assert_eq!(peer, 0);
        assert_eq!(client.kind(&init), Kind::HandshakeInitiation);

        let reply = server.decapsulate(0, &init);
        assert!(reply.error.is_none());
        assert!(reply.to_tunnel.is_empty());
        assert_eq!(reply.to_network.len(), 1, "handshake response");

        // The response completes the handshake and flushes the queued packet, along with a
        // keepalive that confirms the session to the server.
        let flushed = client.decapsulate(0, &reply.to_network[0]);
        assert!(flushed.error.is_none());
        assert!(!flushed.to_network.is_empty());

        let received: Vec<_> = flushed
            .to_network
            .iter()
            .flat_map(|d| {
                let out = server.decapsulate(0, d);
                assert!(out.error.is_none());
                out.to_tunnel
            })
            .collect();
        assert_eq!(received, vec![packet]);

        let answer = ipv4_packet(b"hi back");
        let (_, datagram) = one(&mut server, &answer);
        assert_eq!(client.kind(&datagram), Kind::Data);
        assert_eq!(client.decapsulate(0, &datagram).to_tunnel, vec![answer]);

        // Both sides count what went through.
        let stats = &client.peer_stats()[0];
        assert!(stats.last_handshake.is_some());
        assert!(stats.tx_bytes > 0 && stats.rx_bytes > 0);
    }

    #[test]
    fn explicit_handshake() {
        let (mut client, mut server) = pair();
        let init = init(&mut client, 0);
        let reply = server.decapsulate(0, &init);
        let done = client.decapsulate(0, &reply.to_network[0]);
        assert!(done.error.is_none());

        // The session is up, so data goes out directly, and another explicit handshake is
        // not started on top of it.
        let packet = ipv4_packet(b"x");
        let (_, datagram) = one(&mut client, &packet);
        assert_eq!(server.decapsulate(0, &datagram).to_tunnel, vec![packet]);
        assert!(client.handshake(0).is_empty());
    }

    #[test]
    fn routes_to_the_most_specific_peer() {
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let peers = [
            peer_with(b, "10.0.0.0/8"),
            peer_with(c, "10.1.0.0/16, 172.16.0.0/12"),
        ];
        let mut client = tunnel(a, &peers, 1);
        let mut server_b = tunnel(b, &[peer(a)], 2);
        let mut server_c = tunnel(c, &[peer(a)], 3);
        assert_eq!(client.peer_count(), 2);

        let to = |dst| ipv4([10, 0, 0, 2], dst, b"x");
        assert_eq!(client.route(&to([10, 9, 9, 9])), Some(0));
        assert_eq!(
            client.route(&to([10, 1, 2, 3])),
            Some(1),
            "longest prefix wins"
        );
        assert_eq!(client.route(&to([172, 20, 0, 1])), Some(1));
        assert_eq!(client.route(&to([8, 8, 8, 8])), None);
        assert!(client.encapsulate(&to([8, 8, 8, 8])).unwrap().is_none());

        // Each peer gets its own session, and data reaches the right server.
        let reply = server_b.decapsulate(0, &init(&mut client, 0));
        client.decapsulate(0, &reply.to_network[0]);
        let reply = server_c.decapsulate(0, &init(&mut client, 1));
        client.decapsulate(1, &reply.to_network[0]);

        let packet = to([172, 20, 0, 1]);
        let (peer, datagram) = one(&mut client, &packet);
        assert_eq!(peer, 1);
        assert_eq!(server_c.decapsulate(0, &datagram).to_tunnel, vec![packet]);
        assert!(server_b.decapsulate(0, &datagram).to_tunnel.is_empty());
    }

    #[test]
    fn public_key_matches_handshake_identity() {
        // `peer([1; 32])` is how the other side sees the client with private key [1; 32].
        assert_eq!(public_key(&Key([1; 32])), peer([1; 32]).public_key);
        assert_ne!(public_key(&Key([1; 32])), public_key(&Key([2; 32])));
    }

    #[test]
    fn rejects_garbage_and_unknown_peers() {
        let (_, mut server) = pair();
        let out = server.decapsulate(0, &[1, 2, 3, 4]);
        assert!(out.error.is_some());
        assert!(out.to_tunnel.is_empty() && out.to_network.is_empty());
        assert!(server.decapsulate(5, &[1, 2, 3, 4]).error.is_some());
    }

    #[test]
    fn rejects_wrong_peer() {
        let (mut client, _) = pair();
        let stranger = [3; 32];
        let mut other = tunnel(stranger, &[peer([1; 32])], 3);
        let init = init(&mut client, 0);
        let out = other.decapsulate(0, &init);
        assert!(out.error.is_some());
        assert!(out.to_network.is_empty());
    }

    /// AmneziaWG 1.0 settings: paddings, and the four message types when `headers` is set.
    fn awg(headers: bool, junk: u16) -> Obfuscation {
        let a = Amnezia {
            junk_count: junk,
            junk_min: 40,
            junk_max: 80,
            paddings: [15, 40, 0, 0],
            headers: if headers {
                [
                    Some(Range::single(1234567)),
                    Some(Range::single(2345678)),
                    Some(Range::single(3456789)),
                    Some(Range::single(4567890)),
                ]
            } else {
                [None; 4]
            },
            ..Default::default()
        };
        crate::settings::obfuscation(&a, 1420).unwrap()
    }

    fn type_at(datagram: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(datagram[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn amnezia_1_0_handshake_and_data() {
        let obf = awg(true, 0);
        let mut client = tunnel_with([1; 32], &[peer([2; 32])], 1, &obf);
        let mut server = tunnel_with([2; 32], &[peer([1; 32])], 2, &obf);

        // The initiation carries S1 bytes of padding and then the H1 type.
        let init = init(&mut client, 0);
        assert_eq!(init.len(), 148 + 15);
        assert_eq!(type_at(&init, 15), 1234567);
        assert_eq!(client.kind(&init), Kind::HandshakeInitiation);

        let reply = server.decapsulate(0, &init);
        assert!(reply.error.is_none(), "{:?}", reply.error);
        assert_eq!(reply.to_network.len(), 1);
        assert_eq!(reply.to_network[0].len(), 92 + 40);
        assert_eq!(type_at(&reply.to_network[0], 40), 2345678);
        assert_eq!(server.kind(&reply.to_network[0]), Kind::HandshakeResponse);
        assert!(client.decapsulate(0, &reply.to_network[0]).error.is_none());

        let packet = ipv4_packet(b"obfuscated");
        let (_, datagram) = one(&mut client, &packet);
        assert_eq!(type_at(&datagram, 0), 4567890);
        assert_eq!(client.kind(&datagram), Kind::Data);
        assert_eq!(server.decapsulate(0, &datagram).to_tunnel, vec![packet]);

        // A plain WireGuard peer makes nothing of it.
        let (_, mut plain) = pair();
        assert!(plain.decapsulate(0, &init).error.is_some());
        assert_eq!(plain.kind(&init), Kind::Other);
    }

    #[test]
    fn junk_precedes_the_handshake() {
        let obf = awg(false, 3);
        let mut client = tunnel_with([1; 32], &[peer([2; 32])], 1, &obf);
        let mut server = tunnel_with([2; 32], &[peer([1; 32])], 2, &obf);

        let burst = client.handshake(0);
        assert_eq!(burst.len(), 4, "three junk datagrams, then the initiation");
        for junk in &burst[..3] {
            assert!(
                (40..=80).contains(&junk.len()),
                "junk of {} bytes",
                junk.len()
            );
            assert_eq!(client.kind(junk), Kind::Other);
        }
        assert_eq!(client.kind(&burst[3]), Kind::HandshakeInitiation);

        // The server shrugs the junk off and answers the initiation.
        for junk in &burst[..3] {
            assert!(server.decapsulate(0, junk).to_network.is_empty());
        }
        let reply = server.decapsulate(0, &burst[3]);
        assert_eq!(reply.to_network.len(), 1);
        assert!(client.decapsulate(0, &reply.to_network[0]).error.is_none());

        // Without a session, the first packet brings the burst along too.
        let mut fresh = tunnel_with([1; 32], &[peer([2; 32])], 3, &obf);
        let (_, burst) = fresh.encapsulate(&ipv4_packet(b"x")).unwrap().unwrap();
        assert_eq!(burst.len(), 4);
        assert_eq!(fresh.kind(&burst[3]), Kind::HandshakeInitiation);
    }

    #[test]
    fn signature_packets_lead_the_burst() {
        let a = Amnezia {
            junk_count: 1,
            junk_min: 40,
            junk_max: 40,
            signature_packets: [
                Some("<b 0xf6ab3267fa><r 8>".into()),
                None,
                Some("<rd 6>".into()),
                None,
                None,
            ],
            ..Default::default()
        };
        let obf = crate::settings::obfuscation(&a, 1420).unwrap();
        let mut client = tunnel_with([1; 32], &[peer([2; 32])], 1, &obf);
        let mut server = tunnel_with([2; 32], &[peer([1; 32])], 2, &obf);

        let burst = client.handshake(0);
        assert_eq!(burst.len(), 4, "I1, I3, one junk datagram, the initiation");
        assert_eq!(&burst[0][..5], &[0xf6, 0xab, 0x32, 0x67, 0xfa]);
        assert_eq!(burst[0].len(), 13);
        assert_eq!(burst[1].len(), 6);
        assert!(burst[1].iter().all(u8::is_ascii_digit));
        assert_eq!(burst[2].len(), 40);
        assert_eq!(client.kind(&burst[3]), Kind::HandshakeInitiation);

        // Every handshake sends fresh ones, and the server answers as usual.
        let again = client.handshake(0);
        assert!(again.is_empty(), "a handshake is already in progress");
        let reply = server.decapsulate(0, &burst[3]);
        assert_eq!(reply.to_network.len(), 1);
        assert!(client.decapsulate(0, &reply.to_network[0]).error.is_none());
    }

    #[test]
    fn amnezia_3_1_handshake_and_data() {
        let a = Amnezia {
            paddings: [16, 24, 20, 12],
            headers: [
                Some(Range {
                    lo: 100000,
                    hi: 200000,
                }),
                Some(Range {
                    lo: 300000,
                    hi: 400000,
                }),
                Some(Range {
                    lo: 500000,
                    hi: 600000,
                }),
                Some(Range {
                    lo: 700000,
                    hi: 800000,
                }),
            ],
            header_protection_key: Some(Key([9; 32])),
            content_padding_addition: Some(Range { lo: 0, hi: 64 }),
            random_trailers: true,
            disable_cookies: true,
            ..Default::default()
        };
        let obf = crate::settings::obfuscation(&a, 1420).unwrap();
        let mut client = tunnel_with([1; 32], &[peer([2; 32])], 1, &obf);
        let mut server = tunnel_with([2; 32], &[peer([1; 32])], 2, &obf);

        let init = init(&mut client, 0);
        assert!(init.len() >= 148 + 16);
        assert_eq!(client.kind(&init), Kind::HandshakeInitiation);
        let reply = server.decapsulate(0, &init);
        assert!(reply.error.is_none(), "{:?}", reply.error);
        assert_eq!(reply.to_network.len(), 1);
        assert_eq!(server.kind(&reply.to_network[0]), Kind::HandshakeResponse);
        assert!(client.decapsulate(0, &reply.to_network[0]).error.is_none());

        let packet = ipv4_packet(b"protected");
        let (_, datagram) = one(&mut client, &packet);
        assert_eq!(client.kind(&datagram), Kind::Data);
        assert_eq!(
            client.describe(&datagram),
            format!("data, {} bytes", datagram.len())
        );
        assert_eq!(server.decapsulate(0, &datagram).to_tunnel, vec![packet]);
        let back = ipv4_packet(b"and back");
        let (_, datagram) = one(&mut server, &back);
        assert_eq!(client.decapsulate(0, &datagram).to_tunnel, vec![back]);
    }

    #[test]
    fn describes_datagrams() {
        let (mut client, mut server) = pair();
        let init = init(&mut client, 0);
        assert_eq!(client.describe(&init), "handshake initiation");
        let reply = server.decapsulate(0, &init);
        assert_eq!(client.describe(&reply.to_network[0]), "handshake response");
        client.decapsulate(0, &reply.to_network[0]);
        let (_, datagram) = one(&mut client, &ipv4_packet(b"x"));
        assert!(
            client
                .describe(&datagram)
                .starts_with("data for our session index")
        );
        assert_eq!(client.describe(&[1, 2, 3]), "unrecognised, 3 bytes");
    }

    #[test]
    fn keepalive_is_drawn_from_its_range() {
        assert_eq!(pick(Range::single(7)), 7);
        for _ in 0..200 {
            let v = pick(Range { lo: 15, hi: 25 });
            assert!((15..=25).contains(&v));
        }
    }
}
