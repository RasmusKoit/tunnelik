//! WireGuard sessions with a tunnel's peers, on top of BoringTun. Nothing here depends on
//! Windows, so the packet flow can be tested anywhere.

use std::net::IpAddr;
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Scratch space for one datagram. BoringTun needs at least packet length + 32 bytes.
const BUF_LEN: usize = 65536 + 32;

pub struct Tunnel {
    peers: Vec<PeerSession>,
    buf: Vec<u8>,
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
    /// `index` seeds the WireGuard session indexes; BoringTun uses its low 24 bits per peer.
    pub fn new(interface: &wgconf::Interface, peers: &[wgconf::Peer], index: u32) -> Tunnel {
        let peers = peers
            .iter()
            .enumerate()
            .map(|(i, peer)| PeerSession {
                tunn: Tunn::new(
                    StaticSecret::from(interface.private_key.0),
                    PublicKey::from(peer.public_key.0),
                    peer.preshared_key.as_ref().map(|k| k.0),
                    peer.persistent_keepalive,
                    index.wrapping_add(i as u32) & 0x00FF_FFFF,
                    None,
                ),
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.clone(),
            })
            .collect();
        Tunnel {
            peers,
            buf: vec![0; BUF_LEN],
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

    /// Encrypts an IP packet and returns which peer it goes to. Without a session yet, the
    /// packet is queued and a handshake initiation is returned instead. Packets no peer's
    /// AllowedIPs cover are dropped (`Ok(None)`).
    pub fn encapsulate(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<(usize, Vec<u8>)>, WireGuardError> {
        let Some(peer) = self.route(packet) else {
            return Ok(None);
        };
        match self.peers[peer].tunn.encapsulate(packet, &mut self.buf) {
            TunnResult::WriteToNetwork(datagram) => Ok(Some((peer, datagram.to_vec()))),
            TunnResult::Err(e) => Err(e),
            _ => Ok(None),
        }
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

    /// Starts a handshake with `peer` right away, so it is up before the first packet.
    pub fn handshake(&mut self, peer: usize) -> Option<Vec<u8>> {
        let session = self.peers.get_mut(peer)?;
        match session
            .tunn
            .format_handshake_initiation(&mut self.buf, false)
        {
            TunnResult::WriteToNetwork(datagram) => Some(datagram.to_vec()),
            _ => None,
        }
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
                out.push((i, datagram.to_vec()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wgconf::{Interface, Key, Peer};

    fn interface(private: [u8; 32]) -> Interface {
        Interface {
            private_key: Key(private),
            listen_port: None,
            addresses: vec!["10.0.0.2/32".parse().unwrap()],
            dns_servers: vec![],
            dns_search: vec![],
            mtu: None,
        }
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
        (
            Tunnel::new(&interface(a), &[peer(b)], 1),
            Tunnel::new(&interface(b), &[peer(a)], 2),
        )
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
        let reply = server.decapsulate(0, &client.handshake(peer).unwrap());
        client.decapsulate(peer, &reply.to_network[0]);
        let (_, first) = client.encapsulate(&ipv4_packet(b"hi")).unwrap().unwrap();
        server.decapsulate(0, &first);
    }

    #[test]
    fn drops_packets_from_outside_allowed_ips() {
        let (a, b) = ([1; 32], [2; 32]);
        let mut client = Tunnel::new(&interface(a), &[peer_with(b, "10.0.0.0/8")], 1);
        let mut server = Tunnel::new(&interface(b), &[peer(a)], 2);
        connect(&mut client, 0, &mut server);

        let inside = ipv4_packet_from([10, 9, 9, 9], b"ok");
        let (_, datagram) = server.encapsulate(&inside).unwrap().unwrap();
        let out = client.decapsulate(0, &datagram);
        assert_eq!((out.to_tunnel, out.rejected), (vec![inside], 0));

        // A packet claiming to come from the LAN's DNS server must not get through.
        let spoofed = ipv4_packet_from([192, 168, 1, 1], b"evil");
        let (_, datagram) = server.encapsulate(&spoofed).unwrap().unwrap();
        let out = client.decapsulate(0, &datagram);
        assert!(out.to_tunnel.is_empty());
        assert_eq!(out.rejected, 1);
    }

    #[test]
    fn handshake_then_data_both_ways() {
        let (mut client, mut server) = pair();
        let packet = ipv4_packet(b"hello");

        // No session yet: the packet is queued and a handshake initiation goes out.
        let (peer, init) = client
            .encapsulate(&packet)
            .unwrap()
            .expect("handshake initiation");
        assert_eq!(peer, 0);

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
        let (_, datagram) = server.encapsulate(&answer).unwrap().expect("data packet");
        assert_eq!(client.decapsulate(0, &datagram).to_tunnel, vec![answer]);

        // Both sides count what went through.
        let stats = &client.peer_stats()[0];
        assert!(stats.last_handshake.is_some());
        assert!(stats.tx_bytes > 0 && stats.rx_bytes > 0);
    }

    #[test]
    fn explicit_handshake() {
        let (mut client, mut server) = pair();
        let init = client.handshake(0).expect("handshake initiation");
        let reply = server.decapsulate(0, &init);
        let done = client.decapsulate(0, &reply.to_network[0]);
        assert!(done.error.is_none());

        // The session is up, so data goes out directly.
        let packet = ipv4_packet(b"x");
        let (_, datagram) = client.encapsulate(&packet).unwrap().unwrap();
        assert_eq!(server.decapsulate(0, &datagram).to_tunnel, vec![packet]);
    }

    #[test]
    fn routes_to_the_most_specific_peer() {
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let peers = [
            peer_with(b, "10.0.0.0/8"),
            peer_with(c, "10.1.0.0/16, 172.16.0.0/12"),
        ];
        let mut client = Tunnel::new(&interface(a), &peers, 1);
        let mut server_b = Tunnel::new(&interface(b), &[peer(a)], 2);
        let mut server_c = Tunnel::new(&interface(c), &[peer(a)], 3);
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
        let reply = server_b.decapsulate(0, &client.handshake(0).unwrap());
        client.decapsulate(0, &reply.to_network[0]);
        let reply = server_c.decapsulate(0, &client.handshake(1).unwrap());
        client.decapsulate(1, &reply.to_network[0]);

        let packet = to([172, 20, 0, 1]);
        let (peer, datagram) = client.encapsulate(&packet).unwrap().unwrap();
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
        let mut other = Tunnel::new(&interface(stranger), &[peer([1; 32])], 3);
        let init = client.handshake(0).unwrap();
        let out = other.decapsulate(0, &init);
        assert!(out.error.is_some());
        assert!(out.to_network.is_empty());
    }
}
