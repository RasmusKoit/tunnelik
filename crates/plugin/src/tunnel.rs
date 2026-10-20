//! WireGuard session with a single peer, on top of BoringTun. Nothing here depends on Windows,
//! so the packet flow can be tested anywhere.

use std::net::IpAddr;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Scratch space for one datagram. BoringTun needs at least packet length + 32 bytes.
const BUF_LEN: usize = 65536 + 32;

pub struct Tunnel {
    tunn: Tunn,
    buf: Vec<u8>,
    /// The peer's AllowedIPs: decrypted packets must come from inside them.
    allowed_ips: Vec<wgconf::IpNet>,
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

/// Output of feeding one datagram from the peer into the tunnel.
#[derive(Debug, Default)]
pub struct Decapsulated {
    /// Decrypted IP packets to hand to Windows.
    pub to_tunnel: Vec<Vec<u8>>,
    /// Datagrams to send back to the peer (handshake replies, queued packets).
    pub to_network: Vec<Vec<u8>>,
    pub error: Option<WireGuardError>,
    /// Decrypted packets dropped because their source is outside the peer's AllowedIPs.
    pub rejected: usize,
}

impl Tunnel {
    pub fn new(interface: &wgconf::Interface, peer: &wgconf::Peer, index: u32) -> Tunnel {
        let tunn = Tunn::new(
            StaticSecret::from(interface.private_key.0),
            PublicKey::from(peer.public_key.0),
            peer.preshared_key.as_ref().map(|k| k.0),
            peer.persistent_keepalive,
            index,
            None,
        );
        Tunnel {
            tunn,
            buf: vec![0; BUF_LEN],
            allowed_ips: peer.allowed_ips.clone(),
        }
    }

    /// Encrypts an IP packet for the peer. Without a session yet, the packet is queued and a
    /// handshake initiation is returned instead.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, WireGuardError> {
        match self.tunn.encapsulate(packet, &mut self.buf) {
            TunnResult::WriteToNetwork(datagram) => Ok(Some(datagram.to_vec())),
            TunnResult::Err(e) => Err(e),
            _ => Ok(None),
        }
    }

    pub fn decapsulate(&mut self, datagram: &[u8]) -> Decapsulated {
        let mut out = Decapsulated::default();
        let mut input = datagram;
        loop {
            match self.tunn.decapsulate(None, input, &mut self.buf) {
                // BoringTun wants to be called again with an empty datagram until it is Done,
                // to flush packets that were queued during the handshake.
                TunnResult::WriteToNetwork(datagram) => {
                    out.to_network.push(datagram.to_vec());
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(packet, src) => {
                    accept(&self.allowed_ips, packet, src.into(), &mut out);
                    break;
                }
                TunnResult::WriteToTunnelV6(packet, src) => {
                    accept(&self.allowed_ips, packet, src.into(), &mut out);
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

    /// Starts a handshake right away, so the tunnel is up before the first packet.
    pub fn handshake(&mut self) -> Option<Vec<u8>> {
        match self.tunn.format_handshake_initiation(&mut self.buf, false) {
            TunnResult::WriteToNetwork(datagram) => Some(datagram.to_vec()),
            _ => None,
        }
    }

    /// Time since the last completed handshake, if there was one.
    pub fn last_handshake(&self) -> Option<std::time::Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// Drives rekeying and keepalives. Call a few times per second.
    pub fn tick(&mut self) -> Result<Option<Vec<u8>>, WireGuardError> {
        match self.tunn.update_timers(&mut self.buf) {
            TunnResult::WriteToNetwork(datagram) => Ok(Some(datagram.to_vec())),
            TunnResult::Err(e) => Err(e),
            _ => Ok(None),
        }
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
            addresses: vec!["10.1.254.3/32".parse().unwrap()],
            dns_servers: vec![],
            dns_search: vec![],
            mtu: None,
        }
    }

    fn peer(private_of_peer: [u8; 32]) -> Peer {
        let public = PublicKey::from(&StaticSecret::from(private_of_peer));
        Peer {
            public_key: Key(public.to_bytes()),
            preshared_key: Some(Key([7; 32])),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            endpoint: None,
            persistent_keepalive: None,
        }
    }

    /// Client and server tunnels that trust each other.
    fn pair() -> (Tunnel, Tunnel) {
        let (a, b) = ([1; 32], [2; 32]);
        (
            Tunnel::new(&interface(a), &peer(b), 1),
            Tunnel::new(&interface(b), &peer(a), 2),
        )
    }

    /// Minimal IPv4/UDP packet; BoringTun only checks the header length fields.
    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        ipv4_packet_from([10, 1, 254, 3], payload)
    }

    fn ipv4_packet_from(src: [u8; 4], payload: &[u8]) -> Vec<u8> {
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
        p.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn drops_packets_from_outside_allowed_ips() {
        let (a, b) = ([1; 32], [2; 32]);
        let mut split_peer = peer(b);
        split_peer.allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
        let mut client = Tunnel::new(&interface(a), &split_peer, 1);
        let mut server = Tunnel::new(&interface(b), &peer(a), 2);

        // Handshake, then a first data packet so the server may send too.
        let reply = server.decapsulate(&client.handshake().unwrap());
        client.decapsulate(&reply.to_network[0]);
        let first = client.encapsulate(&ipv4_packet(b"hi")).unwrap().unwrap();
        server.decapsulate(&first);

        let inside = ipv4_packet_from([10, 9, 9, 9], b"ok");
        let datagram = server.encapsulate(&inside).unwrap().unwrap();
        let out = client.decapsulate(&datagram);
        assert_eq!((out.to_tunnel, out.rejected), (vec![inside], 0));

        // A packet claiming to come from the LAN's DNS server must not get through.
        let spoofed = ipv4_packet_from([192, 168, 1, 1], b"evil");
        let datagram = server.encapsulate(&spoofed).unwrap().unwrap();
        let out = client.decapsulate(&datagram);
        assert!(out.to_tunnel.is_empty());
        assert_eq!(out.rejected, 1);
    }

    #[test]
    fn handshake_then_data_both_ways() {
        let (mut client, mut server) = pair();
        let packet = ipv4_packet(b"hello");

        // No session yet: the packet is queued and a handshake initiation goes out.
        let init = client
            .encapsulate(&packet)
            .unwrap()
            .expect("handshake initiation");

        let reply = server.decapsulate(&init);
        assert!(reply.error.is_none());
        assert!(reply.to_tunnel.is_empty());
        assert_eq!(reply.to_network.len(), 1, "handshake response");

        // The response completes the handshake and flushes the queued packet, along with a
        // keepalive that confirms the session to the server.
        let flushed = client.decapsulate(&reply.to_network[0]);
        assert!(flushed.error.is_none());
        assert!(!flushed.to_network.is_empty());

        let received: Vec<_> = flushed
            .to_network
            .iter()
            .flat_map(|d| {
                let out = server.decapsulate(d);
                assert!(out.error.is_none());
                out.to_tunnel
            })
            .collect();
        assert_eq!(received, vec![packet]);

        let answer = ipv4_packet(b"hi back");
        let datagram = server.encapsulate(&answer).unwrap().expect("data packet");
        assert_eq!(client.decapsulate(&datagram).to_tunnel, vec![answer]);
    }

    #[test]
    fn explicit_handshake() {
        let (mut client, mut server) = pair();
        let init = client.handshake().expect("handshake initiation");
        let reply = server.decapsulate(&init);
        let done = client.decapsulate(&reply.to_network[0]);
        assert!(done.error.is_none());

        // The session is up, so data goes out directly.
        let packet = ipv4_packet(b"x");
        let datagram = client.encapsulate(&packet).unwrap().unwrap();
        assert_eq!(server.decapsulate(&datagram).to_tunnel, vec![packet]);
    }

    #[test]
    fn public_key_matches_handshake_identity() {
        // `peer([1; 32])` is how the other side sees the client with private key [1; 32].
        assert_eq!(public_key(&Key([1; 32])), peer([1; 32]).public_key);
        assert_ne!(public_key(&Key([1; 32])), public_key(&Key([2; 32])));
    }

    #[test]
    fn rejects_garbage() {
        let (_, mut server) = pair();
        let out = server.decapsulate(&[1, 2, 3, 4]);
        assert!(out.error.is_some());
        assert!(out.to_tunnel.is_empty() && out.to_network.is_empty());
    }

    #[test]
    fn rejects_wrong_peer() {
        let (mut client, _) = pair();
        let stranger = [3; 32];
        let mut other = Tunnel::new(&interface(stranger), &peer([1; 32]), 3);
        let init = client.handshake().unwrap();
        let out = other.decapsulate(&init);
        assert!(out.error.is_some());
        assert!(out.to_network.is_empty());
    }
}
