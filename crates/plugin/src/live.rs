//! The connected tunnel's live status: written by the plugin to `status.txt` in the package's
//! data folder every few seconds, and read by the app for its overview. Plain lines:
//!
//! ```text
//! tunnel Home
//! updated 1792512000
//! peer <public key> <last handshake, unix seconds, or -> <bytes received> <bytes sent>
//! ```

pub const FILE: &str = "status.txt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    pub tunnel: String,
    /// Unix seconds when the plugin wrote this; old data means the tunnel is gone.
    pub updated: u64,
    pub peers: Vec<PeerLive>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerLive {
    /// Base64, as in the config.
    pub public_key: String,
    /// Unix seconds of the last completed handshake.
    pub last_handshake: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn encode(live: &Live) -> String {
    let mut text = format!("tunnel {}\nupdated {}\n", live.tunnel, live.updated);
    for p in &live.peers {
        let handshake = p
            .last_handshake
            .map_or_else(|| "-".to_string(), |t| t.to_string());
        text.push_str(&format!(
            "peer {} {handshake} {} {}\n",
            p.public_key, p.rx_bytes, p.tx_bytes
        ));
    }
    text
}

pub fn decode(text: &str) -> Option<Live> {
    let mut live = Live {
        tunnel: String::new(),
        updated: 0,
        peers: Vec::new(),
    };
    for line in text.lines() {
        let (kind, rest) = line.split_once(' ')?;
        match kind {
            "tunnel" => live.tunnel = rest.to_string(),
            "updated" => live.updated = rest.parse().ok()?,
            "peer" => {
                let fields: Vec<&str> = rest.split(' ').collect();
                let [key, handshake, rx, tx] = fields.as_slice() else {
                    return None;
                };
                live.peers.push(PeerLive {
                    public_key: key.to_string(),
                    last_handshake: match *handshake {
                        "-" => None,
                        t => Some(t.parse().ok()?),
                    },
                    rx_bytes: rx.parse().ok()?,
                    tx_bytes: tx.parse().ok()?,
                });
            }
            _ => {}
        }
    }
    (!live.tunnel.is_empty()).then_some(live)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let live = Live {
            tunnel: "Home VPN".into(),
            updated: 1_792_512_000,
            peers: vec![
                PeerLive {
                    public_key: "abc+/=".into(),
                    last_handshake: Some(1_792_511_990),
                    rx_bytes: 123_456_789,
                    tx_bytes: 42,
                },
                PeerLive {
                    public_key: "def=".into(),
                    last_handshake: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                },
            ],
        };
        assert_eq!(decode(&encode(&live)), Some(live));
    }

    #[test]
    fn rejects_broken_files() {
        assert_eq!(decode(""), None);
        assert_eq!(decode("updated 5\n"), None);
        assert_eq!(decode("tunnel x\npeer only-two 5\n"), None);
        assert_eq!(decode("tunnel x\nupdated soon\n"), None);
    }
}
