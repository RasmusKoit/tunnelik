//! Interop with real AmneziaWG servers, without the Windows VPN platform: the tunnel code talks
//! to a server over a plain UDP socket, handshakes and gets an ICMP echo answered through the
//! session. Run by hand against the lab (three amneziawg-go containers in WSL, see the
//! scratchpad's `awg-lab`), with `TUNNELIK_LAB` pointing at the folder holding
//! `client/awg<generation>.conf`:
//!
//!     cargo test -p tunnelik-plugin --test lab -- --ignored --nocapture

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use tunnelik_plugin::settings;
use tunnelik_plugin::tunnel::{Kind, Tunnel};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 ICMP echo request, checksums included, as a ping would send it.
fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"tunnelik lab echo, 32 bytes....");
    let sum = checksum(&icmp).to_be_bytes();
    icmp[2..4].copy_from_slice(&sum);

    let total = (20 + icmp.len()) as u16;
    let mut ip = vec![
        0x45,
        0,
        total.to_be_bytes()[0],
        total.to_be_bytes()[1],
        0,
        0,
        0x40,
        0,
        64,
        1,
        0,
        0,
    ];
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let sum = checksum(&ip).to_be_bytes();
    ip[10..12].copy_from_slice(&sum);
    ip.extend_from_slice(&icmp);
    ip
}

fn run(generation: &str) {
    let lab = std::env::var("TUNNELIK_LAB").expect("TUNNELIK_LAB: the lab folder");
    let text = std::fs::read_to_string(format!("{lab}/client/awg{generation}.conf")).unwrap();
    let config = wgconf::parse(&text).unwrap();
    let amnezia = &config.interface.amnezia;
    println!(
        "awg{generation}: AmneziaWG {} {:?}",
        amnezia.generation(),
        amnezia.summary()
    );
    let setup = settings::from_config(&config).unwrap();
    let mut tunnel = Tunnel::new(setup.interface, setup.peers, 0x1234, &setup.obfuscation).unwrap();

    let endpoint = &setup.settings.endpoints[0];
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .connect((endpoint.host.as_str(), endpoint.port))
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // The handshake burst, as connect() sends it.
    let started = Instant::now();
    let burst = tunnel.handshake(0);
    let kinds: Vec<_> = burst.iter().map(|d| tunnel.kind(d)).collect();
    let sizes: Vec<_> = burst.iter().map(Vec::len).collect();
    println!(
        "awg{generation}: burst of {} datagrams {sizes:?} {kinds:?}",
        burst.len()
    );
    assert_eq!(kinds.last(), Some(&Kind::HandshakeInitiation));
    for d in &burst {
        socket.send(d).unwrap();
    }

    let mut buf = vec![0u8; 65536];
    let n = socket
        .recv(&mut buf)
        .expect("a handshake response within 3 s");
    assert_eq!(
        tunnel.kind(&buf[..n]),
        Kind::HandshakeResponse,
        "{} bytes back",
        n
    );
    let done = tunnel.decapsulate(0, &buf[..n]);
    assert!(done.error.is_none(), "{:?}", done.error);
    for d in &done.to_network {
        socket.send(d).unwrap();
    }
    assert!(tunnel.peer_stats()[0].last_handshake.is_some());
    println!(
        "awg{generation}: handshake done in {:?}, response of {n} bytes",
        started.elapsed()
    );

    // An echo to the server's tunnel address through the session.
    let me = match config.interface.addresses[0].addr {
        std::net::IpAddr::V4(a) => a,
        _ => panic!("IPv4 lab"),
    };
    let server = Ipv4Addr::new(10, 9, generation.parse().unwrap(), 1);
    for seq in 1..=3u16 {
        let echo = echo_request(me, server, 0xbeef, seq);
        let (_, datagrams) = tunnel.encapsulate(&echo).unwrap().unwrap();
        assert_eq!(datagrams.len(), 1, "data goes out as one datagram");
        assert_eq!(tunnel.kind(&datagrams[0]), Kind::Data);
        let sent = Instant::now();
        socket.send(&datagrams[0]).unwrap();
        let reply = loop {
            let n = socket.recv(&mut buf).expect("an echo reply within 3 s");
            let out = tunnel.decapsulate(0, &buf[..n]);
            assert!(out.error.is_none(), "{:?}", out.error);
            for d in &out.to_network {
                socket.send(d).unwrap();
            }
            if let Some(p) = out
                .to_tunnel
                .into_iter()
                .find(|p| p.len() >= 28 && p[9] == 1 && p[20] == 0)
            {
                break p;
            }
        };
        assert_eq!(&reply[12..16], &server.octets(), "from the server");
        assert_eq!(
            &reply[24..28],
            &[0xbe, 0xef, 0, seq as u8],
            "our id and sequence"
        );
        println!(
            "awg{generation}: echo {seq} answered in {:?}",
            sent.elapsed()
        );
    }
    let stats = &tunnel.peer_stats()[0];
    println!(
        "awg{generation}: tx {} rx {} bytes, handshake {:?} ago",
        stats.tx_bytes, stats.rx_bytes, stats.last_handshake
    );
}

#[test]
#[ignore]
fn awg15() {
    run("15");
}

#[test]
#[ignore]
fn awg20() {
    run("20");
}

#[test]
#[ignore]
fn awg31() {
    run("31");
}
