//! Windows side of the plugin: the background task, `IVpnPlugIn` and the DLL entry points.
//!
//! Windows runs the background task for every VPN event and hands the event to
//! `VpnChannel::ProcessEventAsync`, which calls back into `Plugin`. Windows reads datagrams from
//! the peer off our UDP socket and passes them to `Decapsulate`; packets leaving the PC arrive in
//! `Encapsulate`. A timer thread drives WireGuard's rekeying and keepalives.

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::ApplicationModel::Background::{
    IBackgroundTask, IBackgroundTask_Impl, IBackgroundTaskInstance,
};
use windows::Networking::HostName;
use windows::Networking::Sockets::DatagramSocket;
use windows::Networking::Vpn::{
    IVpnPlugIn, IVpnPlugIn_Impl, VpnChannel, VpnDataPathType, VpnDomainNameAssignment,
    VpnDomainNameInfo, VpnDomainNameType, VpnInterfaceId, VpnPacketBuffer, VpnPacketBufferList,
    VpnRoute, VpnRouteAssignment,
};
use windows::Storage::ApplicationData;
use windows::Win32::System::Com::IAgileObject;
use windows::Win32::System::WinRT::{
    IActivationFactory, IActivationFactory_Impl, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows_collections::{IIterable, IVectorView};
use windows_core::{
    Error, HRESULT, HSTRING, IInspectable, Interface, OutRef, Ref, Result, implement,
};

use windows::Foundation::{IReference, PropertyValue};

use crate::tunnel::Tunnel;
use crate::winrt::{Context, E_FAIL, host_names, read_buffer, write_buffer};
use crate::{live, profile, settings, store};

/// Class name the package manifest registers for the background task.
pub const TASK_CLASS: &str = "Tunnelik.VpnBackgroundTask";

const TICK_INTERVAL: Duration = Duration::from_millis(250);
const STOP_TIMEOUT: Duration = Duration::from_secs(8);

const S_OK: HRESULT = HRESULT(0);
const S_FALSE: HRESULT = HRESULT(1);
const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x8004_0111_u32 as i32);

/// The connected tunnel. Windows may hand each event to a new plugin object, so state lives here.
static SESSION: Mutex<Option<Arc<Session>>> = Mutex::new(None);

struct Session {
    name: String,
    tunnel: Mutex<Tunnel>,
    channel: VpnChannel,
    /// One UDP connection per peer. Owned by Windows once associated; kept so they live as long
    /// as the session.
    _sockets: Vec<DatagramSocket>,
    /// With several peers, the transport context that tags each peer's connection, by peer
    /// index. Empty for a single peer, which uses the channel's one main transport.
    contexts: Vec<AgileContext>,
    /// Set once Start returned. Sending through the channel before that deadlocks.
    started: AtomicBool,
    stop: AtomicBool,
    stats: Stats,
}

/// A transport context that is known to be usable from any thread.
struct AgileContext(IInspectable);

impl AgileContext {
    /// A boxed peer index. Windows' boxed values are agile; checked rather than assumed.
    fn new(peer: u32) -> Result<AgileContext> {
        let context = PropertyValue::CreateUInt32(peer)?;
        context.cast::<IAgileObject>()?;
        Ok(AgileContext(context))
    }
}

// SAFETY: `new` only accepts objects that implement IAgileObject, which may be called from any
// thread.
unsafe impl Send for AgileContext {}
unsafe impl Sync for AgileContext {}

/// Counters for the status lines in plugin.log.
#[derive(Default)]
struct Stats {
    packets_out: AtomicU64,
    datagrams_out: AtomicU64,
    datagrams_in: AtomicU64,
    packets_in: AtomicU64,
    send_errors: AtomicU64,
    /// Incoming packets not passed to Windows: from outside AllowedIPs, or too big to deliver.
    dropped: AtomicU64,
    encapsulate: Timing,
    decapsulate: Timing,
}

impl Stats {
    fn add(counter: &AtomicU64, n: usize) {
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// How often a callback ran and how long it took in total, to tell the time spent in our code
/// apart from Windows' own overhead per packet.
#[derive(Default)]
struct Timing {
    calls: AtomicU64,
    nanos: AtomicU64,
}

impl Timing {
    fn record(&self, started: Instant) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.nanos
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn summary(&self) -> String {
        let calls = self.calls.load(Ordering::Relaxed);
        let micros = self.nanos.load(Ordering::Relaxed) / 1000;
        let average = micros.checked_div(calls).unwrap_or(0);
        format!(
            "{calls} calls, {} ms total, {average} µs each",
            micros / 1000
        )
    }
}

/// Records a callback's time when it returns, however it returns.
struct TimingGuard<'a>(&'a Timing, Instant);

impl Drop for TimingGuard<'_> {
    fn drop(&mut self) {
        self.0.record(self.1);
    }
}

/// Background task runs (one per VPN event Windows delivers) in this process.
static RUNS: Timing = Timing {
    calls: AtomicU64::new(0),
    nanos: AtomicU64::new(0),
};

impl Session {
    /// Sends a datagram to `peer` outside of Windows' packet callbacks, for handshakes and
    /// timers.
    fn send(&self, peer: usize, datagram: &[u8]) -> Result<()> {
        if !self.started.load(Ordering::Relaxed) {
            return Err(Error::new(E_FAIL, "the VPN channel has not started yet"));
        }
        let result =
            new_packet(&self.channel, VpnDataPathType::Send, datagram).and_then(|packet| {
                self.address(&packet, peer)?;
                self.channel.AppendVpnSendPacketBuffer(&packet)?;
                self.channel.FlushVpnSendPacketBuffers()
            });
        match &result {
            Ok(()) => Stats::add(&self.stats.datagrams_out, 1),
            Err(_) => Stats::add(&self.stats.send_errors, 1),
        }
        result
    }

    /// Points an outgoing datagram at `peer`'s connection. A single peer has only one.
    fn address(&self, packet: &VpnPacketBuffer, peer: usize) -> Result<()> {
        match self.contexts.get(peer) {
            Some(context) => packet.SetTransportContext(&context.0),
            None => Ok(()),
        }
    }

    /// Which peer an incoming datagram came from, by the connection it arrived on.
    fn peer_of(&self, datagram: &VpnPacketBuffer) -> Option<usize> {
        if self.contexts.is_empty() {
            return Some(0);
        }
        let context = datagram
            .TransportContext()
            .or_else(|_| self.channel.CurrentRequestTransportContext())
            .ok()?;
        let index = context.cast::<IReference<u32>>().ok()?.Value().ok()?;
        Some(index as usize)
    }

    /// Writes the live status the app shows; see `live`.
    fn write_live(&self) {
        let now = unix_now();
        let peers = lock(&self.tunnel)
            .peer_stats()
            .into_iter()
            .map(|p| live::PeerLive {
                public_key: p.public_key.to_base64(),
                last_handshake: p
                    .last_handshake
                    .map(|age| now.saturating_sub(age.as_secs())),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            })
            .collect();
        let text = live::encode(&live::Live {
            tunnel: self.name.clone(),
            updated: now,
            peers,
        });
        if let Ok(dir) = local_state() {
            let temp = dir.join(format!("{}.tmp", live::FILE));
            if std::fs::write(&temp, text).is_ok() {
                let _ = std::fs::rename(&temp, dir.join(live::FILE));
            }
        }
    }

    fn status(&self) -> String {
        let tunnel = lock(&self.tunnel);
        let handshake = match tunnel.last_handshake() {
            Some(age) => format!("{}s ago", age.as_secs()),
            None => "none yet".into(),
        };
        let s = &self.stats;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "status: handshake {handshake}; out {} packets / {} datagrams; in {} datagrams / {} packets; {} send errors; {} dropped; encapsulate {}; decapsulate {}; task runs {}",
            get(&s.packets_out),
            get(&s.datagrams_out),
            get(&s.datagrams_in),
            get(&s.packets_in),
            get(&s.send_errors),
            get(&s.dropped),
            s.encapsulate.summary(),
            s.decapsulate.summary(),
            RUNS.summary(),
        )
    }
}

/// Exits the host once its connection is over. The Connect event of a finished connection never
/// completes, and Windows kills its host 90 seconds after the disconnect, taking any newer
/// connection in the same process with it. Exiting now gives the next connect a fresh host.
fn retire_host() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(500));
        // When switching tunnels the next Connect may already run here, before it has a session.
        if current_session().is_none() && CONNECTING.load(Ordering::SeqCst) == 0 {
            file_log("exiting the host process");
            std::process::exit(0);
        }
    });
}

/// Connects in progress in this process, so retire_host doesn't exit underneath one.
static CONNECTING: AtomicUsize = AtomicUsize::new(0);

struct ConnectInProgress;

impl ConnectInProgress {
    fn start() -> Self {
        CONNECTING.fetch_add(1, Ordering::SeqCst);
        ConnectInProgress
    }
}

impl Drop for ConnectInProgress {
    fn drop(&mut self) {
        CONNECTING.fetch_sub(1, Ordering::SeqCst);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn current_session() -> Option<Arc<Session>> {
    lock(&SESSION).clone()
}

fn stop_session() {
    if let Some(session) = lock(&SESSION).take() {
        session.stop.store(true, Ordering::Relaxed);
        if let Ok(dir) = local_state() {
            let _ = std::fs::remove_file(dir.join(live::FILE));
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Factory for the background task class, for whichever process Windows loads us into.
pub fn activation_factory(class: &HSTRING) -> Option<IActivationFactory> {
    (*class == TASK_CLASS).then(|| Factory.into())
}

#[implement(IBackgroundTask)]
struct BackgroundTask;

impl IBackgroundTask_Impl for BackgroundTask_Impl {
    fn Run(&self, task: Ref<IBackgroundTaskInstance>) -> Result<()> {
        let started = Instant::now();
        let task = task.ok()?;
        let result = VpnChannel::ProcessEventAsync(plugin(), &task.TriggerDetails()?);
        if let Err(e) = &result {
            file_log(&format!("handling a VPN event failed: {}", e.message()));
        }
        RUNS.record(started);
        result
    }
}

/// Windows must get the same plugin object for every event; with a fresh one per event, packets
/// still flow but Disconnect never arrives.
fn plugin() -> &'static IVpnPlugIn {
    struct Shared(IVpnPlugIn);
    // SAFETY: `Plugin` is stateless and, like every `#[implement]` object, agile, so its
    // interface may be used from any thread.
    unsafe impl Send for Shared {}
    unsafe impl Sync for Shared {}
    static PLUGIN: OnceLock<Shared> = OnceLock::new();
    &PLUGIN.get_or_init(|| Shared(Plugin.into())).0
}

#[implement(IVpnPlugIn)]
struct Plugin;

impl IVpnPlugIn_Impl for Plugin_Impl {
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let _in_progress = ConnectInProgress::start();
        let channel = channel.ok()?;
        if let Err(message) = connect(channel) {
            log(channel, &message);
            // TerminateConnection shows the message in Settings; SetErrorMessage isn't supported.
            let _ = channel.TerminateConnection(&HSTRING::from(&message));
        }
        Ok(())
    }

    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        if let Some(session) = current_session() {
            file_log(&session.status());
        }
        file_log("disconnecting");
        stop_session();

        // Stop only completes from inside this callback: once it returns, Windows' own teardown
        // takes the channel lock and calls Stop itself, which deadlocks. Bound the wait anyway.
        let channel = channel.ok()?.clone();
        let (done, stopped) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(channel.Stop());
        });
        match stopped.recv_timeout(STOP_TIMEOUT) {
            Ok(Ok(())) => file_log("channel stopped"),
            Ok(Err(e)) => file_log(&format!("stopping the channel failed: {}", e.message())),
            Err(_) => file_log("stopping the channel timed out"),
        }
        retire_host();
        Ok(())
    }

    fn GetKeepAlivePayload(
        &self,
        _channel: Ref<VpnChannel>,
        packet: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        // WireGuard sends its own keepalives from the timer thread.
        packet.write(None)
    }

    fn Encapsulate(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulated: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let (channel, packets, encapsulated) = (channel.ok()?, packets.ok()?, encapsulated.ok()?);
        let Some(session) = current_session() else {
            // Not connected yet: drop the packets, but hand the buffers back to Windows.
            while packets.Size()? > 0 {
                packets.RemoveAtBegin()?;
            }
            return Ok(());
        };
        let started = Instant::now();
        let mut tunnel = lock(&session.tunnel);
        let stats = &session.stats;
        let _timing = TimingGuard(&stats.encapsulate, started);

        for _ in 0..packets.Size()? {
            let packet = packets.RemoveAtBegin()?;
            let buffer = packet.Buffer()?;
            Stats::add(&stats.packets_out, 1);
            match tunnel.encapsulate(&read_buffer(&buffer)?) {
                // Reuse the packet's own buffer when the encrypted datagram fits.
                Ok(Some((peer, datagram))) if datagram.len() <= buffer.Capacity()? as usize => {
                    write_buffer(&buffer, &datagram)?;
                    session.address(&packet, peer)?;
                    encapsulated.Append(&packet)?;
                    Stats::add(&stats.datagrams_out, 1);
                }
                Ok(Some((peer, datagram))) => {
                    let out = new_packet(channel, VpnDataPathType::Send, &datagram)?;
                    session.address(&out, peer)?;
                    encapsulated.Append(&out)?;
                    Stats::add(&stats.datagrams_out, 1);
                }
                Ok(None) => {}
                Err(e) => log(channel, &format!("dropping outgoing packet: {e:?}")),
            }
        }
        Ok(())
    }

    fn Decapsulate(
        &self,
        channel: Ref<VpnChannel>,
        datagram: Ref<VpnPacketBuffer>,
        decapsulated: Ref<VpnPacketBufferList>,
        control: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        let channel = channel.ok()?;
        let Some(session) = current_session() else {
            return Ok(());
        };
        let _timing = TimingGuard(&session.stats.decapsulate, Instant::now());

        let datagram = datagram.ok()?;
        let Some(peer) = session.peer_of(datagram) else {
            Stats::add(&session.stats.dropped, 1);
            return Ok(());
        };
        let data = read_buffer(&datagram.Buffer()?)?;
        let out = lock(&session.tunnel).decapsulate(peer, &data);
        Stats::add(&session.stats.datagrams_in, 1);
        let stats = &session.stats;
        Stats::add(&stats.dropped, out.rejected);
        if let Some(e) = out.error {
            log_drop(&format!(
                "dropping incoming datagram from peer {}: {e:?} ({})",
                peer + 1,
                describe_datagram(&data)
            ));
        }
        // One packet that doesn't fit Windows' buffer (say, the peer uses a larger MTU) is
        // dropped on its own, rather than failing the whole call and everything after it.
        for packet in &out.to_tunnel {
            match new_packet(channel, VpnDataPathType::Receive, packet) {
                Ok(buffer) => {
                    decapsulated.ok()?.Append(&buffer)?;
                    Stats::add(&stats.packets_in, 1);
                }
                Err(_) => Stats::add(&stats.dropped, 1),
            }
        }
        for reply in &out.to_network {
            match new_packet(channel, VpnDataPathType::Send, reply) {
                Ok(buffer) => {
                    session.address(&buffer, peer)?;
                    control.ok()?.Append(&buffer)?;
                    Stats::add(&stats.datagrams_out, 1);
                }
                Err(_) => Stats::add(&stats.send_errors, 1),
            }
        }
        Ok(())
    }
}

/// Error messages here end up in Settings, so they are written for the user.
fn connect(channel: &VpnChannel) -> std::result::Result<(), String> {
    // A new connection replaces whatever is left of the previous one.
    stop_session();

    let custom = channel
        .Configuration()
        .and_then(|c| c.CustomField())
        .context("reading the VPN profile")?;
    let name = profile::tunnel_name(&custom.to_string())?;
    let text = store::load(&local_state()?, &name)?;
    let config = wgconf::parse(&text).map_err(|e| format!("invalid WireGuard config: {e}"))?;
    let setup = settings::from_config(&config)?;
    let s = &setup.settings;
    let servers: Vec<String> = s
        .endpoints
        .iter()
        .map(|e| format!("{}:{}", e.host, e.port))
        .collect();
    log(
        channel,
        &format!("connecting tunnel `{name}` to {}", servers.join(", ")),
    );

    // Each socket must be associated before it connects, so Windows keeps it outside the
    // tunnel. A single peer uses the channel's main transport, the path Windows' own samples
    // use; several peers each get an extra transport, tagged with the peer's index.
    let multi = s.endpoints.len() > 1;
    let mut sockets = Vec::new();
    let mut contexts = Vec::new();
    for (i, endpoint) in s.endpoints.iter().enumerate() {
        let socket = DatagramSocket::new().context("creating the UDP socket")?;
        if multi {
            let context = AgileContext::new(i as u32).context("tagging a connection")?;
            channel
                .AddAndAssociateTransport(&socket, &context.0)
                .context("associating a UDP socket")?;
            contexts.push(context);
        } else {
            channel
                .AssociateTransport(&socket, None::<&IInspectable>)
                .context("associating the UDP socket")?;
        }
        host(&endpoint.host)
            .and_then(|peer| socket.ConnectAsync(&peer, &HSTRING::from(endpoint.port.to_string())))
            .and_then(|op| op.join())
            .context(&format!("reaching {}", servers[i]))?;
        sockets.push(socket);
    }

    let ipv4 = host_list(s.ipv4_addresses.iter().map(ToString::to_string))?;
    let ipv6 = host_list(s.ipv6_addresses.iter().map(ToString::to_string))?;
    let routes = routes(s).context("setting up routes")?;
    let dns = dns(s).context("setting up DNS")?;

    // Windows may hand us packets as soon as the channel starts, so the session exists first.
    let main = sockets[0].clone();
    let session = Arc::new(Session {
        name,
        tunnel: Mutex::new(Tunnel::new(setup.interface, setup.peers, session_index())),
        channel: channel.clone(),
        _sockets: sockets,
        contexts,
        started: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        stats: Stats::default(),
    });
    *lock(&SESSION) = Some(session.clone());

    let started = if multi {
        channel.StartExistingTransports(
            ipv4.as_ref(),
            ipv6.as_ref(),
            None::<&VpnInterfaceId>,
            &routes,
            &dns,
            s.mtu,
            s.max_frame_size,
            false,
        )
    } else {
        channel.StartWithMainTransport(
            ipv4.as_ref(),
            ipv6.as_ref(),
            None::<&VpnInterfaceId>,
            &routes,
            &dns,
            s.mtu,
            s.max_frame_size,
            false,
            &main,
        )
    }
    .context("starting the VPN interface");
    if let Err(e) = started {
        stop_session();
        return Err(e);
    }
    session.started.store(true, Ordering::Relaxed);
    log(channel, "connected");

    // Handshake right away, so each peer is up before the first packet needs it.
    for (peer, server) in servers.iter().enumerate() {
        let handshake = lock(&session.tunnel).handshake(peer);
        if let Some(datagram) = handshake
            && let Err(e) = session.send(peer, &datagram)
        {
            log(
                channel,
                &format!("first handshake not sent to {server}, will retry: {e}"),
            );
        }
    }
    session.write_live();
    let timers = session.clone();
    std::thread::spawn(move || run_timers(&timers));
    Ok(())
}

fn local_state() -> std::result::Result<PathBuf, String> {
    ApplicationData::Current()
        .and_then(|data| data.LocalFolder())
        .and_then(|folder| folder.Path())
        .map(|path| PathBuf::from(path.to_os_string()))
        .context("finding the app's data folder")
}

fn run_timers(session: &Session) {
    // SAFETY: called once at the start of a thread we own.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };

    let mut ticks: u64 = 0;
    let mut handshakes: Vec<Option<Duration>> = Vec::new();
    while !session.stop.load(Ordering::Relaxed) {
        std::thread::sleep(TICK_INTERVAL);
        ticks += 1;

        // Log each completed handshake, to line rekeys up with anything else in the log.
        let now: Vec<Option<Duration>> = lock(&session.tunnel)
            .peer_stats()
            .iter()
            .map(|p| p.last_handshake)
            .collect();
        for (peer, age) in now.iter().enumerate() {
            let before = handshakes.get(peer).copied().flatten();
            if let Some(age) = age
                && before.is_none_or(|b| *age < b)
            {
                file_log(&format!("handshake with peer {} completed", peer + 1));
            }
        }
        handshakes = now;
        // Status after 1, 3 and 10 seconds, then every minute.
        if matches!(ticks, 4 | 12 | 40) || ticks.is_multiple_of(240) {
            file_log(&session.status());
        }
        // The app's overview, every 2 seconds.
        if ticks.is_multiple_of(8) {
            session.write_live();
        }
        let outgoing = lock(&session.tunnel).tick();
        for (peer, datagram) in outgoing {
            // A lost keepalive or handshake is retried on a later tick.
            let _ = session.send(peer, &datagram);
        }
    }
}

fn routes(s: &settings::ChannelSettings) -> Result<VpnRouteAssignment> {
    let routes = VpnRouteAssignment::new()?;
    let ipv4 = routes.Ipv4InclusionRoutes()?;
    for (addr, prefix) in &s.ipv4_routes {
        ipv4.Append(&VpnRoute::CreateVpnRoute(
            &host(&addr.to_string())?,
            *prefix,
        )?)?;
    }
    let ipv6 = routes.Ipv6InclusionRoutes()?;
    for (addr, prefix) in &s.ipv6_routes {
        ipv6.Append(&VpnRoute::CreateVpnRoute(
            &host(&addr.to_string())?,
            *prefix,
        )?)?;
    }
    Ok(routes)
}

fn dns(s: &settings::ChannelSettings) -> Result<VpnDomainNameAssignment> {
    let dns = VpnDomainNameAssignment::new()?;
    if s.dns_servers.is_empty() {
        return Ok(dns);
    }
    let names = dns.DomainNameList()?;
    // "." sends every lookup to the tunnel's DNS servers, like the official client does.
    for suffix in std::iter::once(".").chain(s.dns_search.iter().map(String::as_str)) {
        // Windows needs a real, writable vector for the servers.
        let servers = s
            .dns_servers
            .iter()
            .map(|a| host(&a.to_string()))
            .collect::<Result<Vec<_>>>()?;
        let info = VpnDomainNameInfo::CreateVpnDomainNameInfo(
            &HSTRING::from(suffix),
            VpnDomainNameType::Suffix,
            &host_names(servers),
            None::<&IIterable<HostName>>,
        )?;
        names.Append(&info)?;
    }
    Ok(dns)
}

fn host(name: &str) -> Result<HostName> {
    HostName::CreateHostName(&HSTRING::from(name))
}

fn host_list(
    names: impl Iterator<Item = String>,
) -> std::result::Result<Option<IVectorView<HostName>>, String> {
    let hosts = names
        .map(|n| host(&n).map(Some))
        .collect::<Result<Vec<_>>>()
        .context("reading addresses")?;
    Ok((!hosts.is_empty()).then(|| IVectorView::from(hosts)))
}

/// WireGuard session index; BoringTun uses the low 24 bits.
fn session_index() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos & 0x00FF_FFFF
}

/// A packet buffer from Windows' pools, which only exist once the channel has started.
fn new_packet(channel: &VpnChannel, kind: VpnDataPathType, data: &[u8]) -> Result<VpnPacketBuffer> {
    let packet = if kind == VpnDataPathType::Send {
        channel.GetVpnSendPacketBuffer()?
    } else {
        channel.GetVpnReceivePacketBuffer()?
    };
    write_buffer(&packet.Buffer()?, data)?;
    Ok(packet)
}

/// What kind of WireGuard message a datagram is, for log lines.
fn describe_datagram(data: &[u8]) -> String {
    match data.first() {
        Some(1) => "handshake initiation".into(),
        Some(2) => "handshake response".into(),
        Some(3) => "cookie reply".into(),
        Some(4) if data.len() >= 8 => {
            let index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            format!(
                "data for our session index {index:#x}, {} bytes",
                data.len()
            )
        }
        _ => format!("unrecognised, {} bytes", data.len()),
    }
}

/// Logs a dropped datagram, collapsing a burst of identical drops into one line plus a count:
/// a rejected session can produce hundreds of them per second.
fn log_drop(message: &str) {
    static LAST: Mutex<Option<(String, Instant, u64)>> = Mutex::new(None);
    // Data drops differ only by size; compare without it.
    let kind = message.split(", ").next().unwrap_or(message).to_string();
    let mut last = lock(&LAST);
    if let Some((previous, since, repeats)) = last.as_mut()
        && *previous == kind
        && since.elapsed() < Duration::from_secs(5)
    {
        *repeats += 1;
        return;
    }
    if let Some((_, _, repeats)) = last.take()
        && repeats > 0
    {
        file_log(&format!(
            "(the previous drop repeated {repeats} more times)"
        ));
    }
    file_log(message);
    *last = Some((kind, Instant::now(), 0));
}

fn log(channel: &VpnChannel, message: &str) {
    let _ = channel.LogDiagnosticMessage(&HSTRING::from(message));
    file_log(message);
}

/// Appends to `plugin.log` in the package's data folder. Never log key material here.
pub fn file_log(message: &str) {
    use std::io::Write;
    let Ok(dir) = local_state() else {
        return;
    };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m, s) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("plugin.log"))
    {
        let _ = writeln!(file, "{h:02}:{m:02}:{s:02} UTC {message}");
    }
}

#[implement(IActivationFactory)]
struct Factory;

impl IActivationFactory_Impl for Factory_Impl {
    fn ActivateInstance(&self) -> Result<IInspectable> {
        Ok(BackgroundTask.into())
    }
}

/// Called by Windows to create the background task class named in the package manifest.
#[unsafe(no_mangle)]
unsafe extern "system" fn DllGetActivationFactory(
    name: ManuallyDrop<HSTRING>,
    factory: *mut *mut c_void,
) -> HRESULT {
    let result = activation_factory(&name);
    // SAFETY: Windows passes a valid pointer to receive the factory.
    unsafe {
        match result {
            Some(f) => {
                factory.write(f.into_raw());
                S_OK
            }
            None => {
                factory.write(std::ptr::null_mut());
                CLASS_E_CLASSNOTAVAILABLE
            }
        }
    }
}

/// The session lives in a static, so the DLL must stay loaded.
#[unsafe(no_mangle)]
extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}
