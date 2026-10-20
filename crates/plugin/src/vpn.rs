//! Windows side of the plugin: the background task, `IVpnPlugIn` and the DLL entry points.
//!
//! Windows runs the background task for every VPN event and hands the event to
//! `VpnChannel::ProcessEventAsync`, which calls back into `Plugin`. Windows reads datagrams from
//! the peer off our UDP socket and passes them to `Decapsulate`; packets leaving the PC arrive in
//! `Encapsulate`. A timer thread drives WireGuard's rekeying and keepalives.

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use windows::Win32::System::WinRT::{
    IActivationFactory, IActivationFactory_Impl, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows_collections::{IIterable, IVectorView};
use windows_core::{
    Error, HRESULT, HSTRING, IInspectable, Interface, OutRef, Ref, Result, implement,
};

use crate::tunnel::Tunnel;
use crate::winrt::{Context, E_FAIL, host_names, read_buffer, write_buffer};
use crate::{profile, settings, store};

/// Class name the package manifest registers for the background task.
pub const TASK_CLASS: &str = "WireGuardW11.VpnBackgroundTask";

const TICK_INTERVAL: Duration = Duration::from_millis(250);
const STOP_TIMEOUT: Duration = Duration::from_secs(8);

const S_OK: HRESULT = HRESULT(0);
const S_FALSE: HRESULT = HRESULT(1);
const CLASS_E_CLASSNOTAVAILABLE: HRESULT = HRESULT(0x8004_0111_u32 as i32);

/// The connected tunnel. Windows may hand each event to a new plugin object, so state lives here.
static SESSION: Mutex<Option<Arc<Session>>> = Mutex::new(None);

struct Session {
    tunnel: Mutex<Tunnel>,
    channel: VpnChannel,
    /// Owned by Windows once associated; kept so it lives as long as the session.
    _socket: DatagramSocket,
    /// Set once Start returned. Sending through the channel before that deadlocks.
    started: AtomicBool,
    stop: AtomicBool,
    stats: Stats,
}

/// Counters for the status lines in plugin.log.
#[derive(Default)]
struct Stats {
    packets_out: AtomicU64,
    datagrams_out: AtomicU64,
    datagrams_in: AtomicU64,
    packets_in: AtomicU64,
    send_errors: AtomicU64,
}

impl Stats {
    fn add(counter: &AtomicU64, n: usize) {
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

impl Session {
    /// Sends a datagram outside of Windows' packet callbacks, for handshakes and timers.
    fn send(&self, datagram: &[u8]) -> Result<()> {
        if !self.started.load(Ordering::Relaxed) {
            return Err(Error::new(E_FAIL, "the VPN channel has not started yet"));
        }
        let result =
            new_packet(&self.channel, VpnDataPathType::Send, datagram).and_then(|packet| {
                self.channel.AppendVpnSendPacketBuffer(&packet)?;
                self.channel.FlushVpnSendPacketBuffers()
            });
        match &result {
            Ok(()) => Stats::add(&self.stats.datagrams_out, 1),
            Err(_) => Stats::add(&self.stats.send_errors, 1),
        }
        result
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
            "status: handshake {handshake}; out {} packets / {} datagrams; in {} datagrams / {} packets; {} send errors",
            get(&s.packets_out),
            get(&s.datagrams_out),
            get(&s.datagrams_in),
            get(&s.packets_in),
            get(&s.send_errors),
        )
    }
}

/// Exits the host once its connection is over. The Connect event of a finished connection never
/// completes, and Windows kills its host 90 seconds after the disconnect, taking any newer
/// connection in the same process with it. Exiting now gives the next connect a fresh host.
fn retire_host() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(500));
        if current_session().is_none() {
            file_log("exiting the host process");
            std::process::exit(0);
        }
    });
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
    }
}

/// Factory for the background task class, for whichever process Windows loads us into.
pub fn activation_factory(class: &HSTRING) -> Option<IActivationFactory> {
    (*class == TASK_CLASS).then(|| Factory.into())
}

#[implement(IBackgroundTask)]
struct BackgroundTask;

impl IBackgroundTask_Impl for BackgroundTask_Impl {
    fn Run(&self, task: Ref<IBackgroundTaskInstance>) -> Result<()> {
        let task = task.ok()?;
        let result = VpnChannel::ProcessEventAsync(plugin(), &task.TriggerDetails()?);
        if let Err(e) = &result {
            file_log(&format!("handling a VPN event failed: {}", e.message()));
        }
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
        let mut tunnel = lock(&session.tunnel);
        let stats = &session.stats;

        for _ in 0..packets.Size()? {
            let packet = packets.RemoveAtBegin()?;
            let buffer = packet.Buffer()?;
            Stats::add(&stats.packets_out, 1);
            match tunnel.encapsulate(&read_buffer(&buffer)?) {
                // Reuse the packet's own buffer when the encrypted datagram fits.
                Ok(Some(datagram)) if datagram.len() <= buffer.Capacity()? as usize => {
                    write_buffer(&buffer, &datagram)?;
                    encapsulated.Append(&packet)?;
                    Stats::add(&stats.datagrams_out, 1);
                }
                Ok(Some(datagram)) => {
                    encapsulated.Append(&new_packet(channel, VpnDataPathType::Send, &datagram)?)?;
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

        let data = read_buffer(&datagram.ok()?.Buffer()?)?;
        let out = lock(&session.tunnel).decapsulate(&data);
        Stats::add(&session.stats.datagrams_in, 1);
        Stats::add(&session.stats.packets_in, out.to_tunnel.len());
        Stats::add(&session.stats.datagrams_out, out.to_network.len());
        if let Some(e) = out.error {
            log(channel, &format!("dropping incoming datagram: {e:?}"));
        }
        for packet in &out.to_tunnel {
            decapsulated
                .ok()?
                .Append(&new_packet(channel, VpnDataPathType::Receive, packet)?)?;
        }
        for reply in &out.to_network {
            control
                .ok()?
                .Append(&new_packet(channel, VpnDataPathType::Send, reply)?)?;
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
    log(
        channel,
        &format!(
            "connecting tunnel `{name}` to {}:{}",
            s.endpoint.host, s.endpoint.port
        ),
    );

    // The socket must be associated before it connects, so Windows keeps it outside the tunnel.
    let socket = DatagramSocket::new().context("creating the UDP socket")?;
    channel
        .AssociateTransport(&socket, None::<&IInspectable>)
        .context("associating the UDP socket")?;
    host(&s.endpoint.host)
        .and_then(|peer| socket.ConnectAsync(&peer, &HSTRING::from(s.endpoint.port.to_string())))
        .and_then(|op| op.join())
        .context(&format!("reaching {}:{}", s.endpoint.host, s.endpoint.port))?;

    let ipv4 = host_list(s.ipv4_addresses.iter().map(ToString::to_string))?;
    let ipv6 = host_list(s.ipv6_addresses.iter().map(ToString::to_string))?;
    let routes = routes(s).context("setting up routes")?;
    let dns = dns(s).context("setting up DNS")?;

    // Windows may hand us packets as soon as the channel starts, so the session exists first.
    let session = Arc::new(Session {
        tunnel: Mutex::new(Tunnel::new(setup.interface, setup.peer, session_index())),
        channel: channel.clone(),
        _socket: socket.clone(),
        started: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        stats: Stats::default(),
    });
    *lock(&SESSION) = Some(session.clone());

    let started = channel
        .StartWithMainTransport(
            ipv4.as_ref(),
            ipv6.as_ref(),
            None::<&VpnInterfaceId>,
            &routes,
            &dns,
            s.mtu,
            s.max_frame_size,
            false,
            &socket,
        )
        .context("starting the VPN interface");
    if let Err(e) = started {
        stop_session();
        return Err(e);
    }
    session.started.store(true, Ordering::Relaxed);
    log(channel, "connected");

    // Handshake right away, so the tunnel is up before the first packet needs it.
    let handshake = lock(&session.tunnel).handshake();
    if let Some(datagram) = handshake
        && let Err(e) = session.send(&datagram)
    {
        log(
            channel,
            &format!("first handshake not sent, will retry: {e}"),
        );
    }
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
    while !session.stop.load(Ordering::Relaxed) {
        std::thread::sleep(TICK_INTERVAL);
        ticks += 1;
        // Status after 1, 3 and 10 seconds, then every minute.
        if matches!(ticks, 4 | 12 | 40) || ticks.is_multiple_of(240) {
            file_log(&session.status());
        }
        let datagram = lock(&session.tunnel).tick();
        if let Ok(Some(datagram)) = datagram {
            // A lost keepalive or handshake is retried on a later tick.
            let _ = session.send(&datagram);
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
