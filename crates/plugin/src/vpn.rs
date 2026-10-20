//! Windows side of the plugin: the background task, `IVpnPlugIn` and the DLL entry points.
//!
//! Windows runs the background task for every VPN event and hands the event to
//! `VpnChannel::ProcessEventAsync`, which calls back into `Plugin`. Windows reads datagrams from
//! the peer off our UDP socket and passes them to `Decapsulate`; packets leaving the PC arrive in
//! `Encapsulate`. A timer thread drives WireGuard's rekeying and keepalives.

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
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
use crate::winrt::{Context, E_FAIL, read_buffer, write_buffer};
use crate::{profile, settings, store};

/// Class name the package manifest registers for the background task.
pub const TASK_CLASS: &str = "WireGuardW11.VpnBackgroundTask";

const TICK_INTERVAL: Duration = Duration::from_millis(250);

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
    stop: AtomicBool,
}

impl Session {
    /// Sends a datagram outside of Windows' packet callbacks, for handshakes and timers.
    fn send(&self, datagram: &[u8]) -> Result<()> {
        let packet = new_packet(&self.channel, VpnDataPathType::Send, datagram)?;
        self.channel.AppendVpnSendPacketBuffer(&packet)?;
        self.channel.FlushVpnSendPacketBuffers()
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
        let plugin: IVpnPlugIn = Plugin.into();
        let result = VpnChannel::ProcessEventAsync(&plugin, &task.ok()?.TriggerDetails()?);
        if let Err(e) = &result {
            file_log(&format!("handling a VPN event failed: {}", e.message()));
        }
        result
    }
}

#[implement(IVpnPlugIn)]
struct Plugin;

impl IVpnPlugIn_Impl for Plugin_Impl {
    fn Connect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        let channel = channel.ok()?;
        connect(channel).map_err(|message| {
            log(channel, &message);
            let _ = channel.SetErrorMessage(&HSTRING::from(&message));
            Error::new(E_FAIL, message)
        })
    }

    fn Disconnect(&self, channel: Ref<VpnChannel>) -> Result<()> {
        file_log("trace: Disconnect");
        stop_session();
        channel.ok()?.Stop()
    }

    fn GetKeepAlivePayload(
        &self,
        _channel: Ref<VpnChannel>,
        packet: OutRef<VpnPacketBuffer>,
    ) -> Result<()> {
        // WireGuard sends its own keepalives from the timer thread.
        trace_once(&TRACE_KEEPALIVE, "GetKeepAlivePayload");
        packet.write(None)
    }

    fn Encapsulate(
        &self,
        channel: Ref<VpnChannel>,
        packets: Ref<VpnPacketBufferList>,
        encapsulated: Ref<VpnPacketBufferList>,
    ) -> Result<()> {
        trace_once(&TRACE_ENCAP, "Encapsulate");
        let (channel, packets, encapsulated) = (channel.ok()?, packets.ok()?, encapsulated.ok()?);
        let Some(session) = current_session() else {
            // Not connected yet: drop the packets, but hand the buffers back to Windows.
            while packets.Size()? > 0 {
                packets.RemoveAtBegin()?;
            }
            return Ok(());
        };
        let mut tunnel = lock(&session.tunnel);

        for _ in 0..packets.Size()? {
            let packet = packets.RemoveAtBegin()?;
            let buffer = packet.Buffer()?;
            match tunnel.encapsulate(&read_buffer(&buffer)?) {
                // Reuse the packet's own buffer when the encrypted datagram fits.
                Ok(Some(datagram)) if datagram.len() <= buffer.Capacity()? as usize => {
                    write_buffer(&buffer, &datagram)?;
                    encapsulated.Append(&packet)?;
                }
                Ok(Some(datagram)) => {
                    encapsulated.Append(&new_packet(channel, VpnDataPathType::Send, &datagram)?)?;
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
        trace_once(&TRACE_DECAP, "Decapsulate");
        let channel = channel.ok()?;
        let Some(session) = current_session() else {
            return Ok(());
        };

        let data = read_buffer(&datagram.ok()?.Buffer()?)?;
        let out = lock(&session.tunnel).decapsulate(&data);
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

    // Start below only returns when the connection ends, so the session must exist before it.
    let session = Arc::new(Session {
        tunnel: Mutex::new(Tunnel::new(setup.interface, setup.peer, session_index())),
        channel: channel.clone(),
        _socket: socket.clone(),
        stop: AtomicBool::new(false),
    });
    *lock(&SESSION) = Some(session.clone());
    let timers = session.clone();
    std::thread::spawn(move || run_timers(&timers));

    log(channel, "connected");
    let result = channel
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

    let disconnected = session.stop.load(Ordering::Relaxed);
    stop_session();
    log(channel, "connection ended");
    // Once Windows asked us to disconnect, how Start ends doesn't matter.
    if disconnected { Ok(()) } else { result }
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

    // Start the handshake right away, so the tunnel is up before the first packet. If the
    // channel isn't ready yet the send fails, and WireGuard's retry timer sends it again.
    std::thread::sleep(TICK_INTERVAL);
    let handshake = lock(&session.tunnel).handshake();
    if let Some(datagram) = handshake
        && let Err(e) = session.send(&datagram)
    {
        log(
            &session.channel,
            &format!("first handshake not sent, will retry: {e}"),
        );
    }

    while !session.stop.load(Ordering::Relaxed) {
        std::thread::sleep(TICK_INTERVAL);
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
    let servers = s
        .dns_servers
        .iter()
        .map(|a| host(&a.to_string()).map(Some))
        .collect::<Result<Vec<_>>>()?;
    let names = dns.DomainNameList()?;
    // "." sends every lookup to the tunnel's DNS servers, like the official client does.
    for suffix in std::iter::once(".").chain(s.dns_search.iter().map(String::as_str)) {
        let info = VpnDomainNameInfo::CreateVpnDomainNameInfo(
            &HSTRING::from(suffix),
            VpnDomainNameType::Suffix,
            &IIterable::<HostName>::from(servers.clone()),
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

fn new_packet(channel: &VpnChannel, kind: VpnDataPathType, data: &[u8]) -> Result<VpnPacketBuffer> {
    let mut packet = None;
    channel.RequestVpnPacketBuffer(kind, &mut packet)?;
    let packet = packet.ok_or_else(|| Error::new(E_FAIL, "Windows has no free packet buffer"))?;
    write_buffer(&packet.Buffer()?, data)?;
    Ok(packet)
}

fn log(channel: &VpnChannel, message: &str) {
    let _ = channel.LogDiagnosticMessage(&HSTRING::from(message));
    file_log(message);
}

static TRACE_KEEPALIVE: AtomicBool = AtomicBool::new(false);
static TRACE_ENCAP: AtomicBool = AtomicBool::new(false);
static TRACE_DECAP: AtomicBool = AtomicBool::new(false);

/// Logs the first call of a hot callback, to see which ones Windows makes.
fn trace_once(flag: &AtomicBool, what: &str) {
    if !flag.swap(true, Ordering::Relaxed) {
        file_log(&format!(
            "trace: first {what} on {:?}",
            std::thread::current().id()
        ));
    }
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
