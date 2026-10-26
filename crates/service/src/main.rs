//! Tunnelik's privileged helper, `TunnelikMdm`: a Windows service, declared in the package and
//! run as LocalSystem, that applies VPN profiles through Windows' MDM bridge.
//!
//! Windows only dials a VPN on its own, when a program starts or a name is looked up, for the
//! profile it was handed through the VPNv2 configuration service provider. Outside an MDM
//! enrolment that provider is reachable through a WMI bridge that answers only the SYSTEM
//! account, hence this service. It listens on a named pipe, accepts requests from Tunnelik's own
//! package only, and applies or removes one profile per request. The profile XML comes from the
//! caller; the service checks that it names Tunnelik's plugin and nothing else.
//!
//! Requests are plain text: a header line `apply <name> <bytes>`, `remove <name>` or `ping`,
//! followed by `<bytes>` of profile XML for `apply`. The reply is one line, `ok …` or `error: …`.

#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFamilyName;
use windows::Win32::System::IO::CancelIoEx;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_core::{HSTRING, PWSTR};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "TunnelikMdm";
/// Where the app and the `tunnelik` command reach the service.
const PIPE: &str = r"\\.\pipe\Tunnelik.Mdm";
/// Nobody over the network, SYSTEM gets everything, signed-in users may talk to it.
const PIPE_SECURITY: &str = "D:(D;;GA;;;NU)(A;;GA;;;SY)(A;;GRGW;;;AU)";
const MAX_REQUEST: usize = 64 * 1024;

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = stop.clone();
    let handler = match service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_for_handler.store(true, Ordering::SeqCst);
                // Wake the pipe loop out of ConnectNamedPipe.
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(PIPE);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(handler) => handler,
        Err(e) => {
            log(&format!("registering the control handler failed: {e}"));
            return;
        }
    };
    let status = |state: ServiceState, accept: ServiceControlAccept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    };
    let _ = handler.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ));
    log("started");
    let family = own_package_family();
    serve(&stop, &family);
    log("stopping");
    let _ =
        handler.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()));
}

/// One request at a time, until asked to stop.
fn serve(stop: &AtomicBool, family: &str) {
    let security = match pipe_security() {
        Ok(s) => s,
        Err(e) => {
            log(&format!("setting up the pipe's security failed: {e}"));
            return;
        }
    };
    while !stop.load(Ordering::SeqCst) {
        // SAFETY: the name and security attributes live for the call; the handle is closed below.
        let pipe = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(PIPE),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                MAX_REQUEST as u32,
                MAX_REQUEST as u32,
                0,
                Some(&security as *const SECURITY_ATTRIBUTES),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            log("creating the pipe failed");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }
        // SAFETY: `pipe` is a valid pipe handle for the whole block, closed at its end.
        unsafe {
            // A client that opened the pipe between CreateNamedPipeW and here is already
            // connected, which Windows reports as ERROR_PIPE_CONNECTED rather than success.
            let connected = match ConnectNamedPipe(pipe, None) {
                Ok(()) => true,
                Err(e) => e.code() == ERROR_PIPE_CONNECTED.to_hresult(),
            };
            if connected && !stop.load(Ordering::SeqCst) {
                let reply = match handle(pipe, family) {
                    Ok(reply) => format!("ok {reply}\n"),
                    Err(e) => {
                        log(&format!("refused: {e}"));
                        format!("error: {e}\n")
                    }
                };
                // The flush returns only once the client has read the reply.
                with_deadline(pipe, || {
                    let _ = WriteFile(pipe, Some(reply.as_bytes()), None, None);
                    let _ = FlushFileBuffers(pipe);
                });
                let _ = DisconnectNamedPipe(pipe);
            }
            let _ = CloseHandle(pipe);
        }
    }
}

/// Runs `work`, which reads from or writes to `pipe`, cancelling its blocking calls on the pipe
/// once it has taken longer than five seconds, and again until it returns: there is one pipe
/// instance, and a client that connects and then goes quiet would hold it, and so every other
/// request and the service's own stop, forever. A cancelled read ends the request, but the
/// reply's flush then blocks again for a client that never reads. Only pipe I/O is bounded:
/// the PowerShell run in between may be slow, and its reply must still reach the client.
fn with_deadline<T>(pipe: HANDLE, work: impl FnOnce() -> T) -> T {
    use std::sync::mpsc::RecvTimeoutError;
    // Tunnelik writes its request and reads the reply at once; only a stalled client waits.
    const LIMIT: Duration = Duration::from_secs(5);
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let raw = pipe.0 as usize;
    let watchdog = std::thread::spawn(move || {
        let mut wait = LIMIT;
        while let Err(RecvTimeoutError::Timeout) = finished.recv_timeout(wait) {
            // SAFETY: the pipe stays open until this thread has been joined.
            let _ = unsafe { CancelIoEx(HANDLE(raw as *mut std::ffi::c_void), None) };
            wait = Duration::from_millis(250);
        }
    });
    let result = work();
    let _ = done.send(());
    let _ = watchdog.join();
    result
}

/// Reads and carries out one request. The caller must be Tunnelik's own package.
fn handle(pipe: HANDLE, family: &str) -> Result<String, String> {
    let request = with_deadline(pipe, || read_request(pipe))?;
    let caller = caller_package_family(pipe)?;
    if family.is_empty() || !caller.eq_ignore_ascii_case(family) {
        return Err("only Tunnelik may use this service".into());
    }
    let (verb, name, body) = parse_request(&request)?;
    match verb {
        "ping" => Ok("pong".into()),
        "apply" => {
            check_name(name)?;
            check_profile_xml(body, family)?;
            log(&format!("applying the profile for `{name}`"));
            mdm_powershell(APPLY, name, body, family)
        }
        "remove" => {
            check_name(name)?;
            log(&format!("removing the profile for `{name}`"));
            mdm_powershell(REMOVE, name, "", family)
        }
        other => Err(format!("unknown request `{other}`")),
    }
}

/// Splits a request into its verb, profile name and body, checking the announced length.
fn parse_request(request: &str) -> Result<(&str, &str, &str), String> {
    let (header, body) = request.split_once('\n').unwrap_or((request, ""));
    let (verb, name, length) = split_header(header);
    let length: usize = length.unwrap_or("0").parse().unwrap_or(usize::MAX);
    if verb == "apply" && body.len() != length {
        return Err(format!(
            "the request announced {length} bytes of profile XML but carried {}",
            body.len()
        ));
    }
    Ok((verb, name, body))
}

/// `<verb> <name>` or `apply <name> <bytes>`. Tunnel names may contain spaces, so the name is
/// everything between the verb and, for `apply`, the byte count at the end.
fn split_header(header: &str) -> (&str, &str, Option<&str>) {
    let (verb, rest) = header.split_once(' ').unwrap_or((header, ""));
    match rest.rsplit_once(' ') {
        Some((name, length)) if verb == "apply" => (verb, name, Some(length)),
        _ => (verb, rest, None),
    }
}

/// The same rule as the tunnel names Tunnelik accepts, so a name can't carry anything odd into
/// PowerShell or the configuration service provider.
fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.trim() == name
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
    ok.then_some(())
        .ok_or_else(|| format!("invalid profile name `{name}`"))
}

/// The profile must be Tunnelik's plugin profile and nothing else: no native VPN, no proxy.
fn check_profile_xml(xml: &str, family: &str) -> Result<(), String> {
    // Only the elements manage::mdm::profile_xml writes; anything else (WebProxyServers,
    // TrafficFilterList, Route, comments, DOCTYPE, ...) is refused.
    const ALLOWED: [&str; 15] = [
        "Tunnelik",
        "VPNProfile",
        "RememberCredentials",
        "AlwaysOn",
        "PluginProfile",
        "ServerUrlList",
        "PluginPackageFamilyName",
        "CustomConfiguration",
        "AppTrigger",
        "App",
        "Id",
        "DomainNameInformation",
        "DomainName",
        "DnsServers",
        "AutoTrigger",
    ];
    for tag in xml.split('<').skip(1) {
        let tag = tag.strip_prefix('/').unwrap_or(tag);
        let end = tag
            .find(|c: char| c == '>' || c == '/' || c.is_whitespace())
            .unwrap_or(tag.len());
        if !ALLOWED.contains(&&tag[..end]) {
            return Err(format!(
                "the profile contains <{}>, which is not allowed",
                &tag[..end]
            ));
        }
    }
    // Without the `>`: `<PluginPackageFamilyName >` passes the tag check too.
    if xml.matches("<PluginPackageFamilyName").count() != 1 {
        return Err("the profile must name exactly one plugin".into());
    }
    let wanted = format!("<PluginPackageFamilyName>{family}</PluginPackageFamilyName>");
    if !xml.contains(&wanted) {
        return Err("the profile does not name Tunnelik's plugin".into());
    }
    Ok(())
}

const APPLY: &str = r#"
$ErrorActionPreference = 'Stop'
$ns = 'root\cimv2\mdm\dmmap'
$cls = 'MDM_VPNv2_01'
# The CSP's node name is the profile name, URL-escaped.
$id = $env:TUNNELIK_NAME.Replace(' ', '%20')
# Never replace an all-users VPN connection that isn't Tunnelik's, such as one IT deployed.
$c = Get-VpnConnection -AllUserConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
if ($c -and $c.PlugInApplicationID -ne $env:TUNNELIK_FAMILY) { throw "an all-users VPN connection named '$($env:TUNNELIK_NAME)' exists and is not Tunnelik's" }
$escaped = $env:TUNNELIK_XML.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
Get-CimInstance -Namespace $ns -ClassName $cls | Where-Object { $_.InstanceID -eq $id } | Remove-CimInstance
New-CimInstance -Namespace $ns -ClassName $cls -Property @{ ParentID = './Vendor/MSFT/VPNv2'; InstanceID = $id; ProfileXML = $escaped } | Out-Null
'applied'
"#;

const REMOVE: &str = r#"
$ErrorActionPreference = 'Stop'
$ns = 'root\cimv2\mdm\dmmap'
$cls = 'MDM_VPNv2_01'
$id = $env:TUNNELIK_NAME.Replace(' ', '%20')
$existing = Get-CimInstance -Namespace $ns -ClassName $cls | Where-Object { $_.InstanceID -eq $id }
if (-not $existing) { 'absent' } else {
    $c = Get-VpnConnection -AllUserConnection -Name $env:TUNNELIK_NAME -ErrorAction SilentlyContinue
    if ($c -and $c.PlugInApplicationID -ne $env:TUNNELIK_FAMILY) { throw "an all-users VPN connection named '$($env:TUNNELIK_NAME)' exists and is not Tunnelik's" }
    $existing | Remove-CimInstance; 'removed'
}
"#;

/// Runs one of the scripts above as this service's own account (SYSTEM), which the MDM bridge
/// requires. Values travel as environment variables, so nothing in them is parsed as PowerShell.
fn mdm_powershell(script: &str, name: &str, xml: &str, family: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("TUNNELIK_NAME", name)
        .env("TUNNELIK_XML", xml)
        .env("TUNNELIK_FAMILY", family)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("starting PowerShell: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("unknown error");
        return Err(format!("the MDM bridge refused: {}", line.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn read_request(pipe: HANDLE) -> Result<String, String> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let mut read = 0u32;
        // SAFETY: `chunk` outlives the call and `read` receives the byte count.
        let result = unsafe { ReadFile(pipe, Some(&mut chunk), Some(&mut read), None) };
        if result.is_err() || read == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..read as usize]);
        if data.len() > MAX_REQUEST {
            return Err("the request is too large".into());
        }
        if request_complete(&data) {
            break;
        }
    }
    String::from_utf8(data).map_err(|_| "the request is not UTF-8".into())
}

/// Whether everything the header announced has arrived.
fn request_complete(data: &[u8]) -> bool {
    let Some(newline) = data.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let header = String::from_utf8_lossy(&data[..newline]);
    let (verb, _, length) = split_header(&header);
    if verb != "apply" {
        return true;
    }
    let length: usize = length.unwrap_or("0").parse().unwrap_or(0);
    data.len() >= newline + 1 + length
}

/// The package family of whoever opened the pipe, read from their token while impersonating.
fn caller_package_family(pipe: HANDLE) -> Result<String, String> {
    windows_link::link!("kernel32.dll" "system" fn GetPackageFamilyNameFromToken(token: HANDLE, packagefamilynamelength: *mut u32, packagefamilyname: PWSTR) -> u32);
    /// The pseudo-handle for the calling thread's effective token.
    const CURRENT_THREAD_EFFECTIVE_TOKEN: HANDLE = HANDLE(-6isize as *mut std::ffi::c_void);
    // SAFETY: impersonation is undone before returning, whatever happens in between.
    unsafe {
        ImpersonateNamedPipeClient(pipe).map_err(|e| format!("identifying the caller: {e}"))?;
        let mut buffer = [0u16; 256];
        let mut len = buffer.len() as u32;
        let err = GetPackageFamilyNameFromToken(
            CURRENT_THREAD_EFFECTIVE_TOKEN,
            &mut len,
            PWSTR(buffer.as_mut_ptr()),
        );
        let _ = RevertToSelf();
        if err != 0 {
            return Err(format!("the caller has no package identity (error {err})"));
        }
        let len = len.saturating_sub(1) as usize;
        Ok(String::from_utf16_lossy(&buffer[..len.min(buffer.len())]))
    }
}

fn own_package_family() -> String {
    let mut buffer = [0u16; 256];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer and its length are valid for the call.
    let err = unsafe { GetCurrentPackageFamilyName(&mut len, Some(PWSTR(buffer.as_mut_ptr()))) };
    if err.0 != 0 {
        log(&format!(
            "this service has no package identity (error {})",
            err.0
        ));
        return String::new();
    }
    let len = len.saturating_sub(1) as usize;
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

fn pipe_security() -> Result<SECURITY_ATTRIBUTES, String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL string is valid for the call; the descriptor it allocates lives for the
    // process, which is what the pipe needs.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(PIPE_SECURITY),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| e.message())?;
    }
    Ok(SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    })
}

fn log_path() -> PathBuf {
    // Not ProgramData, where any user may create the folder, or files in it, first. Under
    // LogFiles only SYSTEM and administrators may write; users may read.
    let base =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    base.join(r"System32\LogFiles\Tunnelik").join("mdm.log")
}

fn log(message: &str) {
    let path = log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m, s) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{h:02}:{m:02}:{s:02} UTC {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_checks_lengths() {
        let (verb, name, body) = parse_request("apply Infra 12\n<VPNProfile>").unwrap();
        assert_eq!((verb, name, body), ("apply", "Infra", "<VPNProfile>"));
        assert!(parse_request("apply Infra 5\n<VPNProfile>").is_err());
        assert_eq!(
            parse_request("remove Infra\n").unwrap(),
            ("remove", "Infra", "")
        );
        assert_eq!(parse_request("ping\n").unwrap().0, "ping");
        assert_eq!(
            parse_request("apply Home VPN 12\n<VPNProfile>").unwrap(),
            ("apply", "Home VPN", "<VPNProfile>")
        );
        assert_eq!(
            parse_request("remove Home VPN\n").unwrap(),
            ("remove", "Home VPN", "")
        );
    }

    #[test]
    fn knows_when_a_request_is_complete() {
        assert!(!request_complete(b"apply Infra 12"));
        assert!(!request_complete(b"apply Infra 12\n<VPNProfile"));
        assert!(request_complete(b"apply Infra 12\n<VPNProfile>"));
        assert!(!request_complete(b"apply Home VPN 12\n<VPNProfile"));
        assert!(request_complete(b"apply Home VPN 12\n<VPNProfile>"));
        assert!(request_complete(b"remove Infra\n"));
        assert!(request_complete(b"ping\n"));
    }

    #[test]
    fn checks_names_and_profiles() {
        assert!(check_name("Infra").is_ok());
        assert!(check_name("my tunnel-1.0").is_ok());
        for bad in ["", " x", "a/b", "a\\b", ".hidden", &"x".repeat(65)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        let family = "Vendor.App_abc";
        let good = format!(
            "<VPNProfile><PluginProfile><PluginPackageFamilyName>{family}</PluginPackageFamilyName></PluginProfile></VPNProfile>"
        );
        assert!(check_profile_xml(&good, family).is_ok());
        assert!(check_profile_xml(&good, "Other.App_xyz").is_err());
        assert!(check_profile_xml(&format!("{good}<NativeProfile/>"), family).is_err());
        assert!(
            check_profile_xml(
                &format!("{good}<WebProxyServers>x</WebProxyServers>"),
                family
            )
            .is_err()
        );
        assert!(check_profile_xml(&format!("<!DOCTYPE x>{good}"), family).is_err());
    }
}
