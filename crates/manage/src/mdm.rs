//! Profiles Windows dials on its own, through the `TunnelikMdm` service.
//!
//! Windows only watches for a program starting or a name being looked up on behalf of the one
//! profile it was handed through the VPNv2 configuration service provider, and only the SYSTEM
//! account can reach that provider outside an MDM enrolment. So a tunnel with triggers gets its
//! profile built here as VPNv2 ProfileXML and applied by the package's service, which keeps it
//! in the all-users phonebook as a managed profile. Everything else about the tunnel stays as it
//! is: the plugin reads the same custom configuration, and `rasdial` dials it like any other.

use std::io::{BufRead, BufReader, Write};

/// Where the service listens; the same string as in `crates/service`.
const PIPE: &str = r"\\.\pipe\Tunnelik.Mdm";

/// The ProfileXML for a tunnel: Tunnelik's plugin, the triggers, nothing else.
pub fn profile_xml(
    family: &str,
    server_host: &str,
    custom_configuration: &str,
    always_on: bool,
    dns_servers: &[String],
    app_triggers: &[String],
    dns_triggers: &[String],
) -> String {
    let mut xml = String::from("<VPNProfile>\n  <RememberCredentials>true</RememberCredentials>\n");
    if always_on {
        // Windows' own always on: dialed at sign-in and after network changes, by Windows.
        xml.push_str("  <AlwaysOn>true</AlwaysOn>\n");
    }
    xml.push_str("  <PluginProfile>\n");
    xml.push_str(&format!(
        "    <ServerUrlList>{}</ServerUrlList>\n",
        escape(server_host)
    ));
    xml.push_str(&format!(
        "    <PluginPackageFamilyName>{}</PluginPackageFamilyName>\n",
        escape(family)
    ));
    // Raw XML, as the provider has always received it (the service's escaping used to stop
    // at `&`); the name in it is validated, so there is nothing to escape.
    xml.push_str(&format!(
        "    <CustomConfiguration>{custom_configuration}</CustomConfiguration>\n"
    ));
    xml.push_str("  </PluginProfile>\n");
    for app in app_triggers {
        xml.push_str(&format!(
            "  <AppTrigger>\n    <App>\n      <Id>{}</Id>\n    </App>\n  </AppTrigger>\n",
            escape(app)
        ));
    }
    // Each domain twice: the exact name and, with the leading dot, every name under it. Windows
    // turns these into name-resolution rules that beat the tunnel's catch-all rule, so they
    // name the tunnel's DNS servers too; without them the watched names would be sent to the
    // local network's DNS even while the tunnel is up.
    let servers = dns_servers.join(",");
    for dns in dns_triggers {
        let dns = escape(dns.trim_start_matches('.'));
        for name in [dns.clone(), format!(".{dns}")] {
            xml.push_str("  <DomainNameInformation>\n");
            xml.push_str(&format!("    <DomainName>{name}</DomainName>\n"));
            if !servers.is_empty() {
                xml.push_str(&format!(
                    "    <DnsServers>{}</DnsServers>\n",
                    escape(&servers)
                ));
            }
            xml.push_str("    <AutoTrigger>true</AutoTrigger>\n  </DomainNameInformation>\n");
        }
    }
    xml.push_str("</VPNProfile>\n");
    xml
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Has the service apply `xml` as the managed profile named `name`, replacing an earlier one.
pub fn apply(name: &str, xml: &str) -> Result<(), String> {
    call(&format!("apply {name} {}\n{xml}", xml.len())).map(|_| ())
}

/// Has the service remove the managed profile named `name`, if there is one.
pub fn remove(name: &str) -> Result<(), String> {
    call(&format!("remove {name}\n")).map(|_| ())
}

/// Whether the service is up.
pub fn available() -> bool {
    call("ping\n").is_ok()
}

fn call(request: &str) -> Result<String, String> {
    use std::os::windows::fs::OpenOptionsExt;
    // Whoever serves the pipe may learn who we are, but not act as us.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;
    // The service serves one caller at a time. While it works on someone else's request (an
    // apply takes seconds) the pipe answers ERROR_PIPE_BUSY: wait for a turn rather than
    // reporting the service as off.
    const ERROR_PIPE_BUSY: i32 = 231;
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(PIPE)
    };
    let mut attempt = open();
    for _ in 0..100 {
        match &attempt {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                attempt = open();
            }
            _ => break,
        }
    }
    let mut pipe = attempt.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "Tunnelik's helper service is off (a restart stops it); turn it on under \"Start on its own\", or with `tunnelik trigger enable`".to_string(),
            _ => format!("reaching Tunnelik's helper service: {e}"),
        })?;
    // While the service is stopped, anyone can create a pipe under its name.
    if !served_by_service(&pipe) {
        return Err("the helper service's pipe belongs to another program".into());
    }
    pipe.write_all(request.as_bytes())
        .and_then(|()| pipe.flush())
        .map_err(|e| format!("sending to Tunnelik's helper service: {e}"))?;
    // One line comes back; reading on past it would only see the server hanging up.
    let mut reply = String::new();
    BufReader::new(&pipe)
        .read_line(&mut reply)
        .map_err(|e| format!("hearing back from Tunnelik's helper service: {e}"))?;
    parse_reply(&reply)
}

/// Whether the process at the other end of `pipe` is the running TunnelikMdm service.
fn served_by_service(pipe: &std::fs::File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };
    use windows_core::{PCWSTR, w};

    let mut server = 0u32;
    // SAFETY: the handle is the open pipe's, and `server` receives the id.
    if unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut server) }.is_err() {
        return false;
    }
    // SAFETY: each handle is closed before returning; the status buffer is the size passed.
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) else {
            return false;
        };
        let service = OpenServiceW(scm, w!("TunnelikMdm"), SERVICE_QUERY_STATUS);
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let ok = service.as_ref().is_ok_and(|&service| {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                Some(std::slice::from_raw_parts_mut(
                    (&raw mut status).cast::<u8>(),
                    size_of::<SERVICE_STATUS_PROCESS>(),
                )),
                &mut needed,
            )
            .is_ok()
        });
        if let Ok(service) = service {
            let _ = CloseServiceHandle(service);
        }
        let _ = CloseServiceHandle(scm);
        ok && status.dwProcessId == server
    }
}

fn parse_reply(reply: &str) -> Result<String, String> {
    let line = reply.lines().next().unwrap_or("").trim();
    match line.split_once(' ') {
        Some(("ok", rest)) => Ok(rest.to_string()),
        _ if line == "ok" => Ok(String::new()),
        Some(("error:", rest)) => Err(rest.trim().to_string()),
        _ => Err(format!(
            "unexpected reply from the helper service: `{line}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_profile() {
        let xml = profile_xml(
            "Vendor.App_abc",
            "vpn.example.com",
            "<Tunnelik tunnel=\"Home & Co\"/>",
            true,
            &["10.1.254.1".into(), "10.1.254.2".into()],
            &["C:\\Tools\\a.exe".into()],
            &["corp.example".into(), ".lab.example".into()],
        );
        assert!(xml.starts_with("<VPNProfile>"));
        assert!(xml.contains(
            "<RememberCredentials>true</RememberCredentials>\n  <AlwaysOn>true</AlwaysOn>\n"
        ));
        assert!(xml.contains("<ServerUrlList>vpn.example.com</ServerUrlList>"));
        assert!(xml.contains("<PluginPackageFamilyName>Vendor.App_abc</PluginPackageFamilyName>"));
        assert!(xml.contains(
            "<CustomConfiguration><Tunnelik tunnel=\"Home & Co\"/></CustomConfiguration>"
        ));
        assert!(xml.contains("<Id>C:\\Tools\\a.exe</Id>"));
        // The name itself and everything under it, each resolved through the tunnel.
        assert!(xml.contains("<DomainName>corp.example</DomainName>"));
        assert!(xml.contains("<DomainName>.corp.example</DomainName>"));
        assert!(xml.contains("<DomainName>lab.example</DomainName>"));
        assert!(xml.contains("<DomainName>.lab.example</DomainName>"));
        assert_eq!(xml.matches("<AutoTrigger>true</AutoTrigger>").count(), 4);
        assert_eq!(
            xml.matches("<DnsServers>10.1.254.1,10.1.254.2</DnsServers>")
                .count(),
            4
        );
        assert!(!xml.contains("<NativeProfile"));
    }

    #[test]
    fn leaves_out_what_is_not_set() {
        let xml = profile_xml(
            "Vendor.App_abc",
            "vpn.example.com",
            "<x/>",
            false,
            &[],
            &[],
            &["corp.example".into()],
        );
        assert!(!xml.contains("<AlwaysOn>"));
        assert!(!xml.contains("<DnsServers>"));
        assert!(!xml.contains("<AppTrigger>"));
        assert_eq!(xml.matches("<DomainNameInformation>").count(), 2);
    }

    #[test]
    fn reads_replies() {
        assert_eq!(parse_reply("ok applied\n").unwrap(), "applied");
        assert_eq!(parse_reply("ok\n").unwrap(), "");
        assert_eq!(parse_reply("error: nope\n").unwrap_err(), "nope");
        assert!(parse_reply("").is_err());
    }
}
