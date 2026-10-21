//! Profiles Windows dials on its own, through the `TunnelikMdm` service.
//!
//! Windows only watches for a program starting or a name being looked up on behalf of the one
//! profile it was handed through the VPNv2 configuration service provider, and only the SYSTEM
//! account can reach that provider outside an MDM enrolment. So a tunnel with triggers gets its
//! profile built here as VPNv2 ProfileXML and applied by the package's service, which keeps it
//! in the all-users phonebook as a managed profile. Everything else about the tunnel stays as it
//! is: the plugin reads the same custom configuration, and `rasdial` dials it like any other.

use std::io::{Read, Write};

/// Where the service listens; the same string as in `crates/service`.
const PIPE: &str = r"\\.\pipe\Tunnelik.Mdm";

/// The ProfileXML for a tunnel: Tunnelik's plugin, the triggers, nothing else.
pub fn profile_xml(
    family: &str,
    server_host: &str,
    custom_configuration: &str,
    app_triggers: &[String],
    dns_triggers: &[String],
) -> String {
    let mut xml = String::from("<VPNProfile>\n  <RememberCredentials>true</RememberCredentials>\n");
    xml.push_str("  <PluginProfile>\n");
    xml.push_str(&format!(
        "    <ServerUrlList>{}</ServerUrlList>\n",
        escape(server_host)
    ));
    xml.push_str(&format!(
        "    <PluginPackageFamilyName>{}</PluginPackageFamilyName>\n",
        escape(family)
    ));
    xml.push_str(&format!(
        "    <CustomConfiguration>{}</CustomConfiguration>\n",
        escape(custom_configuration)
    ));
    xml.push_str("  </PluginProfile>\n");
    for app in app_triggers {
        xml.push_str(&format!(
            "  <AppTrigger>\n    <App>\n      <Id>{}</Id>\n    </App>\n  </AppTrigger>\n",
            escape(app)
        ));
    }
    for dns in dns_triggers {
        xml.push_str(&format!(
            "  <DomainNameInformation>\n    <DomainName>.{}</DomainName>\n    <AutoTrigger>true</AutoTrigger>\n  </DomainNameInformation>\n",
            escape(dns.trim_start_matches('.'))
        ));
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
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "Tunnelik's helper service (TunnelikMdm) is not running; it starts with Windows once the package is installed with administrator approval".to_string(),
            _ => format!("reaching Tunnelik's helper service: {e}"),
        })?;
    pipe.write_all(request.as_bytes())
        .and_then(|()| pipe.flush())
        .map_err(|e| format!("sending to Tunnelik's helper service: {e}"))?;
    let mut reply = String::new();
    pipe.read_to_string(&mut reply)
        .map_err(|e| format!("hearing back from Tunnelik's helper service: {e}"))?;
    parse_reply(&reply)
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
            &["C:\\Tools\\a.exe".into()],
            &["corp.example".into(), ".lab.example".into()],
        );
        assert!(xml.starts_with("<VPNProfile>"));
        assert!(xml.contains("<ServerUrlList>vpn.example.com</ServerUrlList>"));
        assert!(xml.contains("<PluginPackageFamilyName>Vendor.App_abc</PluginPackageFamilyName>"));
        assert!(xml.contains(
            "<CustomConfiguration>&lt;Tunnelik tunnel=&quot;Home &amp; Co&quot;/&gt;</CustomConfiguration>"
        ));
        assert!(xml.contains("<Id>C:\\Tools\\a.exe</Id>"));
        assert!(xml.contains("<DomainName>.corp.example</DomainName>"));
        assert!(xml.contains("<DomainName>.lab.example</DomainName>"));
        assert_eq!(xml.matches("<AutoTrigger>true</AutoTrigger>").count(), 2);
        assert!(!xml.contains("<NativeProfile"));
    }

    #[test]
    fn reads_replies() {
        assert_eq!(parse_reply("ok applied\n").unwrap(), "applied");
        assert_eq!(parse_reply("ok\n").unwrap(), "");
        assert_eq!(parse_reply("error: nope\n").unwrap_err(), "nope");
        assert!(parse_reply("").is_err());
    }
}
