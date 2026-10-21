//! A toast for when a tunnel came up without anyone asking: Windows' always-on redialed it after
//! standby, a network change or sign-in.

/// The toast's content. Tunnel names are plain (letters, digits, spaces and `-_.`), but the
/// escaping costs nothing.
pub fn toast_xml(tunnel: &str) -> String {
    let name = escape(tunnel);
    format!(
        "<toast><visual><binding template=\"ToastGeneric\">\
<text>{name} is back up</text>\
<text>Windows reconnected the tunnel.</text>\
</binding></visual></toast>"
    )
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Shows the toast as the Tunnelik app, so it carries the app's name and icon.
#[cfg(windows)]
pub fn show(tunnel: &str) -> windows_core::Result<()> {
    use windows::ApplicationModel::Package;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows_core::HSTRING;

    let content = XmlDocument::new()?;
    content.LoadXml(&HSTRING::from(toast_xml(tunnel)))?;
    let toast = ToastNotification::CreateToastNotification(&content)?;
    let family = Package::Current()?.Id()?.FamilyName()?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(format!("{family}!App")))?
        .Show(&toast)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_tunnel_and_escapes() {
        let xml = toast_xml("Home");
        assert!(xml.contains("<text>Home is back up</text>"));
        assert!(xml.contains("Windows reconnected the tunnel."));
        let xml = toast_xml("a&b<c>\"d'");
        assert!(xml.contains("a&amp;b&lt;c&gt;&quot;d&apos; is back up"));
    }
}
