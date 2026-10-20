//! Reads the WireGuard config out of a VPN profile's custom configuration.
//!
//! The profile carries the config as `<WireGuard>…config text…</WireGuard>`, optionally wrapped in
//! CDATA. Windows hands that XML to the plugin as `VpnChannelConfiguration.CustomField`.

const OPEN: &str = "<WireGuard>";
const CLOSE: &str = "</WireGuard>";

pub fn config_text(custom_field: &str) -> Result<String, String> {
    let start = custom_field
        .find(OPEN)
        .ok_or("VPN profile has no <WireGuard> configuration")?
        + OPEN.len();
    let end = custom_field[start..]
        .find(CLOSE)
        .ok_or("VPN profile's <WireGuard> element is not closed")?
        + start;
    let inner = custom_field[start..end].trim();

    if let Some(cdata) = inner.strip_prefix("<![CDATA[") {
        let cdata = cdata
            .strip_suffix("]]>")
            .ok_or("unterminated CDATA in VPN profile")?;
        return Ok(cdata.to_string());
    }
    Ok(unescape(inner))
}

/// Wraps a config for storing it in a VPN profile.
pub fn custom_configuration(config_text: &str) -> String {
    format!(
        "{OPEN}<![CDATA[{}]]>{CLOSE}",
        config_text.replace("]]>", "]]]]><![CDATA[>")
    )
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#13;", "\r")
        .replace("&#10;", "\n")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]\nPrivateKey = abc+/=\nAddress = 10.1.254.3/32\n";

    #[test]
    fn round_trips_through_cdata() {
        assert_eq!(config_text(&custom_configuration(CONF)).unwrap(), CONF);
    }

    #[test]
    fn reads_plain_and_escaped_text() {
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<WireGuard>\n{}</WireGuard>",
            "A = 1 &amp; &lt;2&gt;\n"
        );
        assert_eq!(config_text(&xml).unwrap(), "A = 1 & <2>");
    }

    #[test]
    fn reports_missing_or_broken_element() {
        assert!(config_text("").unwrap_err().contains("no <WireGuard>"));
        assert!(
            config_text("<WireGuard>x")
                .unwrap_err()
                .contains("not closed")
        );
        assert!(
            config_text("<WireGuard><![CDATA[x</WireGuard>")
                .unwrap_err()
                .contains("CDATA")
        );
    }
}
