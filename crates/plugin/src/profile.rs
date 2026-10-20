//! What a VPN profile stores about its tunnel.
//!
//! The profile only names the tunnel, as `<Tunnelik tunnel="Home"/>`; the config itself lives in
//! the encrypted store. Windows hands this XML to the plugin as `VpnChannelConfiguration.CustomField`.

/// Tunnel names become file names and VPN connection names, so they are kept simple.
pub fn validate_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.trim() == name
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
    if !valid {
        return Err(format!(
            "invalid tunnel name `{name}`: use up to 64 letters, digits, spaces, `-`, `_` or `.`"
        ));
    }
    if is_device_name(name) {
        return Err(format!(
            "invalid tunnel name `{name}`: Windows reserves it for a device"
        ));
    }
    Ok(())
}

/// Names Windows won't allow as files, with or without an extension: `CON`, `nul.conf`.
fn is_device_name(name: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    let stem = name.split('.').next().unwrap_or(name);
    let numbered = |prefix: &str| {
        stem.len() == 4
            && stem[..3].eq_ignore_ascii_case(prefix)
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0'
    };
    DEVICES.iter().any(|d| stem.eq_ignore_ascii_case(d)) || numbered("COM") || numbered("LPT")
}

pub fn custom_configuration(name: &str) -> String {
    format!("<Tunnelik tunnel=\"{name}\"/>")
}

pub fn tunnel_name(custom_field: &str) -> Result<String, String> {
    let attr = custom_field
        .find("tunnel=")
        .ok_or("VPN profile does not name a WireGuard tunnel")?;
    let rest = &custom_field[attr + "tunnel=".len()..];
    // Windows may rewrite the XML, so accept either quote style.
    let quote = rest
        .chars()
        .next()
        .filter(|c| *c == '"' || *c == '\'')
        .ok_or("VPN profile's tunnel name is not quoted")?;
    let len = rest[1..]
        .find(quote)
        .ok_or("VPN profile's tunnel name is not closed")?;
    let name = &rest[1..1 + len];
    validate_name(name)?;
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        assert_eq!(
            tunnel_name(&custom_configuration("Home VPN")).unwrap(),
            "Home VPN"
        );
    }

    #[test]
    fn accepts_rewritten_xml() {
        let xml = "<?xml version=\"1.0\"?>\r\n<Tunnelik tunnel='office-1' />";
        assert_eq!(tunnel_name(xml).unwrap(), "office-1");
    }

    #[test]
    fn rejects_bad_profiles() {
        assert!(tunnel_name("").unwrap_err().contains("does not name"));
        assert!(
            tunnel_name("<Tunnelik tunnel=x/>")
                .unwrap_err()
                .contains("not quoted")
        );
        assert!(
            tunnel_name("<Tunnelik tunnel=\"x/>")
                .unwrap_err()
                .contains("not closed")
        );
        assert!(
            tunnel_name("<Tunnelik tunnel=\"..\\x\"/>")
                .unwrap_err()
                .contains("invalid")
        );
    }

    #[test]
    fn validates_names() {
        for good in ["Home", "office-1", "a.b_c d"] {
            assert!(validate_name(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            " x",
            "x ",
            ".hidden",
            "a/b",
            "a\\b",
            "a\"b",
            &"x".repeat(65),
            "CON",
            "nul",
            "Aux.conf",
            "COM1",
            "lpt9.x",
        ] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
        for good in ["COM0", "COM10", "CONF", "Console", "LPT"] {
            assert!(validate_name(good).is_ok(), "{good}");
        }
    }
}
