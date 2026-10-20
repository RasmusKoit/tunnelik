//! What a VPN profile stores about its tunnel.
//!
//! The profile only names the tunnel, as `<WireGuard tunnel="Home"/>`; the config itself lives in
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
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid tunnel name `{name}`: use up to 64 letters, digits, spaces, `-`, `_` or `.`"
        ))
    }
}

pub fn custom_configuration(name: &str) -> String {
    format!("<WireGuard tunnel=\"{name}\"/>")
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
        let xml = "<?xml version=\"1.0\"?>\r\n<WireGuard tunnel='office-1' />";
        assert_eq!(tunnel_name(xml).unwrap(), "office-1");
    }

    #[test]
    fn rejects_bad_profiles() {
        assert!(tunnel_name("").unwrap_err().contains("does not name"));
        assert!(
            tunnel_name("<WireGuard tunnel=x/>")
                .unwrap_err()
                .contains("not quoted")
        );
        assert!(
            tunnel_name("<WireGuard tunnel=\"x/>")
                .unwrap_err()
                .contains("not closed")
        );
        assert!(
            tunnel_name("<WireGuard tunnel=\"..\\x\"/>")
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
        ] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }
}
