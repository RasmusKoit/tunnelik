//! AmneziaWG settings: the extra `[Interface]` keys that turn a WireGuard config into one for
//! AmneziaWG, the fork that hides the protocol from deep packet inspection. A config with none
//! of them, or all of them zero, is plain WireGuard; the engine treats both the same way.
//!
//! The keys and their spellings follow the official Windows client (`amneziawg-windows`,
//! `conf/parser.go`), matched without regard to case like every other key:
//!
//! | Generation | Keys |
//! |---|---|
//! | 1.0 | `Jc`, `Jmin`, `Jmax` (junk packets before a handshake); `S1`, `S2` (paddings); `H1`–`H4` (message types) |
//! | 1.5 / 2.0 | `I1`–`I5` (signature packets before a handshake); `S3`, `S4` |
//! | 3.0 | `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, and a `PersistentKeepalive` range in `[Peer]` |
//! | 3.1 | `RandomTrailers`, `DisableCookies` |

use std::fmt;
use std::str::FromStr;

use crate::{Key, ParseError};

/// The most junk packets the engine sends before a handshake.
pub const MAX_JUNK_COUNT: u16 = 128;
/// The largest junk packet the engine sends.
pub const MAX_JUNK_SIZE: u16 = 1280;
/// Header protection uses the paddings as its nonce, so each of S1–S4 must hold this much.
pub const MIN_PADDING_WITH_HEADER_PROTECTION: u16 = 12;
/// The most `ContentPaddingAddition` may add to a data packet: the plugin sizes its packet
/// buffers for it, and a padding past one junk packet's worth hides nothing more.
pub const MAX_CONTENT_PADDING: u32 = MAX_JUNK_SIZE as u32;

/// A number or an inclusive range `low-high`, the form AmneziaWG 3 uses for settings it picks
/// at random: `MaxHandshakeAttempts = 3-5`, `PersistentKeepalive = 15-25`, `H1 = 100000-200000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range<T> {
    pub lo: T,
    pub hi: T,
}

impl<T: Copy> Range<T> {
    pub fn single(value: T) -> Range<T> {
        Range {
            lo: value,
            hi: value,
        }
    }
}

impl<T: Copy + PartialEq> Range<T> {
    pub fn is_single(&self) -> bool {
        self.lo == self.hi
    }
}

impl<T: FromStr + PartialOrd> FromStr for Range<T> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let s = s.trim();
        let (lo, hi) = match s.split_once('-') {
            Some((lo, hi)) => (lo.trim(), hi.trim()),
            None => (s, s),
        };
        let lo: T = lo.parse().map_err(|_| ())?;
        let hi: T = hi.parse().map_err(|_| ())?;
        if lo > hi {
            return Err(());
        }
        Ok(Range { lo, hi })
    }
}

impl<T: fmt::Display + PartialEq> fmt::Display for Range<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// Every AmneziaWG setting of an `[Interface]`, zero or unset where the config leaves it out,
/// which is how AmneziaWG itself reads a missing key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Amnezia {
    /// `Jc`: junk packets sent before each handshake.
    pub junk_count: u16,
    /// `Jmin` and `Jmax`: the size range of those packets; both zero means the engine's default.
    pub junk_min: u16,
    pub junk_max: u16,
    /// `S1`–`S4`: random bytes prepended to the handshake initiation, the handshake response,
    /// the cookie reply and every data packet.
    pub paddings: [u16; 4],
    /// `H1`–`H4`: the message type of those four messages instead of WireGuard's 1–4, each a
    /// value or a range to pick from.
    pub headers: [Option<Range<u32>>; 4],
    /// `I1`–`I5`: packets sent before the junk, written in a tag language the engine
    /// understands (`<b 0x..>`, `<r n>`, `<rd n>`, `<rc n>`, `<t>`). Kept as written.
    pub signature_packets: [Option<String>; 5],
    /// `HeaderProtectionKey`: encrypts the low-entropy header fields; must match the server.
    pub header_protection_key: Option<Key>,
    /// `ContentPaddingAddition`: extra bytes appended to data packets.
    pub content_padding_addition: Option<Range<u32>>,
    /// Timers, in seconds except the attempt count.
    pub rekey_after_time: Option<Range<u32>>,
    pub rekey_timeout: Option<Range<u32>>,
    pub reject_after_time: Option<Range<u32>>,
    pub keepalive_timeout: Option<Range<u32>>,
    pub max_handshake_attempts: Option<Range<u32>>,
    /// `RandomTrailers`: random bytes after each message.
    pub random_trailers: bool,
    /// `DisableCookies`: no cookie replies under load.
    pub disable_cookies: bool,
}

impl Amnezia {
    /// Whether anything here changes what goes on the wire; false for a plain WireGuard config.
    pub fn is_active(&self) -> bool {
        self.junk_count > 0
            || self.paddings.iter().any(|&s| s > 0)
            || self.headers.iter().flatten().any(|h| h.hi > 0)
            || self.signature_packets.iter().any(Option::is_some)
            || self.header_protection_key.is_some()
            || self.content_padding_addition.is_some()
            || self.has_timers()
            || self.random_trailers
            || self.disable_cookies
    }

    pub fn has_timers(&self) -> bool {
        self.rekey_after_time.is_some()
            || self.rekey_timeout.is_some()
            || self.reject_after_time.is_some()
            || self.keepalive_timeout.is_some()
            || self.max_handshake_attempts.is_some()
    }

    /// The AmneziaWG generation the settings need: the newest one any of them belongs to.
    pub fn generation(&self) -> &'static str {
        if self.random_trailers || self.disable_cookies {
            "3.1"
        } else if self.header_protection_key.is_some()
            || self.content_padding_addition.is_some()
            || self.has_timers()
        {
            "3.0"
        } else if self.signature_packets.iter().any(Option::is_some)
            || self.paddings[2] > 0
            || self.paddings[3] > 0
        {
            "2.0"
        } else {
            "1.0"
        }
    }

    /// The settings as label and value rows for the window and the command line, nothing
    /// secret among them. Empty for a plain config.
    pub fn summary(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        if self.junk_count > 0 {
            let sizes = match (self.junk_min, self.junk_max) {
                (0, 0) => "default sizes".to_string(),
                (lo, hi) => format!("{lo}–{hi} bytes"),
            };
            rows.push((
                "Junk packets".into(),
                format!("{} × {sizes}", self.junk_count),
            ));
        }
        if self.paddings.iter().any(|&s| s > 0) {
            let s = self.paddings;
            rows.push((
                "Message paddings".into(),
                format!("S1 {}, S2 {}, S3 {}, S4 {}", s[0], s[1], s[2], s[3]),
            ));
        }
        let headers: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.map(|h| format!("H{} {h}", i + 1)))
            .collect();
        if !headers.is_empty() {
            rows.push(("Header types".into(), headers.join(", ")));
        }
        let signatures: Vec<String> = self
            .signature_packets
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.as_ref().map(|_| format!("I{}", i + 1)))
            .collect();
        if !signatures.is_empty() {
            rows.push(("Signature packets".into(), signatures.join(", ")));
        }
        if self.header_protection_key.is_some() {
            rows.push(("Header protection".into(), "on".into()));
        }
        if let Some(r) = self.content_padding_addition {
            rows.push(("Content padding".into(), format!("{} bytes", r.pretty())));
        }
        let timers: Vec<String> = [
            ("rekey after", self.rekey_after_time, " s"),
            ("rekey timeout", self.rekey_timeout, " s"),
            ("reject after", self.reject_after_time, " s"),
            ("keepalive timeout", self.keepalive_timeout, " s"),
            ("handshake attempts", self.max_handshake_attempts, ""),
        ]
        .into_iter()
        .filter_map(|(label, r, unit)| r.map(|r| format!("{label} {}{unit}", r.pretty())))
        .collect();
        if !timers.is_empty() {
            rows.push(("Timers".into(), timers.join(", ")));
        }
        if self.random_trailers {
            rows.push(("Random trailers".into(), "on".into()));
        }
        if self.disable_cookies {
            rows.push(("Cookies".into(), "off".into()));
        }
        rows
    }
}

impl<T: fmt::Display + PartialEq> Range<T> {
    /// `3–5` with an en dash, for prose; `Display` keeps the config's `3-5`.
    pub fn pretty(&self) -> String {
        if self.lo == self.hi {
            self.lo.to_string()
        } else {
            format!("{}–{}", self.lo, self.hi)
        }
    }
}

/// Collects the AmneziaWG keys of one `[Interface]` while it is parsed.
#[derive(Default)]
pub(crate) struct Builder {
    junk_count: Option<u16>,
    junk_min: Option<u16>,
    junk_max: Option<u16>,
    paddings: [Option<u16>; 4],
    headers: [Option<Range<u32>>; 4],
    signature_packets: [Option<String>; 5],
    header_protection_key: Option<Key>,
    content_padding_addition: Option<Range<u32>>,
    rekey_after_time: Option<Range<u32>>,
    rekey_timeout: Option<Range<u32>>,
    reject_after_time: Option<Range<u32>>,
    keepalive_timeout: Option<Range<u32>>,
    max_handshake_attempts: Option<Range<u32>>,
    random_trailers: Option<bool>,
    disable_cookies: Option<bool>,
    /// The line of the first AmneziaWG key, for errors that belong to no single line.
    first_line: Option<usize>,
}

impl Builder {
    /// Takes the key if it is an AmneziaWG one: `Ok(true)` when it was, `Ok(false)` when the
    /// caller should match it itself. `lower` is `key` in lower case.
    pub(crate) fn set(
        &mut self,
        lower: &str,
        key: &str,
        value: &str,
        line: usize,
    ) -> Result<bool, ParseError> {
        use crate::{parse_key, parse_num, set_once};
        match lower {
            "jc" => set_once(
                &mut self.junk_count,
                parse_num(value, key, line)?,
                key,
                line,
            )?,
            "jmin" => set_once(&mut self.junk_min, parse_num(value, key, line)?, key, line)?,
            "jmax" => set_once(&mut self.junk_max, parse_num(value, key, line)?, key, line)?,
            "s1" | "s2" | "s3" | "s4" => {
                let i = (lower.as_bytes()[1] - b'1') as usize;
                set_once(
                    &mut self.paddings[i],
                    parse_num(value, key, line)?,
                    key,
                    line,
                )?
            }
            "h1" | "h2" | "h3" | "h4" => {
                let i = (lower.as_bytes()[1] - b'1') as usize;
                set_once(
                    &mut self.headers[i],
                    parse_range(value, key, line)?,
                    key,
                    line,
                )?
            }
            "i1" | "i2" | "i3" | "i4" | "i5" => {
                let i = (lower.as_bytes()[1] - b'1') as usize;
                if value.is_empty() {
                    return Err(ParseError::at(line, format!("`{key}` has no value")));
                }
                set_once(&mut self.signature_packets[i], value.to_string(), key, line)?
            }
            "headerprotectionkey" => set_once(
                &mut self.header_protection_key,
                parse_key(value, line)?,
                key,
                line,
            )?,
            "contentpaddingaddition" => set_once(
                &mut self.content_padding_addition,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "rekeyaftertime" => set_once(
                &mut self.rekey_after_time,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "rekeytimeout" => set_once(
                &mut self.rekey_timeout,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "rejectaftertime" => set_once(
                &mut self.reject_after_time,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "keepalivetimeout" => set_once(
                &mut self.keepalive_timeout,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "maxhandshakeattempts" => set_once(
                &mut self.max_handshake_attempts,
                parse_range(value, key, line)?,
                key,
                line,
            )?,
            "randomtrailers" => set_once(
                &mut self.random_trailers,
                parse_bool(value, key, line)?,
                key,
                line,
            )?,
            "disablecookies" => set_once(
                &mut self.disable_cookies,
                parse_bool(value, key, line)?,
                key,
                line,
            )?,
            _ => return Ok(false),
        }
        self.first_line.get_or_insert(line);
        Ok(true)
    }

    /// Checks what one key alone cannot, and returns the settings.
    pub(crate) fn build(self) -> Result<Amnezia, ParseError> {
        let at = |message: String| match self.first_line {
            Some(line) => ParseError::at(line, message),
            None => ParseError::general(message),
        };
        let junk_count = self.junk_count.unwrap_or(0);
        let junk_min = self.junk_min.unwrap_or(0);
        let junk_max = self.junk_max.unwrap_or(0);
        if junk_count > MAX_JUNK_COUNT {
            return Err(at(format!(
                "`Jc` must be {MAX_JUNK_COUNT} or less; the engine sends no more junk packets than that"
            )));
        }
        if junk_min > junk_max {
            return Err(at("`Jmin` must not be larger than `Jmax`".into()));
        }
        if junk_max > MAX_JUNK_SIZE {
            return Err(at(format!(
                "`Jmax` must be {MAX_JUNK_SIZE} or less; the engine sends no larger junk packets"
            )));
        }
        if self
            .content_padding_addition
            .is_some_and(|r| r.hi > MAX_CONTENT_PADDING)
        {
            return Err(at(format!(
                "`ContentPaddingAddition` must be {MAX_CONTENT_PADDING} or less"
            )));
        }
        let paddings = self.paddings.map(|s| s.unwrap_or(0));
        if self.header_protection_key.is_some()
            && paddings
                .iter()
                .any(|&s| s < MIN_PADDING_WITH_HEADER_PROTECTION)
        {
            return Err(at(format!(
                "`HeaderProtectionKey` needs `S1`, `S2`, `S3` and `S4` of at least {MIN_PADDING_WITH_HEADER_PROTECTION}"
            )));
        }
        Ok(Amnezia {
            junk_count,
            junk_min,
            junk_max,
            paddings,
            headers: self.headers,
            signature_packets: self.signature_packets,
            header_protection_key: self.header_protection_key,
            content_padding_addition: self.content_padding_addition,
            rekey_after_time: self.rekey_after_time,
            rekey_timeout: self.rekey_timeout,
            reject_after_time: self.reject_after_time,
            keepalive_timeout: self.keepalive_timeout,
            max_handshake_attempts: self.max_handshake_attempts,
            random_trailers: self.random_trailers.unwrap_or(false),
            disable_cookies: self.disable_cookies.unwrap_or(false),
        })
    }
}

pub(crate) fn parse_range<T: FromStr + PartialOrd>(
    value: &str,
    key: &str,
    line: usize,
) -> Result<Range<T>, ParseError> {
    value.parse().map_err(|_| {
        ParseError::at(
            line,
            format!("invalid value `{value}` for `{key}`, expected a number or `low-high`"),
        )
    })
}

/// The spellings Go's `strconv.ParseBool` takes, which is what AmneziaWG uses.
fn parse_bool(value: &str, key: &str, line: usize) -> Result<bool, ParseError> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(ParseError::at(
            line,
            format!("invalid value `{value}` for `{key}`, expected true or false"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!("5".parse::<Range<u32>>(), Ok(Range::single(5)));
        assert_eq!("3-5".parse::<Range<u32>>(), Ok(Range { lo: 3, hi: 5 }));
        assert_eq!(" 3 - 5 ".parse::<Range<u32>>(), Ok(Range { lo: 3, hi: 5 }));
        assert_eq!("5-3".parse::<Range<u32>>(), Err(()));
        assert_eq!("x".parse::<Range<u32>>(), Err(()));
        assert_eq!("3-".parse::<Range<u32>>(), Err(()));
        assert_eq!(Range { lo: 3, hi: 5 }.to_string(), "3-5");
        assert_eq!(Range::single(7).to_string(), "7");
        assert_eq!(Range { lo: 3, hi: 5 }.pretty(), "3–5");
    }

    #[test]
    fn plain_config_is_inactive() {
        let a = Amnezia::default();
        assert!(!a.is_active());
        assert_eq!(a.generation(), "1.0");
        assert!(a.summary().is_empty());
    }

    #[test]
    fn generations() {
        let mut a = Amnezia {
            junk_count: 4,
            ..Default::default()
        };
        assert!(a.is_active());
        assert_eq!(a.generation(), "1.0");
        a.signature_packets[0] = Some("<r 10>".into());
        assert_eq!(a.generation(), "2.0");
        a.max_handshake_attempts = Some(Range { lo: 3, hi: 5 });
        assert_eq!(a.generation(), "3.0");
        a.disable_cookies = true;
        assert_eq!(a.generation(), "3.1");

        let s4_only = Amnezia {
            paddings: [0, 0, 0, 16],
            ..Default::default()
        };
        assert_eq!(s4_only.generation(), "2.0");
        let vanilla_header = Amnezia {
            headers: [Some(Range::single(0)), None, None, None],
            ..Default::default()
        };
        assert!(!vanilla_header.is_active());
    }

    #[test]
    fn summary_rows() {
        let a = Amnezia {
            junk_count: 4,
            junk_min: 50,
            junk_max: 1000,
            paddings: [15, 40, 0, 0],
            headers: [
                Some(Range::single(1234567)),
                Some(Range { lo: 10, hi: 20 }),
                None,
                None,
            ],
            signature_packets: [Some("<t>".into()), None, Some("<r 4>".into()), None, None],
            header_protection_key: Some(Key([9; 32])),
            content_padding_addition: Some(Range { lo: 0, hi: 64 }),
            max_handshake_attempts: Some(Range { lo: 3, hi: 5 }),
            random_trailers: true,
            disable_cookies: true,
            ..Default::default()
        };
        let rows = a.summary();
        let row = |label: &str| {
            rows.iter()
                .find(|(l, _)| l == label)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("no row {label}"))
        };
        assert_eq!(row("Junk packets"), "4 × 50–1000 bytes");
        assert_eq!(row("Message paddings"), "S1 15, S2 40, S3 0, S4 0");
        assert_eq!(row("Header types"), "H1 1234567, H2 10-20");
        assert_eq!(row("Signature packets"), "I1, I3");
        assert_eq!(row("Header protection"), "on");
        assert_eq!(row("Content padding"), "0–64 bytes");
        assert_eq!(row("Timers"), "handshake attempts 3–5");
        assert_eq!(row("Random trailers"), "on");
        assert_eq!(row("Cookies"), "off");
        assert!(!format!("{rows:?}").contains(&Key([9; 32]).to_base64()));

        let defaults = Amnezia {
            junk_count: 2,
            ..Default::default()
        };
        assert_eq!(defaults.summary()[0].1, "2 × default sizes");
    }
}
