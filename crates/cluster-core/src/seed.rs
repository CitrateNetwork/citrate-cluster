//! HUP-S8.4 (mesh prerequisite): the **group seed**, a short text a member shares as a link or a QR
//! code so another member's machine can find this one without typing an address.
//!
//! A seed carries **network locations only**: the group id and up to [`MAX_SEED_ADDRS`] libp2p
//! multiaddrs, each naming its peer (`.../p2p/<peer id>`). It grants nothing. A machine that dials a
//! seeded address is still admitted only at the `identify` handshake, against the group's roster and
//! DeviceLinks, exactly like a bootstrap address. A forged or stale seed costs one failed dial.
//!
//! Format (fits a QR code; `/` and `:` are legal in a URI query, so multiaddrs stay readable):
//!
//! ```text
//! citrate-cluster://seed?v=1&g=<group>&a=<multiaddr>&a=<multiaddr>
//! ```
//!
//! Values are percent-encoded for `%`, `&`, `=`, `#`, `+`, space, and any byte outside printable
//! ASCII. Unknown keys are ignored (a later version may add fields); a missing or different `v` is
//! refused. Parsing is pure and bounded: this crate stays free of libp2p, so the multiaddr check
//! here is structural, and the daemon parses each address with libp2p before dialing it.

/// The URI prefix every seed starts with.
pub const SEED_PREFIX: &str = "citrate-cluster://seed?";

/// The only seed version this build reads and writes.
pub const SEED_VERSION: &str = "1";

/// Most addresses one seed carries (a machine has a few interfaces; a QR code stays scannable).
pub const MAX_SEED_ADDRS: usize = 8;

/// Longest accepted seed text, in bytes. A version-40 QR code holds 2953 bytes in byte mode.
pub const MAX_SEED_LEN: usize = 2048;

/// Longest group id a seed carries, in bytes.
pub const MAX_GROUP_LEN: usize = 256;

/// Longest single multiaddr a seed carries, in bytes.
pub const MAX_ADDR_LEN: usize = 256;

/// A decoded group seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSeed {
    /// The group (== the mesh topic) the addresses serve.
    pub group: String,
    /// Peer multiaddrs, each ending in (or containing) `/p2p/<peer id>`.
    pub addrs: Vec<String>,
}

/// Why a seed was refused. Secret-free (a seed holds no secrets anyway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// Not a `citrate-cluster://seed?` URI.
    NotASeed,
    /// Longer than [`MAX_SEED_LEN`].
    TooLong,
    /// `v` missing or not [`SEED_VERSION`].
    Version,
    /// A bad percent escape or a value that is not UTF-8.
    Encoding,
    /// The group id is missing, repeated, empty, too long or has control characters.
    Group,
    /// No addresses, or more than [`MAX_SEED_ADDRS`].
    AddrCount,
    /// An address that is not a `/...` multiaddr naming a `/p2p/` peer, or is too long.
    Addr,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SeedError::NotASeed => "not a cluster seed",
            SeedError::TooLong => "seed is too long",
            SeedError::Version => "unsupported seed version",
            SeedError::Encoding => "seed has a bad escape or is not UTF-8",
            SeedError::Group => "seed has a missing or malformed group id",
            SeedError::AddrCount => "seed must carry between 1 and 8 addresses",
            SeedError::Addr => "seed has a malformed peer address",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SeedError {}

impl GroupSeed {
    /// Build a seed, validating every field (the same rules [`GroupSeed::decode`] applies).
    pub fn new(group: &str, addrs: Vec<String>) -> Result<Self, SeedError> {
        let seed = GroupSeed {
            group: group.to_string(),
            addrs,
        };
        seed.validate()?;
        Ok(seed)
    }

    fn validate(&self) -> Result<(), SeedError> {
        if !valid_group(&self.group) {
            return Err(SeedError::Group);
        }
        if self.addrs.is_empty() || self.addrs.len() > MAX_SEED_ADDRS {
            return Err(SeedError::AddrCount);
        }
        if !self.addrs.iter().all(|a| valid_addr(a)) {
            return Err(SeedError::Addr);
        }
        Ok(())
    }

    /// The seed as link/QR text.
    pub fn encode(&self) -> String {
        let mut out = String::from(SEED_PREFIX);
        out.push_str("v=");
        out.push_str(SEED_VERSION);
        out.push_str("&g=");
        out.push_str(&pct_encode(&self.group));
        for a in &self.addrs {
            out.push_str("&a=");
            out.push_str(&pct_encode(a));
        }
        out
    }

    /// Parse and validate link/QR text. Surrounding whitespace is ignored.
    pub fn decode(text: &str) -> Result<Self, SeedError> {
        let text = text.trim();
        if text.len() > MAX_SEED_LEN {
            return Err(SeedError::TooLong);
        }
        let query = text.strip_prefix(SEED_PREFIX).ok_or(SeedError::NotASeed)?;
        let mut version: Option<String> = None;
        let mut group: Option<String> = None;
        let mut addrs: Vec<String> = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "v" => version = Some(pct_decode(v)?),
                "g" => {
                    if group.is_some() {
                        return Err(SeedError::Group);
                    }
                    group = Some(pct_decode(v)?);
                }
                "a" => {
                    if addrs.len() >= MAX_SEED_ADDRS {
                        return Err(SeedError::AddrCount);
                    }
                    addrs.push(pct_decode(v)?);
                }
                _ => {} // a later version's field; ignored
            }
        }
        if version.as_deref() != Some(SEED_VERSION) {
            return Err(SeedError::Version);
        }
        let seed = GroupSeed {
            group: group.ok_or(SeedError::Group)?,
            addrs,
        };
        seed.validate()?;
        Ok(seed)
    }
}

fn valid_group(g: &str) -> bool {
    !g.trim().is_empty() && g.len() <= MAX_GROUP_LEN && !g.chars().any(char::is_control)
}

/// Structural multiaddr check: starts with `/`, printable ASCII without spaces, names a `/p2p/` peer
/// with a non-empty id, and has no empty path segment.
fn valid_addr(a: &str) -> bool {
    if a.len() > MAX_ADDR_LEN || !a.starts_with('/') {
        return false;
    }
    if !a.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    let parts: Vec<&str> = a[1..].split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    parts
        .windows(2)
        .any(|w| w[0] == "p2p" && w[1].bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_graphic() && !matches!(b, b'%' | b'&' | b'=' | b'#' | b'+');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Result<String, SeedError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(SeedError::Encoding)?;
            let hex = std::str::from_utf8(hex).map_err(|_| SeedError::Encoding)?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| SeedError::Encoding)?;
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| SeedError::Encoding)
}

#[cfg(test)]
#[path = "seed_tests.rs"]
mod seed_tests;
