//! # Per-device identity: the DeviceLink (HUP-S8.1)
//!
//! A member runs Citrate Core on more than one machine. Before this module every machine meshed as
//! the member's **comms** identity, and because the comms key is derived from the wallet, two
//! machines of one member presented the SAME secp256k1 key and therefore the SAME libp2p PeerId: the
//! mesh could not tell them apart, and one could not be cut off without cutting off the other.
//!
//! The fix (planset decision D-31, owner amendment 2026-09-30): every device mints its own random
//! secp256k1 **device key** (sealed on that device, never derived from the wallet), and a
//! [`DeviceLink`] record binds that device to its member. The device key is the Noise/libp2p
//! identity, so the PeerId is derived from it: one device key, one PeerId, one address.
//!
//! ## What a link proves
//!
//! A [`SignedDeviceLink`] carries three EIP-191 signatures over the exact
//! [`DeviceLink::signing_message`]:
//!
//! * `member_sig` by the member's roster key (the comms key the group roster is keyed on), which is
//!   the identity this mesh can check against the roster, so it is the one that authorizes;
//! * `device_sig` by the device key itself (proof the device holds the key the link names, so a link
//!   cannot be minted for somebody else's PeerId);
//! * `wallet_sig` by the member's custody wallet, produced through citrate-core's signature ceremony
//!   with explicit human approval (D-31 "wallet-signed"). The member signature covers the wallet
//!   address, so the two keys vouch for each other.
//!
//! A device is admitted to a group's mesh only when its link verifies on all three, its member is
//! in the role-gated roster, and the member has not revoked it. Devices inherit their member's role
//! ([`effective_roster`]), so the existing [`crate::ClusterMembership`] gate, and its proven
//! `admitted ⊆ allowed` invariant, does the admission. Nothing about the gate is duplicated here.
//!
//! ## Revocation is sticky
//!
//! A [`SignedRevocation`] by the member removes the device in the same reconcile step that sees it
//! (the "one admission cycle" of US-8.1 AC2). Revocation is per device KEY and permanent: a revoked
//! key is never admitted again, even if a later link for it arrives. Re-adding a machine means it
//! mints a fresh device key and gets a fresh link. A revocation only counts when it is signed by the
//! member that the device is linked to, so one member cannot evict another member's machine.
//!
//! ## Purity
//!
//! This crate stays free of crypto, I/O and networking (CLAUDE.md rule 3). Signature recovery is
//! injected through [`LinkVerifier`]; `cluster-daemon` supplies the real secp256k1 EIP-191
//! implementation. Formal model: `formal/DeviceLink.tla` (`NoActWithoutLink`,
//! `RevokedDeviceEvicted`, `DistinctPeerIds`, and ClusterAdmission's `admitted ⊆ allowed`).

use std::collections::{BTreeMap, BTreeSet};

use crate::{canonical_address, role_rank, MIN_CLUSTER_RANK};

/// The DeviceLink wire/message version. Bumped only with a new message format.
pub const DEVICE_LINK_VERSION: u32 = 1;

/// Longest device label carried in a link (shown in rosters; also signed, so it must be bounded).
pub const MAX_LABEL_LEN: usize = 48;

/// Most links / revocations one roster update may carry for a group. A group is a small mesh; this
/// bounds the verification work a single update can force, and 64 signed links (about 600 bytes of
/// JSON each) fit inside the daemon's 64 KiB IPC line cap with room for the roster.
pub const MAX_LINKS_PER_UPDATE: usize = 64;

/// The highest device index accepted (index 0 is the member's first device).
pub const MAX_DEVICE_INDEX: u32 = 1023;

/// The unsigned body of a device link: which device key belongs to which member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLink {
    /// The member's roster address (canonical: lowercase, no `0x`). The comms identity.
    pub member: String,
    /// The device key's address (canonical). The libp2p PeerId is derived from the same key.
    pub device: String,
    /// The member's custody wallet address (canonical). Signs through the ceremony.
    pub wallet: String,
    /// The member's index for this device (0 = first). Unique per member among active links.
    pub index: u32,
    /// A short human label ("Studio Mac", "Linux box").
    pub label: String,
    /// Unix seconds when the link was issued.
    pub issued_at: u64,
}

/// Whether a label is acceptable: 1..=[`MAX_LABEL_LEN`] chars of ASCII letters, digits, space,
/// `.`, `_`, `-`, `'`, with no leading/trailing space. Restricting the alphabet keeps the signed
/// message unambiguous (no newlines or look-alike characters inside a signed field).
pub fn label_is_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label.trim() == label
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-' | b'\''))
}

impl DeviceLink {
    /// Build a link with canonicalized addresses. `None` if any address is malformed, the label is
    /// invalid, the index is out of range, or the device key is the member or wallet key itself (a
    /// device key must be its own key).
    pub fn new(
        member: &str,
        device: &str,
        wallet: &str,
        index: u32,
        label: &str,
        issued_at: u64,
    ) -> Option<Self> {
        let member = canonical_address(member)?;
        let device = canonical_address(device)?;
        let wallet = canonical_address(wallet)?;
        if device == member || device == wallet {
            return None;
        }
        if index > MAX_DEVICE_INDEX || !label_is_valid(label) {
            return None;
        }
        Some(DeviceLink {
            member,
            device,
            wallet,
            index,
            label: label.to_string(),
            issued_at,
        })
    }

    /// The exact text every signer signs (EIP-191 `personal_sign`). Human readable, because the
    /// wallet signature is approved by a person in the ceremony, who sees this text verbatim.
    /// citrate-core builds the same bytes; both repos pin the golden vector in their tests.
    pub fn signing_message(&self) -> String {
        format!(
            "Citrate DeviceLink v{DEVICE_LINK_VERSION}\n\
             Link this device to my Citrate member identity.\n\
             member: 0x{}\n\
             device: 0x{}\n\
             wallet: 0x{}\n\
             index: {}\n\
             label: {}\n\
             issued_at: {}",
            self.member, self.device, self.wallet, self.index, self.label, self.issued_at
        )
    }
}

/// A device link plus its three signatures (hex, 65-byte `r||s||v`, optional `0x`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceLink {
    pub link: DeviceLink,
    pub member_sig: String,
    pub device_sig: String,
    pub wallet_sig: String,
}

/// A member's revocation of one of its devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    pub member: String,
    pub device: String,
    pub revoked_at: u64,
}

impl DeviceRevocation {
    /// Build with canonical addresses; `None` if either is malformed.
    pub fn new(member: &str, device: &str, revoked_at: u64) -> Option<Self> {
        Some(DeviceRevocation {
            member: canonical_address(member)?,
            device: canonical_address(device)?,
            revoked_at,
        })
    }

    /// The exact text the member's roster key signs to revoke a device.
    pub fn signing_message(&self) -> String {
        format!(
            "Citrate DeviceRevocation v{DEVICE_LINK_VERSION}\n\
             Remove this device from my Citrate member identity.\n\
             member: 0x{}\n\
             device: 0x{}\n\
             revoked_at: {}",
            self.member, self.device, self.revoked_at
        )
    }
}

/// A revocation plus the member's signature over [`DeviceRevocation::signing_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevocation {
    pub revocation: DeviceRevocation,
    pub member_sig: String,
}

/// Recovers the signer of an EIP-191 `personal_sign` signature. Injected so this crate stays free
/// of crypto; `cluster-daemon` provides the secp256k1 implementation.
pub trait LinkVerifier {
    /// The canonical address that produced `sig_hex` over `message`, or `None` when the signature is
    /// malformed or does not recover.
    fn recover(&self, message: &str, sig_hex: &str) -> Option<String>;
}

/// Why a link or revocation was not accepted. Reported back to the client, never fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRejection {
    /// The link body failed validation (bad address, label, index, or a device key equal to the
    /// member or wallet key).
    Malformed { device: String },
    /// One of the three signatures does not recover to the address it should.
    BadSignature { device: String, which: &'static str },
    /// Two different active links name the same device key (or the same member index). Neither is
    /// admitted: every node must reach the same answer, so a conflict is never resolved by order.
    Conflict { device: String },
    /// The device key was revoked by its member.
    Revoked { device: String },
    /// A revocation whose signature does not recover to its member.
    BadRevocation { device: String },
    /// The update carried more than [`MAX_LINKS_PER_UPDATE`] links or revocations.
    TooMany,
}

/// Verify one signed link: body valid and all three signatures recover to the right keys.
pub fn verify_link(
    signed: &SignedDeviceLink,
    verifier: &dyn LinkVerifier,
) -> Result<(), LinkRejection> {
    let l = &signed.link;
    // Re-run constructor validation on the received body (it may not have come through `new`).
    let Some(canon) = DeviceLink::new(
        &l.member,
        &l.device,
        &l.wallet,
        l.index,
        &l.label,
        l.issued_at,
    ) else {
        return Err(LinkRejection::Malformed {
            device: l.device.clone(),
        });
    };
    let msg = canon.signing_message();
    for (which, sig, want) in [
        ("member", &signed.member_sig, &canon.member),
        ("device", &signed.device_sig, &canon.device),
        ("wallet", &signed.wallet_sig, &canon.wallet),
    ] {
        if verifier.recover(&msg, sig).as_deref() != Some(want.as_str()) {
            return Err(LinkRejection::BadSignature {
                device: canon.device.clone(),
                which,
            });
        }
    }
    Ok(())
}

/// The verified device links of one group, plus the sticky revocations. The daemon keeps one per
/// group; every roster update rebuilds the links but only ever ADDS revocations.
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    /// device -> its verified link (only links that verified and do not conflict).
    links: BTreeMap<String, DeviceLink>,
    /// (member, device) revocations, each verified as signed by that member. Sticky.
    revoked: BTreeSet<(String, String)>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record verified revocations (sticky) and replace the link set with the verified,
    /// non-conflicting, non-revoked links from `links`. Returns what was rejected and why.
    pub fn update(
        &mut self,
        links: &[SignedDeviceLink],
        revocations: &[SignedRevocation],
        verifier: &dyn LinkVerifier,
    ) -> Vec<LinkRejection> {
        let mut rejected = Vec::new();
        if links.len() > MAX_LINKS_PER_UPDATE || revocations.len() > MAX_LINKS_PER_UPDATE {
            // Refuse the whole update: keep the previous links and revocations untouched.
            rejected.push(LinkRejection::TooMany);
            return rejected;
        }

        // 1. Revocations first (sticky), so a link and its revocation in the same update never admit.
        for r in revocations {
            let Some(rev) = DeviceRevocation::new(
                &r.revocation.member,
                &r.revocation.device,
                r.revocation.revoked_at,
            ) else {
                rejected.push(LinkRejection::BadRevocation {
                    device: r.revocation.device.clone(),
                });
                continue;
            };
            if verifier
                .recover(&rev.signing_message(), &r.member_sig)
                .as_deref()
                == Some(rev.member.as_str())
            {
                self.revoked.insert((rev.member, rev.device));
            } else {
                rejected.push(LinkRejection::BadRevocation { device: rev.device });
            }
        }

        // 2. Verify each link; keep the newest per (device, member) when a link is re-issued.
        let mut verified: BTreeMap<String, Vec<DeviceLink>> = BTreeMap::new();
        for s in links {
            match verify_link(s, verifier) {
                Ok(()) => {
                    let l = &s.link;
                    // Canonical form of the verified body.
                    if let Some(c) = DeviceLink::new(
                        &l.member,
                        &l.device,
                        &l.wallet,
                        l.index,
                        &l.label,
                        l.issued_at,
                    ) {
                        verified.entry(c.device.clone()).or_default().push(c);
                    }
                }
                Err(e) => rejected.push(e),
            }
        }

        // 3. Resolve per device: drop revoked keys, refuse cross-member conflicts.
        let mut candidates: BTreeMap<String, DeviceLink> = BTreeMap::new();
        for (device, mut ls) in verified {
            let members: BTreeSet<&String> = ls.iter().map(|l| &l.member).collect();
            if members.len() > 1 {
                rejected.push(LinkRejection::Conflict { device });
                continue;
            }
            // Same member re-issued the link (e.g. a new label): the newest wins, ties by label.
            ls.sort_by(|a, b| (a.issued_at, &a.label).cmp(&(b.issued_at, &b.label)));
            let Some(newest) = ls.pop() else { continue };
            if self
                .revoked
                .contains(&(newest.member.clone(), newest.device.clone()))
            {
                rejected.push(LinkRejection::Revoked { device });
                continue;
            }
            candidates.insert(device, newest);
        }

        // 4. A member index names one device: two active devices on one (member, index) conflict.
        let mut by_slot: BTreeMap<(String, u32), Vec<String>> = BTreeMap::new();
        for (d, l) in &candidates {
            by_slot
                .entry((l.member.clone(), l.index))
                .or_default()
                .push(d.clone());
        }
        for devices in by_slot.values().filter(|ds| ds.len() > 1) {
            for d in devices {
                candidates.remove(d);
                rejected.push(LinkRejection::Conflict { device: d.clone() });
            }
        }

        self.links = candidates;
        rejected
    }

    /// The member a device is actively linked to (verified, unrevoked), if any.
    pub fn member_of(&self, device: &str) -> Option<&str> {
        let d = canonical_address(device)?;
        self.links.get(&d).map(|l| l.member.as_str())
    }

    /// Whether `device` was revoked by the member it is (or was) linked to.
    pub fn is_revoked(&self, member: &str, device: &str) -> bool {
        match (canonical_address(member), canonical_address(device)) {
            (Some(m), Some(d)) => self.revoked.contains(&(m, d)),
            _ => false,
        }
    }

    /// All active links, sorted by device.
    pub fn links(&self) -> Vec<DeviceLink> {
        self.links.values().cloned().collect()
    }

    /// The active links of one member, sorted by index.
    pub fn devices_of(&self, member: &str) -> Vec<DeviceLink> {
        let Some(m) = canonical_address(member) else {
            return Vec::new();
        };
        let mut v: Vec<DeviceLink> = self
            .links
            .values()
            .filter(|l| l.member == m)
            .cloned()
            .collect();
        v.sort_by_key(|l| l.index);
        v
    }

    /// The revoked (member, device) pairs, sorted.
    pub fn revocations(&self) -> Vec<(String, String)> {
        self.revoked.iter().cloned().collect()
    }
}

/// The roster the admission gate actually runs on: the member roster plus every actively linked
/// device of a member that is itself allowed, with the member's role. A device whose member is
/// offboarded (or drops below Member) leaves this set in the same step, and a revoked device is
/// never in it. A device address that is ALSO a roster member keeps only its member entry (a key
/// cannot be both a member identity and somebody's device), which keeps peer ids one-to-one.
pub fn effective_roster(
    roster: &[(String, String)],
    registry: &DeviceRegistry,
) -> Vec<(String, String)> {
    let mut role_of: BTreeMap<String, String> = BTreeMap::new();
    for (addr, role) in roster {
        if let Some(a) = canonical_address(addr) {
            // Highest role wins if an address appears twice (same rule as `allowed_set`'s threshold).
            let better = role_of
                .get(&a)
                .map(|r| role_rank(role) > role_rank(r))
                .unwrap_or(true);
            if better {
                role_of.insert(a, role.clone());
            }
        }
    }
    let mut out: Vec<(String, String)> = role_of
        .iter()
        .map(|(a, r)| (a.clone(), r.clone()))
        .collect();
    for l in registry.links.values() {
        if role_of.contains_key(&l.device) {
            continue; // a member key is never also a device
        }
        // The member must itself pass the cluster gate (on the roster, role >= Member).
        if let Some(role) = role_of.get(&l.member) {
            if role_rank(role) >= MIN_CLUSTER_RANK {
                out.push((l.device.clone(), role.clone()));
            }
        }
    }
    out.sort();
    out
}

/// One device in a member's roster entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    pub device: String,
    pub index: u32,
    pub label: String,
    pub issued_at: u64,
}

/// A roster entry with the member's devices listed under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDevices {
    pub member: String,
    pub role: String,
    pub devices: Vec<DeviceView>,
}

/// The roster with each allowed member's active devices listed under it (US-8.1: "both devices
/// appear under the member in the cluster roster"). Members below the cluster threshold are omitted,
/// like everywhere else in the gate.
pub fn device_roster(roster: &[(String, String)], registry: &DeviceRegistry) -> Vec<MemberDevices> {
    let mut out: BTreeMap<String, MemberDevices> = BTreeMap::new();
    for (addr, role) in roster {
        let Some(a) = canonical_address(addr) else {
            continue;
        };
        if role_rank(role) < MIN_CLUSTER_RANK {
            continue;
        }
        let entry = out.entry(a.clone()).or_insert_with(|| MemberDevices {
            member: a.clone(),
            role: role.clone(),
            devices: Vec::new(),
        });
        if role_rank(role) > role_rank(&entry.role) {
            entry.role = role.clone();
        }
    }
    for m in out.values_mut() {
        m.devices = registry
            .devices_of(&m.member)
            .into_iter()
            .map(|l| DeviceView {
                device: l.device,
                index: l.index,
                label: l.label,
                issued_at: l.issued_at,
            })
            .collect();
    }
    out.into_values().collect()
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod device_tests;
