//! HUP-S8.1 / S8.4 soak fixture: a throwaway fleet for the daemon-level multi-machine DeviceLink runs
//! (`scripts/soak/DEVICELINK_MULTI_MACHINE.md`). NOT shipped and never pointed at a real wallet.
//!
//! The real app links a device with three signatures, the wallet one collected through core's
//! SignatureCeremony. A daemon-level soak has no app, so this tool mints FRESH random test keys for
//! every member, wallet and device, signs the links and the revocations once, in memory, and writes:
//!
//! * `device-<m>-<d>.seed`: each device's secret (0600), copied to the machine that runs that device;
//! * `roster.json`: `[[member, "member"], ...]`;
//! * `links.json`: every signed link (public attestations);
//! * `revoke-<m>-<d>.json`: a one-element list with that device's signed revocation;
//! * `fleet.json`: a summary (member, device addresses, labels) for the operator.
//!
//! Member and wallet secrets are never written anywhere: they exist only while this process runs.
//!
//! ```text
//! cargo run --release -p cluster-daemon --example devicelink_fixture -- <out-dir> <devices-per-member...>
//! # two machines, two members with one device each:     ... -- fleet-test 1 1
//! # three machines, member 1 with two, member 2 one:    ... -- fleet-test 2 1
//! ```

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;

    use cluster_core::device::{DeviceLink, DeviceRevocation};
    use cluster_daemon::devices::{address_of, eip191_digest};
    use k256::ecdsa::SigningKey;
    use serde_json::{json, Value};

    fn fresh_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
        let mut f = std::fs::File::open("/dev/urandom")?;
        loop {
            let mut b = zeroize::Zeroizing::new([0u8; 32]);
            f.read_exact(b.as_mut())?;
            if let Ok(k) = SigningKey::from_slice(b.as_ref()) {
                return Ok(k);
            }
        }
    }
    fn sign(k: &SigningKey, msg: &str) -> Result<String, Box<dyn std::error::Error>> {
        let (sig, recid) = k.sign_prehash_recoverable(&eip191_digest(msg.as_bytes()))?;
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + recid.to_byte());
        Ok(format!("0x{}", hex::encode(out)))
    }
    fn write(path: &std::path::Path, body: &str, mode: u32) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        f.write_all(body.as_bytes())
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage =
        "usage: devicelink_fixture <out-dir> <devices-per-member> [<devices-per-member> ...]";
    let out = std::path::PathBuf::from(args.first().ok_or(usage)?);
    let counts: Vec<u32> = args[1..]
        .iter()
        .map(|s| s.parse::<u32>())
        .collect::<Result<_, _>>()
        .map_err(|_| usage)?;
    if counts.is_empty() || counts.iter().any(|c| *c == 0 || *c > 8) || counts.len() > 16 {
        return Err("1 to 16 members, each with 1 to 8 devices".into());
    }
    if out.exists() {
        return Err(format!("{} exists; pick a new directory", out.display()).into());
    }
    std::fs::create_dir_all(&out)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut roster = Vec::new();
    let mut links = Vec::new();
    let mut summary = Vec::new();
    for (mi, n) in counts.iter().enumerate() {
        let m = mi + 1;
        let member = fresh_key()?;
        let wallet = fresh_key()?;
        let member_addr = address_of(member.verifying_key());
        roster.push(json!([member_addr, "member"]));
        let mut devices = Vec::new();
        for d in 1..=*n {
            let device = fresh_key()?;
            let label = format!("member {m} device {d}");
            let link = DeviceLink::new(
                &member_addr,
                &address_of(device.verifying_key()),
                &address_of(wallet.verifying_key()),
                d - 1,
                &label,
                now,
            )
            .ok_or("link body did not validate")?;
            let msg = link.signing_message();
            links.push(json!({
                "member": link.member, "device": link.device, "wallet": link.wallet,
                "index": link.index, "label": link.label, "issuedAt": link.issued_at,
                "memberSig": sign(&member, &msg)?, "deviceSig": sign(&device, &msg)?,
                "walletSig": sign(&wallet, &msg)?,
            }));
            let rev = DeviceRevocation::new(&member_addr, &link.device, now + 1)
                .ok_or("revocation body did not validate")?;
            let rev_json = json!([{
                "member": rev.member, "device": rev.device, "revokedAt": rev.revoked_at,
                "memberSig": sign(&member, &rev.signing_message())?,
            }]);
            write(
                &out.join(format!("revoke-{m}-{d}.json")),
                &serde_json::to_string_pretty(&rev_json)?,
                0o644,
            )?;
            let seed = zeroize::Zeroizing::new(hex::encode(device.to_bytes()));
            write(&out.join(format!("device-{m}-{d}.seed")), &seed, 0o600)?;
            devices.push(json!({ "device": link.device, "label": label, "seedFile": format!("device-{m}-{d}.seed") }));
        }
        summary.push(json!({ "member": member_addr, "devices": devices }));
    }
    write(
        &out.join("roster.json"),
        &serde_json::to_string_pretty(&Value::Array(roster))?,
        0o644,
    )?;
    write(
        &out.join("links.json"),
        &serde_json::to_string_pretty(&Value::Array(links))?,
        0o644,
    )?;
    let fleet = json!({ "createdAt": now, "testKeysOnly": true, "members": summary });
    write(
        &out.join("fleet.json"),
        &serde_json::to_string_pretty(&fleet)?,
        0o644,
    )?;
    println!("{}", serde_json::to_string_pretty(&fleet)?);
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("devicelink_fixture runs on macOS and Linux only");
    std::process::exit(2);
}
