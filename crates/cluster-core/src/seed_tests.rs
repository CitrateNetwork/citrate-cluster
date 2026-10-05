//! HUP-S8.4: group seed (link/QR) encode/decode and every refusal.

use super::*;

const PEER: &str = "16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ";

fn ma(port: u16) -> String {
    format!("/ip4/192.168.1.20/tcp/{port}/p2p/{PEER}")
}

#[test]
fn a_seed_round_trips_through_its_link_text() {
    let seed = GroupSeed::new("group-7f3a", vec![ma(4211), ma(4300)]).expect("valid");
    let text = seed.encode();
    assert!(text.starts_with(SEED_PREFIX), "{text}");
    assert!(
        text.contains("&a=/ip4/192.168.1.20/tcp/4211/p2p/"),
        "{text}"
    );
    assert_eq!(GroupSeed::decode(&text), Ok(seed));
}

#[test]
fn group_ids_with_reserved_characters_and_ipv6_addresses_survive() {
    let g = "team & co = #1 +x %y ü";
    let v6 = format!("/ip6/fe80::1/tcp/4211/p2p/{PEER}");
    let seed = GroupSeed::new(g, vec![v6.clone()]).expect("valid");
    let text = seed.encode();
    assert!(!text.contains(' '), "no raw space in a QR link: {text}");
    // A URL handler would read `#` as a fragment and `+` as a space, and `=`/`&` split fields.
    for esc in ["%26", "%3D", "%23", "%2B", "%25", "%20"] {
        assert!(text.contains(esc), "{esc} escaped in {text}");
    }
    assert!(!text.contains('#') && !text.contains('+'), "{text}");
    let back = GroupSeed::decode(&format!("  {text}\n")).expect("decodes");
    assert_eq!(back.group, g);
    assert_eq!(back.addrs, vec![v6]);
}

#[test]
fn unknown_keys_are_ignored_for_forward_compatibility() {
    let text = format!("{SEED_PREFIX}v=1&g=g1&x=later&a={}", ma(1));
    assert_eq!(GroupSeed::decode(&text).map(|s| s.addrs.len()), Ok(1));
}

#[test]
fn refuses_text_that_is_not_a_seed_or_has_the_wrong_version() {
    assert_eq!(
        GroupSeed::decode("https://example.com/?v=1"),
        Err(SeedError::NotASeed)
    );
    let no_v = format!("{SEED_PREFIX}g=g1&a={}", ma(1));
    assert_eq!(GroupSeed::decode(&no_v), Err(SeedError::Version));
    let v2 = format!("{SEED_PREFIX}v=2&g=g1&a={}", ma(1));
    assert_eq!(GroupSeed::decode(&v2), Err(SeedError::Version));
}

#[test]
fn refuses_a_missing_repeated_empty_or_control_group() {
    let a = ma(1);
    for text in [
        format!("{SEED_PREFIX}v=1&a={a}"),
        format!("{SEED_PREFIX}v=1&g=&a={a}"),
        format!("{SEED_PREFIX}v=1&g=%20%20&a={a}"),
        format!("{SEED_PREFIX}v=1&g=a&g=b&a={a}"),
        format!("{SEED_PREFIX}v=1&g=a%0Ab&a={a}"),
        format!("{SEED_PREFIX}v=1&g={}&a={a}", "x".repeat(MAX_GROUP_LEN + 1)),
    ] {
        assert_eq!(GroupSeed::decode(&text), Err(SeedError::Group), "{text}");
    }
}

#[test]
fn refuses_no_addresses_or_too_many() {
    let none = format!("{SEED_PREFIX}v=1&g=g1");
    assert_eq!(GroupSeed::decode(&none), Err(SeedError::AddrCount));
    let many: String = (0..=MAX_SEED_ADDRS as u16)
        .map(|p| format!("&a={}", ma(p)))
        .collect();
    let text = format!("{SEED_PREFIX}v=1&g=g1{many}");
    assert_eq!(GroupSeed::decode(&text), Err(SeedError::AddrCount));
    assert_eq!(GroupSeed::new("g1", vec![]), Err(SeedError::AddrCount));
}

#[test]
fn refuses_an_address_without_a_peer_id_or_with_junk() {
    for bad in [
        "/ip4/10.0.0.1/tcp/4211".to_string(), // no /p2p/: cannot be matched to a peer
        "ip4/10.0.0.1/tcp/4211/p2p/abc".to_string(), // not a multiaddr
        "/ip4/10.0.0.1//tcp/1/p2p/abc".to_string(), // empty segment
        "/ip4/10.0.0.1/tcp/1/p2p/".to_string(), // empty peer id
        "/ip4/10.0.0.1/tcp/1/p2p/ab-c".to_string(), // not a base58/base32 id
        format!("/dns4/{}/tcp/1/p2p/{PEER}", "h".repeat(MAX_ADDR_LEN)),
    ] {
        assert_eq!(
            GroupSeed::new("g1", vec![bad.clone()]),
            Err(SeedError::Addr),
            "{bad}"
        );
    }
    let spaced = format!("{SEED_PREFIX}v=1&g=g1&a=/ip4/1.2.3.4/tcp/1%20/p2p/{PEER}");
    assert_eq!(GroupSeed::decode(&spaced), Err(SeedError::Addr));
}

#[test]
fn refuses_bad_escapes_non_utf8_and_oversize_text() {
    let a = ma(1);
    for text in [
        format!("{SEED_PREFIX}v=1&g=%zz&a={a}"),
        format!("{SEED_PREFIX}v=1&g=%4&a={a}"),
        format!("{SEED_PREFIX}v=1&g=%FF&a={a}"),
    ] {
        assert_eq!(GroupSeed::decode(&text), Err(SeedError::Encoding), "{text}");
    }
    let huge = format!("{SEED_PREFIX}v=1&g={}", "g".repeat(MAX_SEED_LEN));
    assert_eq!(GroupSeed::decode(&huge), Err(SeedError::TooLong));
}

#[test]
fn errors_read_as_plain_words() {
    assert_eq!(
        SeedError::AddrCount.to_string(),
        "seed must carry between 1 and 8 addresses"
    );
    assert_eq!(SeedError::NotASeed.to_string(), "not a cluster seed");
}
