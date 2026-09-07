//! CL-B-001 tripwire (negative regression test).
//!
//! The 32-byte secp256k1 cluster identity secret held in [`Libp2pConfig::secret`] must be wiped
//! from memory when the config is dropped. This test constructs a config with a known non-zero
//! secret, runs its destructor in place (via `ManuallyDrop`, which does NOT free the backing
//! storage), and then reads the secret bytes back out of that still-owned storage.
//!
//! Against the FIXED code (`impl Drop for Libp2pConfig` calls `secret.zeroize()`) the bytes are all
//! zero and the test passes. Against the PRE-FIX code (no `Drop`, no zeroize) the plain `[u8; 32]`
//! is left intact and the assertion FAILS — which is exactly the regression this guards.

use std::mem::ManuallyDrop;
use std::ptr;

use cluster_daemon::libp2p_transport::Libp2pConfig;

#[test]
fn libp2p_config_zeroizes_secret_on_drop() {
    let sentinel = [0xABu8; 32];

    // `ManuallyDrop` keeps the storage alive after we invoke the destructor, so reading the
    // `secret` field back is a read of memory we still own (not freed/reused heap).
    let mut cfg = ManuallyDrop::new(Libp2pConfig {
        secret: sentinel,
        listen: "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("static multiaddr parses"),
        group_id: "cl-b-001-test".to_string(),
        bootstrap: Vec::new(),
    });

    // Address of the secret field, captured before the destructor runs.
    let secret_ptr: *const [u8; 32] = ptr::addr_of!(cfg.secret);

    // Sanity: the secret is actually present before drop.
    let before = unsafe { ptr::read(secret_ptr) };
    assert_eq!(before, sentinel, "test setup: secret should be present before drop");

    // Run `Drop::drop` in place. ManuallyDrop does not free the stack storage afterwards.
    unsafe { ManuallyDrop::drop(&mut cfg) };

    // Read the same bytes back out of the (still-owned) storage the destructor operated on.
    let after = unsafe { ptr::read(secret_ptr) };

    assert!(
        after.iter().all(|&b| b == 0),
        "CL-B-001 regression: Libp2pConfig::secret was NOT zeroized on drop (found {after:?})"
    );
}
