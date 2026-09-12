#[test]
fn verify_ietf_rejects_wrong_proof_length() {
    let err = pbnjam_ring_proof_core::verify_ietf_vrf(&[0u8; 32], &[0u8; 32], &[0u8; 8], &[])
        .expect_err("short proof");
    assert!(err.to_string().contains("Invalid proof length"));
}
