use node_manager::{self, NodeId, NodeManager};
use rsa::pkcs8::DecodePrivateKey;

fn make_node_manager() -> NodeManager {
    use rsa::pkcs8::EncodePrivateKey;

    fn gen_fn(data: &[u8]) -> Result<NodeId, ()> {
        Ok(NodeId::from_data(data))
    }

    let local_key =
        rsa::RsaPrivateKey::from_pkcs8_pem(include_str!("../tests/test_key1.pem")).unwrap();
    let local_key_der = local_key.to_pkcs8_der().unwrap();

    NodeManager::new(gen_fn, local_key_der.as_ref())
}

#[test]
fn node_manager_test_basic() {
    let _mgr = make_node_manager();
}

#[test]
fn node_manager_test_signing() {
    let test_key_1 = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!("test_key1.pem")).unwrap();
    let test_key_2 = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!("test_key2.pem")).unwrap();

    let test_op = node_manager::Operation::AddByAdmin(vec![1, 2, 3, 4]);
    let test_op_other = node_manager::Operation::AddByAdmin(vec![4, 3, 2, 1]);

    let msg = test_op.clone().sign(246_802_000, &test_key_1).unwrap();

    assert!(msg.signature_is_valid(&test_key_1));

    // Test that validation fails with different key
    assert!(!msg.signature_is_valid(&test_key_2));

    // Test that validation fails with different data for time
    let mut msg_diff_time = msg.clone();
    msg_diff_time.timestamp += 1;
    assert!(!msg_diff_time.signature_is_valid(&test_key_1));

    let mut msg_diff_time = msg.clone();
    msg_diff_time.timestamp += 1;
    assert!(!msg_diff_time.signature_is_valid(&test_key_1));
}
