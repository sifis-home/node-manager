use node_manager::admin::AdminNode;
use node_manager::{self, Message, NodeManager, NodeManagerBuilder, Response};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use std::collections::HashMap;

// More can e.g. be generated via:
// openssl genrsa -out tests/test_keyN.pem 2048

const TEST_KEY_1: &str = include_str!("keys/test_key1.pem");
const TEST_KEY_2: &str = include_str!("keys/test_key2.pem");
const TEST_KEY_3: &str = include_str!("keys/test_key3.pem");
const TEST_KEY_4: &str = include_str!("keys/test_key4.pem");

const TEST_KEYS: &[&str] = &[
    include_str!("keys/test_key1.pem"),
    include_str!("keys/test_key2.pem"),
    include_str!("keys/test_key3.pem"),
    include_str!("keys/test_key4.pem"),
    include_str!("keys/test_key5.pem"),
    include_str!("keys/test_key6.pem"),
    include_str!("keys/test_key7.pem"),
    include_str!("keys/test_key8.pem"),
    include_str!("keys/test_key9.pem"),
    include_str!("keys/test_key10.pem"),
    include_str!("keys/test_key11.pem"),
    include_str!("keys/test_key12.pem"),
    include_str!("keys/test_key13.pem"),
    include_str!("keys/test_key14.pem"),
    include_str!("keys/test_key15.pem"),
    include_str!("keys/test_key16.pem"),
    include_str!("keys/test_key17.pem"),
    include_str!("keys/test_key18.pem"),
    include_str!("keys/test_key19.pem"),
    include_str!("keys/test_key20.pem"),
];

const TEST_SHARED_KEY: &[u8] = &[1; 32];

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn make_node_manager(pem: &str) -> NodeManager {
    make_node_manager_key(pem, None)
}

fn key_pem_to_der(key_pem: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem).unwrap();
    let key_der = key.to_pkcs8_der().unwrap();

    let key_der_slice: &[u8] = key_der.as_ref();
    key_der_slice.to_vec()
}

fn key_pem_pair_to_der_public(key_pem: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem).unwrap();
    let key_pub = key.to_public_key().to_public_key_der().unwrap();

    let key_der_slice: &[u8] = key_pub.as_ref();
    key_der_slice.to_vec()
}

fn make_node_manager_key(pem: &str, key: Option<Vec<u8>>) -> NodeManager {
    fn gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(data.to_vec())
    }

    let mut builder = NodeManagerBuilder::new(&key_pem_to_der(pem), gen_fn);
    if let Some(key) = key {
        builder = builder.shared_key(key);
    }
    builder.build()
}

#[test]
fn node_manager_test_basic() {
    let _mgr = make_node_manager(TEST_KEY_1);
}

#[test]
fn node_manager_test_signing() {
    let test_key_1 = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_KEY_1).unwrap();
    let test_key_2 = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_KEY_2).unwrap();

    let test_op = node_manager::Operation::AddByAdmin(vec![1, 2, 3, 4]);

    let msg = test_op.clone().sign(246_802_000, &[], &test_key_1).unwrap();

    assert!(msg.signature_is_valid(&test_key_1));

    // Test that validation fails with different key
    assert!(!msg.signature_is_valid(&test_key_2));

    // Test that validation fails with different data for time
    let mut msg_diff_time = msg.clone();
    msg_diff_time.timestamp += 1;
    assert!(!msg_diff_time.signature_is_valid(&test_key_1));
}

type MsgBuf = HashMap<Option<Vec<u8>>, Vec<Message>>;

fn handle_msg_buf(
    nodes: &mut [NodeManager],
    buf: &MsgBuf,
    timestamp: u64,
) -> (Vec<Option<Vec<u8>>>, MsgBuf) {
    let mut new_buf = MsgBuf::new();
    let mut new_shared_keys = vec![None; nodes.len()];
    let msgs_count: usize = buf.iter().map(|(_, msgs)| msgs.len()).sum();
    log::info!(
        "Distributing {msgs_count} message{s} to nodes...",
        s = if msgs_count > 1 { "s" } else { "" }
    );
    for (node_i, node) in nodes.iter_mut().enumerate() {
        for (net_id, msgs) in buf {
            for msg in msgs {
                if let Some(net_id) = net_id {
                    if net_id != node.shared_key() {
                        // Mismatch, this node will not receive this message :)
                        continue;
                    }
                }
                let in_members_network = net_id.is_some();
                let msg_bytes = msg.serialize();
                let resps = node
                    .handle_msg_ts(&msg_bytes, in_members_network, timestamp)
                    .unwrap();
                for resp in resps {
                    match resp {
                        Response::SetSharedKey(k) => {
                            new_shared_keys[node_i] = Some(k);
                        }
                        Response::Message(msg, for_members_network) => {
                            let net_id = for_members_network.then(|| node.shared_key().to_vec());
                            let list = new_buf.entry(net_id).or_default();
                            list.push(msg);
                        }
                    }
                }
            }
        }
    }
    (new_shared_keys, new_buf)
}

#[test]
fn node_manager_test_joining() {
    #![allow(unused_assignments)]
    init_logger();

    let admin_key_pair_der = key_pem_to_der(TEST_KEY_1);
    let admin = node_manager::admin::AdminNode::from_key_pair_der(&admin_key_pair_der);

    let mut nodes = vec![
        make_node_manager_key(TEST_KEY_2, Some(TEST_SHARED_KEY.to_vec())),
        make_node_manager(TEST_KEY_3),
        make_node_manager(TEST_KEY_4),
    ];

    let key_3_der_public = key_pem_pair_to_der_public(TEST_KEY_3);
    let key_4_der_public = key_pem_pair_to_der_public(TEST_KEY_4);

    let admin_public_key_der = admin.public_key_der();
    nodes.iter_mut().for_each(|nd| {
        nd.add_admin_key_der(&admin_public_key_der).unwrap();
    });

    let msg_add_1 = admin.sign_addition(&key_4_der_public, 77).unwrap();

    let mut new_keys;
    let mut msg_buf = MsgBuf::new();

    // Distribute the addition message on the lobby network
    msg_buf.entry(None).or_default().push(msg_add_1);

    // One round of message handling
    (new_keys, msg_buf) = handle_msg_buf(&mut nodes, &msg_buf, 100_500);

    assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 0);

    (new_keys, msg_buf) = handle_msg_buf(&mut nodes, &msg_buf, 100_600);

    // Node 2 has joined!
    assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 1);
    assert_eq!(new_keys[2], Some(TEST_SHARED_KEY.to_vec()));

    let msg_add_2 = admin.sign_addition(&key_3_der_public, 100_650).unwrap();

    // Distribute the addition message on the lobby network
    msg_buf.entry(None).or_default().push(msg_add_2);

    (new_keys, msg_buf) = handle_msg_buf(&mut nodes, &msg_buf, 100_700);

    assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 0);

    (new_keys, msg_buf) = handle_msg_buf(&mut nodes, &msg_buf, 100_800);

    // Node 1 has joined!
    assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 1);
    assert_eq!(new_keys[1], Some(TEST_SHARED_KEY.to_vec()));
}

struct NetworkSimulator {
    admin: AdminNode,
    nodes: Vec<NodeManager>,
    msg_buf: MsgBuf,
}

impl NetworkSimulator {
    fn new(
        admin_key_pair_pem: &str,
        init_nodes: Vec<NodeManager>,
        add_nodes_keys_pem: &[&str],
    ) -> Self {
        let admin_key_pair_der = key_pem_to_der(admin_key_pair_pem);
        let admin = node_manager::admin::AdminNode::from_key_pair_der(&admin_key_pair_der);

        let mut nodes = init_nodes;
        nodes.extend(add_nodes_keys_pem.iter().map(|k| make_node_manager(k)));

        let admin_public_key_der = admin.public_key_der();
        nodes.iter_mut().for_each(|nd| {
            nd.add_admin_key_der(&admin_public_key_der).unwrap();
        });

        Self {
            admin,
            nodes,
            msg_buf: MsgBuf::new(),
        }
    }
    fn msg_buf_round(&mut self, ts: u64) -> Vec<Option<Vec<u8>>> {
        let (new_keys, msg_buf) = handle_msg_buf(&mut self.nodes, &self.msg_buf, ts);
        self.msg_buf = msg_buf;
        new_keys
    }
    fn handle_node_join(&mut self, node_idx: usize, ts_1: u64, ts_2: u64) {
        let node_public_der = self.nodes[node_idx].public_key_der();
        let msg_add = self.admin.sign_addition(&node_public_der, 77).unwrap();

        // Distribute the addition message on the lobby network
        self.msg_buf.entry(None).or_default().push(msg_add);

        // One round of message handling
        let mut new_keys;
        new_keys = self.msg_buf_round(ts_1);

        assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 0);

        // Another round for the response
        new_keys = self.msg_buf_round(ts_2);

        // Node has joined!
        assert_eq!(new_keys.iter().filter(|k| k.is_some()).count(), 1);
        assert_eq!(
            new_keys[node_idx],
            Some(TEST_SHARED_KEY.to_vec()),
            "can't see node {} as joined",
            node_idx
        );
        assert_eq!(self.nodes[node_idx].shared_key(), TEST_SHARED_KEY.to_vec());
    }
}

#[test]
fn node_manager_test_joining_20() {
    init_logger();

    let nodes = vec![make_node_manager_key(
        TEST_KEY_2,
        Some(TEST_SHARED_KEY.to_vec()),
    )];
    let mut sim = NetworkSimulator::new(TEST_KEY_1, nodes, &TEST_KEYS[2..]);

    println!("Nodes generated");

    for (i, _) in TEST_KEYS[2..].iter().enumerate() {
        let ts = 100_000 + i as u64 * 100;
        sim.handle_node_join(i + 1, ts, ts + 50);
    }
}
