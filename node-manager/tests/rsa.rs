// More can e.g. be generated via:
// openssl genrsa -out tests/test_keyN.pem 2048

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

fn test_key() -> &'static str {
    TEST_KEYS[0]
}

fn test_keys() -> &'static [&'static str] {
    TEST_KEYS
}

include!("../src/tests-template.rs");
