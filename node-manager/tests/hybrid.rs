use once_cell::sync::OnceCell;
use rand_07::{rngs::SmallRng, CryptoRng, RngCore, SeedableRng};

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

/// Testing random number generator for determinism during testing
struct TestRng(SmallRng);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), rand_07::Error> {
        self.0.try_fill_bytes(buf)
    }
}

impl CryptoRng for TestRng {}

// These statics exist so that the LeakSanitizer doesn't think the keys are "leaked"
// TODO: once once_cell from core stabilizes, use that one
static KEYS_STORAGE: OnceCell<Vec<Box<str>>> = OnceCell::new();
static KEYS: OnceCell<Vec<&'static str>> = OnceCell::new();

fn test_keys() -> &'static [&'static str] {
    KEYS.get_or_init(|| {
        let vec_ref = KEYS_STORAGE.get_or_init(|| {
            let mut rng = TestRng(SmallRng::seed_from_u64(10_424_143));
            (0..20)
                .map(|v| {
                    if v % 2 == 0 {
                        TEST_KEYS[v].to_string().into_boxed_str()
                    } else {
                        PrivateKey::generate_ed25519_rng(&mut rng)
                            .to_pkcs8_pem()
                            .unwrap()
                            .into_boxed_str()
                    }
                })
                .collect::<Vec<_>>()
        });
        vec_ref
            .iter()
            .map(|r| {
                let r: &'static str = r;
                r
            })
            .collect::<Vec<&'static str>>()
    })
}

fn test_key() -> &'static str {
    test_keys()[0]
}

include!("../src/tests-template.rs");
