use once_cell::sync::OnceCell;
use rand_07::{rngs::SmallRng, CryptoRng, RngCore, SeedableRng};

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

// This static exists so that the LeakSanitizer doesn't think the keys are "leaked"
// TODO: once once_cell from core stabilizes, use that one
static KEYS: OnceCell<&'static [&'static str]> = OnceCell::new();

fn test_key() -> &'static str {
    test_keys()[0]
}

fn test_keys() -> &'static [&'static str] {
    KEYS.get_or_init(|| {
        let mut rng = TestRng(SmallRng::seed_from_u64(10_424_143));
        (0..20)
            .map(|_| {
                &*Box::leak(
                    PrivateKey::generate_ed25519_rng(&mut rng)
                        .to_pkcs8_pem()
                        .unwrap()
                        .into_boxed_str(),
                )
            })
            .collect::<Vec<_>>()
            .leak()
    })
}

include!("../src/tests-template.rs");
