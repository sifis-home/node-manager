use once_cell::sync::OnceCell;

// These statics exist so that the LeakSanitizer doesn't think the keys are "leaked"
// TODO: once once_cell from core stabilizes, use that one
static KEYS_STORAGE: OnceCell<Vec<Box<str>>> = OnceCell::new();
static KEYS: OnceCell<Vec<&'static str>> = OnceCell::new();

fn test_key() -> &'static str {
    test_keys()[0]
}

fn test_keys() -> &'static [&'static str] {
    KEYS.get_or_init(|| {
        let vec_ref = KEYS_STORAGE.get_or_init(|| {
            let mut rng = TestRng::new();
            (0..20)
                .map(|_| {
                    PrivateKey::generate_ed25519_rng(&mut rng)
                        .to_pkcs8_pem()
                        .unwrap()
                        .into_boxed_str()
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

include!("../src/tests-template.rs");
