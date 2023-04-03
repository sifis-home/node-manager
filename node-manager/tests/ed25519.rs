fn test_key() -> &'static str {
    Box::leak(
        PrivateKey::generate_ed25519()
            .to_pkcs8_pem()
            .unwrap()
            .into_boxed_str(),
    )
}

fn test_keys() -> &'static [&'static str] {
    (0..20)
        .map(|_| {
            &*Box::leak(
                PrivateKey::generate_ed25519()
                    .to_pkcs8_pem()
                    .unwrap()
                    .into_boxed_str(),
            )
        })
        .collect::<Vec<_>>()
        .leak()
}

include!("../src/tests-template.rs");
