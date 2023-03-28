use rsa::padding::PaddingScheme;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::{PublicKey as _, RsaPrivateKey, RsaPublicKey};
use sha2::Digest;
use std::error::Error;

#[derive(Clone)]
pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let pk = RsaPrivateKey::from_pkcs8_der(der).map_err(Box::<dyn Error>::from)?;
        Ok(PrivateKey(pk))
    }
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        let pk = RsaPrivateKey::from_pkcs8_pem(pem).map_err(Box::<dyn Error>::from)?;
        Ok(PrivateKey(pk))
    }
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let key_der = self.0.to_pkcs8_der().map_err(Box::<dyn Error>::from)?;

        let key_der_slice: &[u8] = key_der.as_ref();
        Ok(key_der_slice.to_vec())
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.0
            .decrypt(padding_scheme_encrypt(), data)
            .map_err(Box::<dyn Error>::from)
    }
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.0
            .sign(padding_scheme_sign(), digest)
            .map_err(Box::<dyn Error>::from)
    }
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.to_public_key())
    }
}

pub trait VerifySignature {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>>;
}

impl VerifySignature for PrivateKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        (*self.0)
            .verify(padding_scheme_sign(), digest, signature)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

impl VerifySignature for PublicKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        self.verify(digest, signature)
    }
}

#[derive(Clone)]
pub struct PublicKey(RsaPublicKey);

impl PublicKey {
    pub fn from_public_key_der(public_key_der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let pk =
            RsaPublicKey::from_public_key_der(public_key_der).map_err(Box::<dyn Error>::from)?;
        Ok(PublicKey(pk))
    }
    pub fn to_public_key_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let key_pub = self.0.to_public_key_der().map_err(Box::<dyn Error>::from)?;
        let key_der_slice: &[u8] = key_pub.as_ref();
        Ok(key_der_slice.to_vec())
    }
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        self.0
            .verify(padding_scheme_sign(), digest, signature)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.0
            .encrypt(&mut OsRng, padding_scheme_encrypt(), data)
            .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}

fn padding_scheme_sign() -> PaddingScheme {
    PaddingScheme::PSS {
        digest: Box::new(sha2::Sha256::new()),
        salt_rng: Box::new(OsRng),
        salt_len: Some(16),
    }
}

fn padding_scheme_encrypt() -> PaddingScheme {
    PaddingScheme::OAEP {
        digest: Box::new(sha2::Sha256::new()),
        mgf_digest: Box::new(sha2::Sha256::new()),
        label: Some(String::new()),
    }
}
