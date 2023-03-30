use base64ct::{Base64, Decoder, Encoder, Encoding};
use ed25519_dalek::{
    Keypair as EdKeypair, PublicKey as EdPublicKey, Signature as EdSignature, Signer, Verifier,
};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha384;
use hpke::kem::{Kem, X25519HkdfSha256};
use hpke::{single_shot_open, single_shot_seal, Deserializable, OpModeR, OpModeS, Serializable};
use rand::SeedableRng;
use rsa::padding::PaddingScheme;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::{PublicKey as _, RsaPrivateKey, RsaPublicKey};
use sha2::Digest;
use std::error::Error;

pub type X25519Public = <X25519HkdfSha256 as Kem>::PublicKey;
pub type X25519Private = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type X25519Encapped = <X25519HkdfSha256 as Kem>::EncappedKey;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;
type KemUsed = X25519HkdfSha256;

#[derive(Clone)]
pub struct PrivateKey(PrivKey);

enum PrivKey {
    Rsa(RsaPrivateKey),
    Ed25519 {
        der: Vec<u8>,
        k_priv: X25519Private,
        k_pub: X25519Public,
        sign_key: EdKeypair,
    },
}

impl Clone for PrivKey {
    fn clone(&self) -> Self {
        match self {
            PrivKey::Rsa(rsa) => PrivKey::Rsa(rsa.clone()),
            PrivKey::Ed25519 {
                der,
                k_priv,
                k_pub,
                sign_key,
            } => PrivKey::Ed25519 {
                der: der.clone(),
                k_priv: k_priv.clone(),
                k_pub: k_pub.clone(),
                // We manually implement clone here because EdKeyPair does not impl clone:
                sign_key: EdKeypair::from_bytes(&sign_key.to_bytes()).unwrap(),
            },
        }
    }
}

impl PrivateKey {
    pub fn generate_ed25519() -> Self {
        let mut csprng = rand_07::rngs::OsRng;
        let ed_key_pair = EdKeypair::generate(&mut csprng);
        let der = ed_key_pair.to_bytes();
        Self::from_pkcs8_der(&der).unwrap()
    }
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        match RsaPrivateKey::from_pkcs8_der(der) {
            Ok(pk) => return Ok(PrivateKey(PrivKey::Rsa(pk))),
            Err(_) => {
                // Note: This isn't really in der format, nor pkcs8.
                // TODO: find a better name for this function and the pem equivalent.
                let sign_key = EdKeypair::from_bytes(der).map_err(Box::<dyn Error>::from)?;
                // Note: what we are doing below is not 100% great because it uses the input data as *pseudorandom*,
                // not to unwrap the key directly. If we arrived at precisely the same key as used for signing it
                // might not be a good idea either due to the key being reused. Thus, we have this weird code here.
                // It's not 100% perfect, ideally we'd do something else.
                let (k_priv, k_pub) = X25519HkdfSha256::derive_keypair(der);
                Ok(PrivateKey(PrivKey::Ed25519 {
                    der: der.to_vec(),
                    k_priv,
                    k_pub,
                    sign_key,
                }))
            }
        }
    }
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        let pk = match RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(pk) => PrivKey::Rsa(pk),
            Err(_) => {
                let der = Base64::decode_vec(pem).unwrap();
                return Self::from_pkcs8_der(&der);
            }
        };
        Ok(PrivateKey(pk))
    }
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.0 {
            PrivKey::Rsa(pk) => {
                let key_der = pk.to_pkcs8_der().map_err(Box::<dyn Error>::from)?;

                let key_der_slice: &[u8] = key_der.as_ref();
                Ok(key_der_slice.to_vec())
            }
            PrivKey::Ed25519 { der, .. } => Ok(der.to_vec()),
        }
    }
    pub fn to_pkcs8_pem(&self) -> Result<String, Box<dyn Error>> {
        match &self.0 {
            PrivKey::Rsa(pk) => Ok(pk.to_pkcs8_pem(Default::default())?.as_str().to_owned()),
            PrivKey::Ed25519 { .. } => Ok(Base64::encode_string(&self.to_pkcs8_der()?)),
        }
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.0 {
            PrivKey::Rsa(pk) => pk
                .decrypt(padding_scheme_encrypt(), data)
                .map_err(Box::<dyn Error>::from),
            PrivKey::Ed25519 { k_priv, .. } => {
                // TODO get rid of unwraps
                let (key_encapped_data, ciphertext_data): (Vec<u8>, Vec<u8>) =
                    bincode::deserialize(&data).map_err(Box::<dyn Error>::from)?;
                let encapped_key =
                    <X25519Encapped as Deserializable>::from_bytes(&key_encapped_data).unwrap();
                let opened = single_shot_open::<Aead, Kdf, KemUsed>(
                    &OpModeR::Base,
                    k_priv,
                    &encapped_key,
                    INFO_STR,
                    &ciphertext_data,
                    &[],
                )
                .unwrap();
                Ok(opened)
            }
        }
    }
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.0 {
            PrivKey::Rsa(pk) => pk
                .sign(padding_scheme_sign(), digest)
                .map_err(Box::<dyn Error>::from),
            PrivKey::Ed25519 { sign_key, .. } => Ok(sign_key.sign(digest).to_bytes().to_vec()),
        }
    }
    pub fn to_public_key(&self) -> PublicKey {
        let pk = match &self.0 {
            PrivKey::Rsa(pk) => PubKey::Rsa(pk.to_public_key()),
            PrivKey::Ed25519 {
                k_pub, sign_key, ..
            } => {
                let sign_pub = sign_key.public;
                let der = bincode::serialize::<(Vec<u8>, &[u8; 32])>(&(
                    k_pub.to_bytes().to_vec(),
                    sign_pub.as_bytes(),
                ))
                .unwrap();
                let k_pub = k_pub.clone();
                let sign_pub = sign_pub.clone();
                PubKey::Ed25519 {
                    der,
                    k_pub,
                    sign_pub,
                }
            }
        };
        PublicKey(pk)
    }
}

pub trait VerifySignature {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>>;
}

impl VerifySignature for PrivateKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        match &self.0 {
            PrivKey::Rsa(pk) => pk
                .verify(padding_scheme_sign(), digest, signature)
                .map_err(|e| Box::new(e) as Box<dyn Error>),
            PrivKey::Ed25519 { sign_key, .. } => {
                let signature = EdSignature::from_bytes(signature)
                    .map_err(|e| Box::new(e) as Box<dyn Error>)?;
                sign_key
                    .verify(digest, &signature)
                    .map_err(Box::<dyn Error>::from)
            }
        }
    }
}

impl VerifySignature for PublicKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        self.verify(digest, signature)
    }
}

#[derive(Clone)]
pub struct PublicKey(PubKey);

#[derive(Clone)]
enum PubKey {
    Rsa(RsaPublicKey),
    Ed25519 {
        // TODO this one isn't really needed
        der: Vec<u8>,
        k_pub: X25519Public,
        sign_pub: EdPublicKey,
    },
}

impl PublicKey {
    pub fn from_public_key_der(public_key_der: &[u8]) -> Result<Self, Box<dyn Error>> {
        let pk = match RsaPublicKey::from_public_key_der(public_key_der) {
            Ok(pk) => PubKey::Rsa(pk),
            Err(_) => {
                let (k_pub_bytes, sign_pub_bytes): (Vec<u8>, [u8; 32]) =
                    bincode::deserialize(public_key_der).map_err(Box::<dyn Error>::from)?;
                // TODO get rid of unwrap
                let k_pub = X25519Public::from_bytes(&k_pub_bytes).unwrap();
                let sign_pub =
                    EdPublicKey::from_bytes(&sign_pub_bytes).map_err(Box::<dyn Error>::from)?;
                PubKey::Ed25519 {
                    der: public_key_der.to_vec(),
                    k_pub,
                    sign_pub,
                }
            }
        };
        Ok(PublicKey(pk))
    }
    pub fn to_public_key_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.0 {
            PubKey::Rsa(pk) => {
                let key_pub = pk.to_public_key_der().map_err(Box::<dyn Error>::from)?;
                let key_der_slice: &[u8] = key_pub.as_ref();
                Ok(key_der_slice.to_vec())
            }
            PubKey::Ed25519 { der, .. } => Ok(der.clone()),
        }
    }
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        match &self.0 {
            PubKey::Rsa(pk) => pk
                .verify(padding_scheme_sign(), digest, signature)
                .map_err(|e| Box::new(e) as Box<dyn Error>),
            PubKey::Ed25519 { sign_pub, .. } => {
                let signature = EdSignature::from_bytes(signature)
                    .map_err(|e| Box::new(e) as Box<dyn Error>)?;
                sign_pub
                    .verify(digest, &signature)
                    .map_err(Box::<dyn Error>::from)
            }
        }
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.0 {
            PubKey::Rsa(pk) => pk
                .encrypt(&mut OsRng, padding_scheme_encrypt(), data)
                .map_err(|e| Box::new(e) as Box<dyn Error>),
            PubKey::Ed25519 { k_pub, .. } => {
                let mut csprng = rand::rngs::StdRng::from_entropy();
                // TODO don't use unwrap here
                let (key_encapped, ciphertext) = single_shot_seal::<Aead, Kdf, KemUsed, _>(
                    &OpModeS::Base,
                    k_pub,
                    INFO_STR,
                    data,
                    &[],
                    &mut csprng,
                )
                .unwrap();
                let key_encapped = key_encapped.to_bytes();
                let key_encapped: &[u8] = key_encapped.as_slice();
                bincode::serialize(&(key_encapped, ciphertext)).map_err(Box::<dyn Error>::from)
            }
        }
    }
}

const INFO_STR: &[u8] = b"NodeManager message encryption";

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
