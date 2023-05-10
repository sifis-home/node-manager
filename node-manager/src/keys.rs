use anyhow::Result;
use base64ct::{Base64, Encoding};
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

pub fn priv_key_pem_to_der(key_pem: &str) -> Vec<u8> {
    let key = PrivateKey::from_pkcs8_pem(key_pem).unwrap();
    let key_der = key.to_pkcs8_der().unwrap();

    let key_der_slice: &[u8] = key_der.as_ref();
    key_der_slice.to_vec()
}

impl PrivateKey {
    pub fn generate_ed25519_rng<Rng: rand_07::Rng + rand_07::CryptoRng>(rng: &mut Rng) -> Self {
        let ed_key_pair = EdKeypair::generate(rng);
        let der = ed_key_pair.to_bytes();
        Self::from_pkcs8_der(&der).unwrap()
    }
    pub fn generate_ed25519() -> Self {
        let mut csprng = rand_07::rngs::OsRng;
        Self::generate_ed25519_rng(&mut csprng)
    }
    pub fn is_rsa(&self) -> bool {
        matches!(self.0, PrivKey::Rsa { .. })
    }
    pub fn is_ed25519(&self) -> bool {
        matches!(self.0, PrivKey::Ed25519 { .. })
    }
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        match RsaPrivateKey::from_pkcs8_der(der) {
            Ok(pk) => Ok(PrivateKey(PrivKey::Rsa(pk))),
            Err(_) => {
                // Note: This isn't really in der format, nor pkcs8.
                // TODO: find a better name for this function and the pem equivalent.
                let sign_key = EdKeypair::from_bytes(der)?;
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
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let pk = match RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(pk) => PrivKey::Rsa(pk),
            Err(_) => {
                let der = Base64::decode_vec(pem)?;
                return Self::from_pkcs8_der(&der);
            }
        };
        Ok(PrivateKey(pk))
    }
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        match &self.0 {
            PrivKey::Rsa(pk) => {
                let key_der = pk.to_pkcs8_der()?;

                let key_der_slice: &[u8] = key_der.as_ref();
                Ok(key_der_slice.to_vec())
            }
            PrivKey::Ed25519 { der, .. } => Ok(der.to_vec()),
        }
    }
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        match &self.0 {
            PrivKey::Rsa(pk) => Ok(pk.to_pkcs8_pem(Default::default())?.as_str().to_owned()),
            PrivKey::Ed25519 { .. } => Ok(Base64::encode_string(&self.to_pkcs8_der()?)),
        }
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            PrivKey::Rsa(pk) => Ok(pk.decrypt(padding_scheme_encrypt(), data)?),
            PrivKey::Ed25519 { k_priv, .. } => {
                // TODO get rid of unwraps
                let (key_encapped_data, ciphertext_data): (Vec<u8>, Vec<u8>) =
                    bincode::deserialize(data)?;
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
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        Ok(match &self.0 {
            PrivKey::Rsa(pk) => pk.sign(padding_scheme_sign(), digest)?,
            PrivKey::Ed25519 { sign_key, .. } => sign_key.sign(digest).to_bytes().to_vec(),
        })
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
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<()>;
}

impl VerifySignature for PrivateKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        match &self.0 {
            PrivKey::Rsa(pk) => pk.verify(padding_scheme_sign(), digest, signature)?,
            PrivKey::Ed25519 { sign_key, .. } => {
                let signature = EdSignature::from_bytes(signature)?;
                sign_key.verify(digest, &signature)?
            }
        }
        Ok(())
    }
}

impl VerifySignature for PublicKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
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
    pub fn from_public_key_der(public_key_der: &[u8]) -> Result<Self> {
        let pk = match RsaPublicKey::from_public_key_der(public_key_der) {
            Ok(pk) => PubKey::Rsa(pk),
            Err(_) => {
                let (k_pub_bytes, sign_pub_bytes): (Vec<u8>, [u8; 32]) =
                    bincode::deserialize(public_key_der)?;
                // TODO get rid of unwrap
                let k_pub = X25519Public::from_bytes(&k_pub_bytes).unwrap();
                let sign_pub = EdPublicKey::from_bytes(&sign_pub_bytes)?;
                PubKey::Ed25519 {
                    der: public_key_der.to_vec(),
                    k_pub,
                    sign_pub,
                }
            }
        };
        Ok(PublicKey(pk))
    }
    pub fn to_public_key_der(&self) -> Result<Vec<u8>> {
        match &self.0 {
            PubKey::Rsa(pk) => {
                let key_pub = pk.to_public_key_der()?;
                let key_der_slice: &[u8] = key_pub.as_ref();
                Ok(key_der_slice.to_vec())
            }
            PubKey::Ed25519 { der, .. } => Ok(der.clone()),
        }
    }
    pub fn from_public_key_pem(pem: &str) -> Result<Self> {
        let _err = match RsaPublicKey::from_public_key_pem(pem) {
            Ok(pk) => return Ok(PublicKey(PubKey::Rsa(pk))),
            Err(err) => err,
        };
        let der = Base64::decode_vec(pem)?;
        Self::from_public_key_der(&der)
    }
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        match &self.0 {
            PubKey::Rsa(pk) => Ok(pk
                .to_public_key_pem(Default::default())?
                .as_str()
                .to_owned()),
            PubKey::Ed25519 { .. } => Ok(Base64::encode_string(&self.to_public_key_der()?)),
        }
    }
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        match &self.0 {
            PubKey::Rsa(pk) => pk.verify(padding_scheme_sign(), digest, signature)?,
            PubKey::Ed25519 { sign_pub, .. } => {
                let signature = EdSignature::from_bytes(signature)?;
                sign_pub.verify(digest, &signature)?
            }
        }
        Ok(())
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(match &self.0 {
            PubKey::Rsa(pk) => pk.encrypt(&mut OsRng, padding_scheme_encrypt(), data)?,
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
                bincode::serialize(&(key_encapped, ciphertext))?
            }
        })
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

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    fn test_key(key: PrivateKey) {
        // Test serialization round trips of the private key
        {
            let key_pem = key.to_pkcs8_pem().unwrap();
            let key_pem_again = PrivateKey::from_pkcs8_pem(&key_pem)
                .unwrap()
                .to_pkcs8_pem()
                .unwrap();
            assert_eq!(key_pem, key_pem_again);

            let key_der = key.to_pkcs8_der().unwrap();
            let key_der_again = PrivateKey::from_pkcs8_der(&key_der)
                .unwrap()
                .to_pkcs8_der()
                .unwrap();
            assert_eq!(key_der, key_der_again);
        }
        let key_pub = key.to_public_key();

        // Test serialization round trips of the public key
        {
            let key_pub_pem = key_pub.to_pkcs8_pem().unwrap();
            let key_pub_pem_again = PublicKey::from_public_key_pem(&key_pub_pem)
                .unwrap()
                .to_pkcs8_pem()
                .unwrap();
            assert_eq!(key_pub_pem, key_pub_pem_again);

            let key_pub_der = key_pub.to_public_key_der().unwrap();
            let key_pub_der_again = PublicKey::from_public_key_der(&key_pub_der)
                .unwrap()
                .to_public_key_der()
                .unwrap();
            assert_eq!(key_pub_der, key_pub_der_again);
        }

        let hi = b"hello, world!";

        // Test encryption round trip
        {
            let hi_encrypted = key.to_public_key().encrypt(hi).unwrap();
            let hi_decrypted = key.decrypt(&hi_encrypted).unwrap();
            assert_eq!(hi, hi_decrypted.as_slice());
        }
        {
            // RSA gives MessageTooLong for 6 and above, while the ed25519 method
            // allows any length.
            let num = if key.is_rsa() {
                5
            } else if key.is_ed25519() {
                640
            } else {
                unreachable!()
            };
            let hi_big = (0..num)
                .map(|ctr: u32| Sha256::digest(ctr.to_be_bytes()))
                .fold(Vec::new(), |mut v, sl| {
                    v.extend_from_slice(&sl);
                    v
                });
            let hi_encrypted = key.to_public_key().encrypt(&hi_big).unwrap();
            let hi_decrypted = key.decrypt(&hi_encrypted).unwrap();
            assert_eq!(hi_big, hi_decrypted.as_slice());
        }

        // Test signature round trip
        {
            let hi_hash = Sha256::digest(hi);
            let mut hi_signature = key.sign(&hi_hash).unwrap();
            key_pub.verify(&hi_hash, &hi_signature).unwrap();

            let mut hi_hash_modified = hi_hash;
            hi_hash_modified
                .iter_mut()
                .for_each(|v| *v = v.wrapping_add(13));

            let _ = key_pub
                .verify(&hi_hash_modified, &hi_signature)
                .unwrap_err();

            hi_signature
                .iter_mut()
                .for_each(|v| *v = v.wrapping_add(13));
            let _ = key_pub.verify(hi, &hi_signature).unwrap_err();
        }
    }

    #[test]
    fn test_rsa() {
        let rsa_key_str = include_str!("../tests/keys/test_key1.pem");
        let rsa_key = PrivateKey::from_pkcs8_pem(rsa_key_str).unwrap();
        test_key(rsa_key);
    }

    #[test]
    fn test_ed25519() {
        let ed25519_key = PrivateKey::generate_ed25519();
        test_key(ed25519_key);
    }
}
