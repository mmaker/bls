extern crate bls12_381;
extern crate rand;
extern crate rand_core;
extern crate digest;
extern crate ff;
extern crate sha2;

use ff::Field;
use bls12_381::{Scalar, G1Projective, G2Projective, G2Affine};

use rand::Rng;
use rand_core::RngCore;

use sha2::Sha512;

pub struct Signature {
    s: G1Projective,
}

pub struct SecretKey {
    x: Scalar,
}

impl SecretKey {
    pub fn generate<R: RngCore>(csprng: R) -> Self {
        SecretKey {
            x: Scalar::random(csprng),
        }
    }

    pub fn blind_sign(&self, blinded_message: &G1Projective) -> Signature {
        Signature { s: blinded_message * self.x }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let h = G1Projective::hash_from_bytes::<Sha512>(message);
        Signature { s: h * self.x }
    }
}

pub struct PublicKey {
    p_pub: G2Projective,
}

impl PublicKey {
    pub fn from_secret(secret: &SecretKey) -> Self {
        // TODO Decide on projective vs affine
        PublicKey {
            p_pub: G2Projective::generator() * secret.x,
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let h = G1Projective::hash_from_bytes::<Sha512>(message); // XXX. add domain sep
        let lhs = bls12_381::pairing(&signature.s.into(), &G2Affine::generator());
        let rhs = bls12_381::pairing(&h.into(), &self.p_pub.into());
        lhs == rhs
    }
}

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = SecretKey::generate(csprng);
        let public = PublicKey::from_secret(&secret);
        Keypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.public.verify(message, signature)
    }
}


pub struct BlsBlind {
    r: Scalar,
    pub(crate) blinded_message: G1Projective
}

impl BlsBlind {
    pub fn new<R: RngCore>(csrng: R, message: &[u8], _public: &PublicKey) -> Self {
        let h = G1Projective::hash_from_bytes::<Sha512>(message); // XXX: add public key
        let r = Scalar::random(csrng);
        let r_inv = r.invert().unwrap(); // do something here, buy a lottery ticket
        Self {r,
            blinded_message: h * r_inv }
    }

    pub fn unblind(self, signature: Signature) -> Signature {
        Signature { s: signature.s * self.r }
    }

    pub fn to_string(&self) -> String {
        self.blinded_message.to_string()
    }
}

#[test]
fn sign_verify() {
    let mut rng = rand::thread_rng();

    for i in 0..500 {
        let keypair = Keypair::generate(&mut rng);
        let message = format!("Message {}", i);
        let sig = keypair.sign(&message.as_bytes());
        assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
    }
}

#[test]
fn test_blind_sign_verify() {
    let mut rng = rand::thread_rng();

    for i in 0 ..500 {
        let keypair = Keypair::generate(&mut rng);
        let message = format!("Blinded message {}", i);
        let user = BlsBlind::new(&mut rng, message.as_bytes(), &keypair.public);
        let blinded_signature = keypair.secret.blind_sign(&user.blinded_message);
        let signature = user.unblind(blinded_signature);
        assert!(keypair.verify(message.as_bytes(), &signature))
    }
}