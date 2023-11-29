// Practical Threshold Signatures, Victor Shoup, 2000
// NOTE: what is the difference between # and #!?

#![allow(unused_imports)]
// use errors::{Error, Result};
#[cfg(not(test))]
use log::info;
use sha2::{Digest, Sha256};

use num_bigint::*;
use std::path::PathBuf;
#[cfg(test)]
use std::{println as info, println as warn};
use thiserror::Error;
// use std::error::Error
// use num_modular::*;
use crypto_bigint::*;
use crypto_primes::*;
// use num_prime::nt_funcs::*;
use num_bigint::algorithms::extended_gcd;
use num_integer::Integer;
use num_traits::{CheckedSub, One, Pow, Zero};
use rand::prelude::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};
use rand_core::CryptoRngCore;
use rsa::{
    hazmat::{
        pkcs1v15_generate_prefix, pkcs1v15_sign_pad, pkcs1v15_sign_unpad, uint_to_be_pad,
        uint_to_zeroizing_be_pad,
    },
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};

use serde::{Deserialize, Serialize};
use serde_json::{Result as SerdeResult, Value};
use std::any::type_name;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Add, Div, Mul, MulAssign, Neg, Shr};
use std::str::FromStr;

// FIXME reexport the RSA customized module?

// FIXME Check that the geneated values/shares etc. are not ones or zeroes for example?
// TODO: add PSS padding --- needs message passing
// TODO: fix the k-out-of-l signatures that differ from the regular one when k < l
// TODO: prefer BigUint over BigInt

// Deal function to generate from
// inputs k-out-of-n
// return vec of PrivateShares and vec of VerificationKey
// SecretPackage and PublicPackage

/// Credits to: https://frost.zfnd.org/index.html for the API design
pub fn generate_with_dealer(
    max_signers: u16,
    min_signers: u16,
    // TODO add identifiers and rng parameters?
    key_bit_length: usize,
) -> Result<(Vec<SecretPackage>, Vec<PublicPackage>), KeyGenError> {
    let private_key = key_gen(key_bit_length, max_signers as usize, min_signers as usize)?;
    let shares = generate_secret_shares(&private_key, max_signers as usize, min_signers as usize);
    // pub fn generate_verification(
    let secret_pkgs = shares
        .iter()
        .enumerate()
        .map(|(i, share)| SecretPackage {
            uid: i,
            gid: None,
            share: share.clone(),
        })
        .collect();

    let public_key = RsaPublicKey::from(&private_key);
    let (v, vkeys) = generate_verification(&RSAThresholdPublicKey::from(&private_key), shares);
    let public_pkg = PublicPackage {
        v: v,
        verification_keys: vkeys,
        public_key: public_key,
        group_size: max_signers as usize,
    };

    Ok((secret_pkgs, vec![public_pkg; max_signers as usize]))
}

// PublicPackage: HashMap of PartialSignature VerificationKeys, VerificationKey
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicPackage {
    pub v: BigInt,
    pub verification_keys: Vec<RsaVerificationKey>,
    pub public_key: RsaPublicKey,
    pub group_size: usize,
}
// TODO add unique IDs and also keep the unique ideas around
// TODO rename to SecretKeyPackage?
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretPackage {
    // TODO use bigger IDs? globally unique ids?
    pub uid: usize,
    pub gid: Option<usize>,
    // TODO This is not nice, but needed for meesign-crypto integration
    pub share: RsaSecretShare,
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum SigningError {
    #[error("General signing error")]
    SigningError,
    #[error("Message cannot be signed")]
    MessageCannotBeSigned,
}

impl SecretPackage {
    // TODO save v, vi to the SecretPackage to make this more ergonomic?
    pub fn sign(
        &self,
        message: &[u8],
        max_signers: u16,
        v: BigInt,
        vi: &RsaVerificationKey,
        padding_scheme: PaddingScheme,
    ) -> Result<PartialMessageSignature, SigningError> {
        // NOTE: is this how to handle errors in Rust?
        // let message = match String::from_utf8(message) {
        //     Ok(msg) => msg,
        //     Err(_) => return Err(SigningError::MessageCannotBeSigned),
        // };
        let delta = factorial(max_signers as usize);
        let partial_signature = sign_with_share(message, delta, &self.share, &v, vi, padding_scheme);
        Ok(partial_signature)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSAThresholdPrivateKey {
    n: BigInt,
    p: BigInt,
    q: BigInt,
    d: BigInt,
    m: BigInt,
    e: BigInt,
    // TODO follow RustCrypto/RSA convention of functions instead of fields
    pub bytes_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSAThresholdPublicKey {
    n: BigInt,
    e: BigInt,
    // TODO follow RustCrypto/RSA convention of functions instead of fields
    bytes_size: usize,
}

pub struct Group {
    size: usize,
}
pub struct GroupParams {}

// FIXME introduce lifetimes?
// TODO Should merge RsaSecretShare and RsaVerificationKey?
//      It could be a problem for verifying the proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RsaSecretShare {
    // TODO the id is both on SecretPackage, RsaSecretShare
    pub id: usize,
    pub n: BigUint,
    pub e: BigUint,
    pub key_bytes_size: usize,
    pub share: BigInt,
}

// FIXME introduce lifetimes?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RsaVerificationKey {
    id: usize,
    key: BigInt,
}

// Should PartialMessageSignature be split to the share and the verification proof?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialMessageSignature {
    pub id: usize,
    pub xi: BigInt,
    pub z: BigInt,
    pub c: BigInt,
    // key: RSAThresholdPublicKey,
}

// TODO move the errors to another file?
#[derive(Error, Debug)]
pub enum KeyGenError {
    // #[error("The provided bit_length '{found:?}' was greater than the expected '{expected:?}'.")]
    // UnexpectedBitLength { expected: usize, found: usize },
    #[error("Too Big")]
    TooBig,
    #[error("Too Small")]
    TooSmall,
    #[error("No Inverse")]
    NoInverse,
    #[error("The group is too big")]
    GroupTooBig,
    #[error("Bit length does not match")]
    BitLength,
}

#[derive(Error, Debug)]
pub enum PolynomialError {
    #[error("No coefficients/polynomial provided")]
    NoCoefficients,
}

impl From<&RSAThresholdPrivateKey> for RSAThresholdPublicKey {
    fn from(private_key: &RSAThresholdPrivateKey) -> Self {
        RSAThresholdPublicKey {
            n: private_key.n.clone(),
            e: private_key.e.clone(),
            bytes_size: private_key.bytes_size,
        }
    }
}

impl From<RSAThresholdPrivateKey> for RSAThresholdPublicKey {
    fn from(private_key: RSAThresholdPrivateKey) -> Self {
        (&private_key).into()
    }
}

// NOTE: Conversion to RsaPrivateKey is here in order to be able to build the RsaPublicKey.
// However, Having RsaPrivateKey from RSAThresholdPrivateKey sounds a bit dangerous. The threshold
// variant should not be available for the non-treshold one as that could lead to a misuse.
impl From<RSAThresholdPrivateKey> for RsaPrivateKey {
    fn from(private_key: RSAThresholdPrivateKey) -> Self {
        (&private_key).into()
    }
}

impl From<&RSAThresholdPrivateKey> for RsaPrivateKey {
    fn from(private_key: &RSAThresholdPrivateKey) -> Self {
        let n = (private_key.p.clone() * private_key.q.clone())
            .to_biguint()
            .expect("");

        RsaPrivateKey::from_components(
            n,
            private_key.e.to_biguint().expect(""),
            private_key.d.to_biguint().expect(""),
            vec![
                private_key.p.clone().to_biguint().expect(""),
                private_key.q.clone().to_biguint().expect(""),
            ],
        )
        .unwrap()
    }
}

impl From<RSAThresholdPrivateKey> for RsaPublicKey {
    fn from(private_key: RSAThresholdPrivateKey) -> Self {
        (&private_key).into()
    }
}

impl From<&RSAThresholdPrivateKey> for RsaPublicKey {
    fn from(private_key: &RSAThresholdPrivateKey) -> Self {
        let rsa_key: RsaPrivateKey = private_key.into();
        RsaPublicKey::from(&rsa_key)
    }
}

fn print_type_of<T>(_: &T) {
    eprintln!("{:?}", std::any::type_name::<T>())
}

/// `n_parties` equals the `l` parameter from the paper
pub fn key_gen(
    bit_length: usize,
    l: usize,
    k: usize,
    // t: usize,
) -> Result<RSAThresholdPrivateKey, KeyGenError> {
    // FIXME add bounds on l, k and t
    let (p, q) = match generate_p_and_q(bit_length) {
        Ok((p, q)) => (p, q),
        Err(e) => return Err(e),
    };
    let e: BigInt = BigInt::from(0x10001); // 65537

    // FIXME: compare against e directly
    if BigInt::from(l) > e {
        return Err(KeyGenError::GroupTooBig);
    };

    let n = p.clone().mul(&q);
    // FIXME code without unwraps
    let p_prime = &p.checked_sub(&BigInt::one()).unwrap().shr(1);
    let q_prime = &q.checked_sub(&BigInt::one()).unwrap().shr(1);

    let m = p_prime.mul(q_prime);
    let dd = match e.clone().mod_inverse(&m) {
        Some(value) => value,
        None => return Err(KeyGenError::NoInverse),
    };
    assert!(dd.cmp(&BigInt::zero()) == Ordering::Greater);

    // TODO d is expected to be an Integer, not exactly modulo, it just needs to
    // satisfy the equation de = 1 mod m
    // let d: BigInt = match dd.to_biguint() {
    //     Some(value) => value,
    //     None => return Err(KeyGenError::NoInverse),
    // };
    assert_eq!(
        dd.clone().mul(e.clone()).mod_floor(&m).cmp(&BigInt::one()),
        Ordering::Equal
    );

    Ok(RSAThresholdPrivateKey {
        n: n.clone(),
        p: p,
        q: q,
        d: dd,
        m: m,
        e: e,
        bytes_size: (n.bits() + 7) / 8,
    })
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum PaddingScheme {
    NONE,
    _PSS,
    PKCS1v15,
}

fn digest_msg(
    msg: &[u8],
    scheme: PaddingScheme,
    // _rng: &mut R,
    // key: &RsaPublicKey,
    // share: &RsaSecretShare,
    n: &BigUint,
    key_bytes_size: usize,
) -> BigInt {
    // eprintln!("no prefix len:{} data:{:?}", msg.len(), msg);
    // BigInt::from_bytes_be(
    //     Sign::Plus,
    //     msg,
    // )
    // let msg_digest = Sha256::digest(msg);
    // FIXME is this correct conversion?
    // TODO Add support for various hash functions
    // let hashed =
    //     BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&n.to_bigint().expect(""));
    // TODO there are four variants for PSS
    // let inner = pkcs1v15_sign_pad(&[], &msg, key_bytes_size).unwrap();
    // assert_eq!((BigInt::from_bytes_be(Sign::Plus, &inner).to_bytes_be().1), inner);
    match scheme {
        PaddingScheme::NONE => todo!(), //hashed,
        PaddingScheme::_PSS => unimplemented!(),
        PaddingScheme::PKCS1v15 => {
            // let prefix = pkcs1v15_generate_prefix::<Sha256>();
            // eprintln!("hashed: {:?}", hashed.to_bytes_be().1);
            // eprintln!("key_bytes: {}", key_bytes_size);
            BigInt::from_bytes_be(
                Sign::Plus,
                // &pkcs1v15_sign_pad(&[], &hashed.to_bytes_be().1, key_bytes_size).unwrap(),
                &pkcs1v15_sign_pad(&[], &msg, key_bytes_size).unwrap(),
            )
        }
    }
}

fn evaluate_polynomial_mod(
    value: BigInt,
    coeffs: &Vec<BigInt>,
    modulus: &BigInt,
) -> Result<BigInt, PolynomialError> {
    let mut prev: BigInt = match coeffs.last() {
        Some(last) => last.clone(),
        None => return Err(PolynomialError::NoCoefficients),
    };

    for next in coeffs.iter().rev().skip(1) {
        // TODO what multiplication and addition is used for * and +, should we call functions
        // mul and add instead?
        prev = prev.mul(&value).add(next); //#.mod_floor(modulus);
    }
    let rem = prev.mod_floor(modulus);
    Ok(rem)
}

pub fn generate_secret_shares(
    key: &RSAThresholdPrivateKey,
    l: usize,
    k: usize,
) -> Vec<RsaSecretShare> {
    // generate random coefficients
    let mut rng = ChaCha20Rng::from_entropy();
    let mut a_coeffs: Vec<BigInt> = (0..=(k - 1))
        .map(|_| rng.gen_bigint_range(&BigInt::zero(), &key.m))
        .collect();
    // fix a_0 to the private exponent
    a_coeffs[0] = key.d.clone();
    // calculate the individual shares
    let shares: Vec<RsaSecretShare> = (1..=l)
        .map(|i| RsaSecretShare {
            id: i,
            n: key.n.to_biguint().expect(""),
            e: key.e.to_biguint().expect(""),
            key_bytes_size: key.bytes_size,
            share: evaluate_polynomial_mod(i.into(), &a_coeffs, &key.m).unwrap(),
        })
        .collect();
    shares
}

pub fn generate_verification(
    key: &RSAThresholdPublicKey,
    shares: Vec<RsaSecretShare>,
) -> (BigInt, Vec<RsaVerificationKey>) {
    let mut rng = ChaCha20Rng::from_entropy();
    let two = BigInt::from(2u8);
    // FIXME: v is supposed to be from the subgroup of squares, is it?
    let v = rng.gen_bigint_range(&two, &key.n);
    assert_eq!(v.gcd(&key.n).cmp(&BigInt::one()), Ordering::Equal);
    let verification_keys = shares
        .iter()
        .map(|s| RsaVerificationKey {
            id: s.id,
            key: v.modpow(&s.share, &key.n),
        })
        .collect();
    (v, verification_keys)
}

/// _i = x^{2 \delta s_i} \in Q_n
pub fn sign_with_share(
    msg: &[u8],
    delta: usize,
    share: &RsaSecretShare,
    // key: &RsaPublicKey,
    v: &BigInt,
    vi: &RsaVerificationKey,
    scheme: PaddingScheme,
) -> PartialMessageSignature {
    // FIXME add some kind of blinding?
    let x = digest_msg(
        msg,
        scheme,
        // &mut ChaCha20Rng::from_entropy(),
        &share.n,
        share.key_bytes_size,
    );
    // FIXME is this correct conversion?
    // let x = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&key.n);
    // eprintln!("x = {:?}", x);
    // let xi = BigInt::from_bytes_be(msg_digest);
    let mut exponent = BigInt::from(2u8);
    exponent.mul_assign(BigInt::from(delta));
    exponent.mul_assign(share.share.clone());
    // calculate the signature share
    let xi = x.modpow(&exponent, &share.n.to_bigint().expect(""));
    // x_tilde
    let x_tilde = x.pow(4 * delta);
    let xi_squared: BigInt = xi.modpow(&BigInt::from(2u8), &share.n.to_bigint().expect(""));

    // calculate the proof of correctness
    let n_bits = share.n.bits();
    let hash_length = 256;
    let two = BigInt::from(2u8);

    let bound = two
        .pow(n_bits + 2 * hash_length)
        .checked_sub(&BigInt::one())
        .expect("");
    let mut rng = ChaCha20Rng::from_entropy();
    let r = rng.gen_bigint_range(&BigInt::zero(), &bound);
    // eprintln!("pz_r = {}", r);
    // FIXME the next exponentiation should not be modulo
    let v_prime = v.modpow(&r, &share.n.to_bigint().expect(""));
    let x_prime = x_tilde.modpow(&r, &share.n.to_bigint().expect(""));
    // c =  hash(v, x_tilde, vi, xi^2, v^r, x^r)
    // FIXME omitting the sign could be of an issue
    let mut commit = v.to_bytes_be().1;
    commit.extend(x_tilde.to_bytes_be().1);
    // FIXME don't just use the key but provide some way of hashing?
    commit.extend(vi.key.to_bytes_be().1);
    commit.extend(xi_squared.to_bytes_be().1);
    commit.extend(v_prime.to_bytes_be().1);
    commit.extend(x_prime.to_bytes_be().1);

    let c = BigInt::from_bytes_be(Sign::Plus, &Sha256::digest(commit));
    let z = (share.share.clone().mul(c.clone())).add(r.clone());

    PartialMessageSignature {
        id: share.id,
        xi: xi,
        z: z,
        c: c,
    }
}

fn lambda(delta: usize, i: usize, j: usize, l: usize, subset: Vec<usize>) -> BigInt {
    // FIXME usize might overflow? what about using BigInt
    let subset: Vec<usize> = subset.into_iter().filter(|&s| s != j).collect();
    // eprintln!("filtered subset: {:?}, j: {}", subset, j);

    let numerator: i64 = subset
        .iter()
        .map(|&j_prime| i as i64 - j_prime as i64)
        .product();
    let denominator: i64 = subset
        .iter()
        .map(|&j_prime| j as i64 - j_prime as i64)
        .product();
    // eprintln!("numerator / denominator: {:?}", numerator / denominator);

    // TODO use mul and div
    //
    let value = BigInt::from((delta as i64 * numerator) / denominator);
    // eprintln!("lambda: {}", value);
    value
}

// TODO inline?
pub fn factorial(value: usize) -> usize {
    let mut acc = 1;
    for i in 1..=value {
        acc *= i
    }
    acc
}

// Based on this API the `bit_length` should not be divided, but instead
// the division shouldbe handled by the key gen caller
fn generate_p_and_q(bit_length: usize) -> Result<(BigInt, BigInt), KeyGenError> {
    let min_bit_length = 3;
    let max_bit_length = 16384;
    let half_bit_length = bit_length / 2;

    if half_bit_length < min_bit_length {
        // Trying to prevent the following panic!
        // https://docs.rs/crypto-primes/latest/src/crypto_primes/presets.rs.html#85
        return Err(KeyGenError::TooSmall);
    }
    if half_bit_length > max_bit_length {
        return Err(KeyGenError::TooBig);
    }

    // Use the largest available types for the initial primes generates
    // Generate two distinct safe probably primes
    info!("Generating p prime..");
    // FIXME From experimenting it seems that larger values mean much slower generation times
    // So ideally we would pick the U type based on the half_bit_length
    // E.g. U2048 vs U16384
    let crypto_p: U2048 = generate_safe_prime(Some(half_bit_length));
    info!("Generating q prime..");
    let mut crypto_q: U2048 = generate_safe_prime(Some(half_bit_length));
    while crypto_p == crypto_q {
        info!("p == q, recalculating q");
        crypto_q = generate_safe_prime(Some(half_bit_length));
    }

    // FIXME: I am a bit unsure about the converting between crypto-bigint and num-bigint
    let p = BigInt::from_bytes_be(Sign::Plus, &crypto_p.to_be_bytes());
    let q = BigInt::from_bytes_be(Sign::Plus, &crypto_q.to_be_bytes());

    if p.bits() != half_bit_length || q.bits() != half_bit_length {
        return Err(KeyGenError::BitLength);
    }

    Ok((p, q))
}

// FIXME go through expects and fix them!
// TODO pass the msg digest
pub fn verify_proof(
    msg: &[u8],
    v: &BigInt,
    delta: usize,
    // xi: BigInt,
    vi: &RsaVerificationKey,
    // c: BigInt,
    // z: BigInt,
    pms: &PartialMessageSignature,
    n: &BigUint,
    key_bytes_size: usize,
    // key: &RSAThresholdPublicKey,
    scheme: PaddingScheme,
) -> bool {
    let x = digest_msg(
        msg,
        scheme,
        // &mut ChaCha20Rng::from_entropy(),
        n,
        key_bytes_size,
    );
    let x_tilde: BigInt = x.pow(4 * delta);

    let xi_squared: BigInt = pms.xi.modpow(&BigInt::from(2u8), &n.to_bigint().expect(""));

    let v2z = v.modpow(&pms.z, &n.to_bigint().expect(""));
    // FIXME refactor param5 and param6 calculations
    // FIXME use checked_mul instead
    let param5 = v.modpow(&pms.z, &n.to_bigint().expect(""));
    let tmp1 = vi
        .key
        .modpow(&pms.c, &n.to_bigint().expect(""))
        .mod_inverse(&n.to_bigint().expect(""))
        .expect("");
    let param5 = (param5 * tmp1).mod_floor(&n.to_bigint().expect(""));

    let param6 = x_tilde.modpow(&pms.z, &n.to_bigint().expect(""));
    let tmp2 = pms
        .xi
        .modpow(
            &(pms.c.clone().mul(BigInt::from(2u8))),
            &n.to_bigint().expect(""),
        )
        .mod_inverse(&n.to_bigint().expect(""))
        .expect("");
    let param6 = (param6 * tmp2).mod_floor(&n.to_bigint().expect(""));

    let mut commit = v.to_bytes_be().1;
    commit.extend(x_tilde.to_bytes_be().1);
    commit.extend(vi.key.to_bytes_be().1);
    commit.extend(xi_squared.to_bytes_be().1);
    commit.extend(param5.to_bytes_be().1);
    commit.extend(param6.to_bytes_be().1);
    pms.c
        .cmp(&BigInt::from_bytes_be(Sign::Plus, &Sha256::digest(commit)))
        == Ordering::Equal
}

// FIXME: allow specifying the path
pub fn save_key(key: &RSAThresholdPrivateKey) -> std::io::Result<()> {
    let mut keyfile = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    keyfile.push("resources/test/private_key.json");
    eprintln!("keyfile path: {}", keyfile.display());
    let mut handle = File::create(keyfile)?;
    handle.write_all(serde_json::to_string(key).unwrap().as_bytes())?;
    Ok(())
}

pub fn load_key() -> std::io::Result<RSAThresholdPrivateKey> {
    let mut keyfile = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    keyfile.push("resources/test/private_key.json");
    let mut handle = File::open(keyfile)?;

    let mut data = String::new();
    handle.read_to_string(&mut data)?;
    let key: RSAThresholdPrivateKey = serde_json::from_str(&data)?;
    Ok(key)
}

// Who can combine the shares? Should this be a function of SecretPackage?
/// Combine signature shares.
pub fn combine_shares(
    msg: &[u8],
    // TODO do not pass both delta and l
    delta: usize,
    sign_shares: Vec<PartialMessageSignature>,
    // key: &RSAThresholdPublicKey,
    key_share: &RsaSecretShare,
    l: usize,
    scheme: PaddingScheme,
) -> BigInt {
    // FIXME verify the shares prior to combining them
    let x = digest_msg(
        msg,
        scheme,
        // &mut ChaCha20Rng::from_entropy(),
        &key_share.n.to_biguint().expect(""),
        key_share.key_bytes_size,
    );
    eprintln!("combine shares x len: \n{:?}", x.to_bytes_be().1.len());
    // eprintln!("pz_x = {}", x);

    let mut w = BigInt::one();
    // FIXME the set is supposed to be dynamic
    let subset = sign_shares.iter().map(|s| s.id).collect::<Vec<usize>>();
    // eprintln!(
    //     "The subset used for combining the signatures is: {:?}",
    //     subset
    // );
    for (_, share) in sign_shares.iter().enumerate() {
        let lamb = lambda(delta, 0, share.id, l, subset.clone());
        // eprintln!("lambda is: {lamb}");

        // FIXME exponent might be negative - what then?
        let exponent = BigInt::from(2u8).mul(lamb);
        // assert!(exponent.cmp
        // eprintln!("Combining shares: exponent: {}", exponent);

        w.mul_assign(match exponent.cmp(&BigInt::zero()) {
            Ordering::Less => share
                .xi
                .modpow(&exponent.neg(), &key_share.n.to_bigint().expect(""))
                .mod_inverse(&key_share.n)
                .expect(""),
            Ordering::Equal => BigInt::one(),
            Ordering::Greater => share
                .xi
                .modpow(&exponent, &key_share.n.to_bigint().expect("")),
        });
        // w.mul_assign(share.modpow(&exponent, &key_share.n));
    }
    w = w.mod_floor(&key_share.n.to_bigint().expect(""));
    let e_prime = BigInt::from(4u8).mul(delta.pow(2));
    let (g, Some(a), Some(b)) = extended_gcd(
        std::borrow::Cow::Borrowed(&e_prime.to_biguint().expect("")),
        std::borrow::Cow::Borrowed(&key_share.e.to_biguint().expect("")),
        true,
    ) else {
        todo!()
    };
    // eprintln!("a: {}", a);
    // eprintln!("e_prime: {}", e_prime);
    // eprintln!("b: {}", b);
    // eprintln!("pz_w = {}", w);
    // eprintln!("x: {}", x.to_string());
    // assert_eq!(
    //     e_prime
    //         .clone()
    //         .mul(a.clone())
    //         .add(&key_share.e.to_bigint().expect("").clone().mul(b.clone()))
    //         .cmp(&BigInt::one()),
    //     Ordering::Equal,
    //     "The Bezout's equality e'a + eb != 1 does not hold.",
    // );
    // assert_eq!(g.cmp(&BigInt::one()), Ordering::Equal);
    // let we = w.modpow(
    //     &key_share.e.to_bigint().expect(""),
    //     &key_share.n.to_bigint().expect(""),
    // );
    // let xe_prime = x.modpow(&BigInt::from(e_prime), &key_share.n.to_bigint().expect(""));
    // assert_eq!(
    //     we.cmp(&BigInt::zero()),
    //     Ordering::Greater,
    //     "w^e is not positive"
    // );
    // assert_eq!(
    //     xe_prime.cmp(&BigInt::zero()),
    //     Ordering::Greater,
    //     "x^e' is not positive"
    // );

    // // FIXME For 2 out of 3 this assertion passes for signers with IDs 0 and 1, but fails for signers
    // // with IDs 0 and 2
    // assert_eq!(
    //     we.cmp(&xe_prime),
    //     // .cmp(&x.modpow(&BigInt::from(e_prime), &key_share.n)),
    //     Ordering::Equal,
    //     "w^e != x^e'"
    // );

    // NOTE raise to the negative power is not possible at the moment
    let first = match a.cmp(&BigInt::zero()) {
        Ordering::Less => w
            .modpow(&a.neg(), &key_share.n.to_bigint().expect(""))
            .mod_inverse(&key_share.n.to_bigint().expect(""))
            .expect(""),
        Ordering::Equal => BigInt::one(),
        Ordering::Greater => w.modpow(&a, &key_share.n.to_bigint().expect("")),
    };
    let second = match b.cmp(&BigInt::zero()) {
        Ordering::Less => x
            .modpow(&b.neg(), &key_share.n.to_bigint().expect(""))
            .mod_inverse(&key_share.n)
            .expect(""),
        Ordering::Equal => BigInt::one(),
        Ordering::Greater => x.modpow(&b, &key_share.n.to_bigint().expect("")),
    };
    eprintln!("shares combined");

    BigInt::from_bytes_be(
        Sign::Plus,
        &uint_to_zeroizing_be_pad(
            (first
                .mul(second)
                .mod_floor(&key_share.n.to_bigint().expect("")))
            .to_biguint()
            .expect(""),
            key_share.key_bytes_size,
        )
        .expect(""),
    )
}

fn verify_signature(
    msg: &[u8],
    signature: &BigInt,
    scheme: PaddingScheme,
    key: &RSAThresholdPublicKey,
) -> bool {
    // let hashed = Sha256::digest(msg);
    // FIXME is this correct conversion?
    // let hashed = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&key.n);

    let padded = signature.modpow(&key.e, &key.n).mod_floor(&key.n);

    match scheme {
        PaddingScheme::NONE => {
            match BigInt::from_bytes_be(Sign::Plus, &msg)
                .mod_floor(&key.n)
                .cmp(&padded)
            {
                Ordering::Less | Ordering::Greater => false,
                Ordering::Equal => true,
            }
        }
        PaddingScheme::_PSS => unimplemented!(),
        PaddingScheme::PKCS1v15 => {
            let prefix = pkcs1v15_generate_prefix::<Sha256>();
            pkcs1v15_sign_unpad(
                &[], // prefix
                &msg,
                &uint_to_be_pad(padded.to_biguint().expect(""), key.bytes_size).unwrap(),
                key.bytes_size,
            )
            .unwrap()
                == ()
        }
    }

    // match msg.cmp(&hashed) {
    //     Ordering::Less | Ordering::Greater => false,
    //     Ordering::Equal => true,
    // }
}

// FIXME this should be only a helper in tests, move it
fn regular_signature(msg: &[u8], key: &RSAThresholdPrivateKey) -> BigInt {
    let msg_digest = Sha256::digest(msg);
    let modulus = &key.p.clone().mul(key.q.clone());
    let x = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&modulus);

    x.modpow(&key.d, &modulus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use rand::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};
    use std::iter::zip;

    #[test]
    fn test_evaluate_polynomial() {
        let coeffs = vec![
            BigInt::from(17u32),
            BigInt::from(63u32),
            BigInt::from(127u32),
        ];
        let modulus = BigInt::from(127u32);
        assert_eq!(
            evaluate_polynomial_mod(BigInt::from(2u32), &coeffs, &modulus).unwrap(),
            BigInt::from(16u32)
        );
    }

    #[test]
    fn evaluate_simple_polynomial() {
        let coeffs = vec![
            BigInt::from(1u64),
            BigInt::from(1u64),
            BigInt::from(1u64),
            BigInt::from(1u64),
        ];
        let modulus = BigInt::from(13u64);
        assert_eq!(
            evaluate_polynomial_mod(BigInt::from(1u32), &coeffs, &modulus).unwrap(),
            BigInt::from(4u64)
        );

        let coeffs = vec![
            BigInt::from(1u64),
            BigInt::from(2u64),
            BigInt::from(3u64),
            // BigInt::from(1u64),
        ];
        let modulus = BigInt::from(13u64);
        assert_eq!(
            evaluate_polynomial_mod(BigInt::from(100u32), &coeffs, &modulus).unwrap(),
            BigInt::from(2u32)
        );
    }

    #[test]
    fn another_polynomial_eval() {
        // h(x)=21231311311+x*31982323219+x^(2)*98212312334+x^(3)*43284+x^(4)*9381391389
        let coeffs = vec![
            BigInt::from(21231311311u64),
            BigInt::from(31982323219u64),
            BigInt::from(98212312334u64),
            BigInt::from(43284u32),
            BigInt::from(9381391389u64),
        ];
        let modulus = BigInt::from(7124072u64);
        assert_eq!(
            evaluate_polynomial_mod(BigInt::from(0u32), &coeffs, &modulus).unwrap(),
            BigInt::from(1576751u64)
        );
        // assert_eq!(
        //     evaluate_polynomial_mod(BigInt::from(1u32), &coeffs, &modulus).unwrap(),
        //     BigInt::from(2828353u64)
        // );
        assert_eq!(
            evaluate_polynomial_mod(BigInt::from(2u32), &coeffs, &modulus).unwrap(),
            BigInt::from(4139197u64)
        );
    }

    #[test]
    fn gen_keys() {
        // generate_primes(32);
        let l = 3;
        let k = 2;
        // let t = 1;
        let bit_length = 32;
        let _sk = key_gen(bit_length, l, k); //, t);
    }

    #[test]
    fn gen_shares() {
        let l = 3;
        let k = 2;
        // let t = 1;
        let bit_length = 128;
        let sk = key_gen(bit_length, l, k).unwrap();
        let shares = generate_secret_shares(&sk, l, k);
        let (v, vks) = generate_verification(&RSAThresholdPublicKey::from(&sk), shares);
    }

    #[test]
    fn is_safep_prime() {
        let mut rng = ChaCha20Rng::from_entropy();
        let p = rng.gen_prime(128);
        eprintln!("{}", p);
        // eprintln!("{:?}", p.to_bytes_be());
        let cp = U128::from_be_slice(&p.to_bytes_be());

        eprintln!("{:?}", is_safe_prime(&cp));
        eprintln!("{}", cp);
    }

    #[test]
    fn test_key_gen() {
        // another_key_gen(100000);

        // Given bits
        // let bit_length = 512;
        // let x: U8 = match bit_length {
        //     ..=32 => generate_safe_prime(Some(bit_length)),
        //     _ => generate_safe_prime(Some(256)),
        // };

        // assert_eq!(x.bits(), 32);
    }

    // #[test]
    // fn from_crypto_to_num() {
    //     let p: U256 = generate_safe_prime(Some(256));
    //     // let value = 32;
    //     // let x = match value {
    //     //     ..=32 => U64::generate_safe_prime(Some(value)),
    //     //     _ => U
    //     // }

    //     // eprintln!("{:?}", p);
    //     let bytes = p.to_be_bytes();
    //     // eprintln!("{:?}", bytes);
    //     let nb_p = BigInt::from_bytes_be(Sign::Plus, &bytes);
    //     // eprintln!("{:?}", nb_p.to_bytes_be());

    //     for (a, b) in zip(p.to_be_bytes()[1], nb_p.to_bytes_be()[1]) {
    //         assert_eq!(a, b);
    //     }
    // }

    #[test]
    fn generating_small_primes_errors() {
        assert!(generate_p_and_q(1).is_err());

        let (p, q) = generate_p_and_q(100).unwrap();

        assert!(p > BigInt::one());
        assert!(q > BigInt::one());

        eprintln!("{:?}", p.to_bytes_be());
        eprintln!("{:?}", q.to_bytes_be());
    }

    #[test]
    fn it_works() {
        let one = Checked::new(U256::ONE);
        let two = one + Checked::new(U256::from(1u8));

        // assert_eq!(two, Checked::new(U2048::from(2)));
        assert_eq!(two.0.unwrap(), U256::from(2u8));

        // let mut rng = ChaCha20Rng::from_entropy();
        // let modulus = 2048;
        // let key = key_gen(&mut rng, modulus);
        // eprintln!("{}", key.bits());
    }

    #[test]
    fn test_factorial() {
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(2), 2);
        assert_eq!(factorial(3), 6);
        assert_eq!(factorial(20), 2432902008176640000);
    }

    #[test]
    fn test_ordering() {
        assert_eq!(BigInt::zero().cmp(&BigInt::one()), Ordering::Less);
        assert_eq!(BigInt::one().cmp(&BigInt::zero()), Ordering::Greater);
    }

    #[test]
    fn try_hashing() {
        let msg = b"hello";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        hasher.finalize();
    }

    #[test]
    fn signing() {
        let l = 3;
        let k = 2;
        // let t = 1;
        let bit_length = 32;
        let sk = key_gen(bit_length, l, k).unwrap();
        let pubkey = RSAThresholdPublicKey::from(&sk);
        let shares = generate_secret_shares(&sk, l, k);
        // FIXME test
    }

    #[test]
    fn filtering() {
        let vals: Vec<u8> = vec![1, 2, 3, 4];
        eprintln!(
            "{:?}",
            vals.into_iter().filter(|&v| v != 1u8).collect::<Vec<u8>>()
        );
    }

    #[test]
    fn dealer_integration() {
        // initialize the group
        let l = 3;
        let k = 2;
        // let t = 1;
        let bit_length = 512;
        let msg = "ahello".as_bytes();
        let pad = PaddingScheme::PKCS1v15;
        // dealer's part
        let sk = key_gen(bit_length, l, k).unwrap();
        // let sk = load_key().unwrap();
        let pubkey = RSAThresholdPublicKey::from(&sk);
        let shares = generate_secret_shares(&sk, l, k);
        let (v, verification_keys) = generate_verification(&pubkey, shares.clone());

        let delta = factorial(l);
        // distribute the shares
        // hash_all_the_things(&v, delta);

        let mss1 = sign_with_share(
            msg.clone(),
            delta,
            &shares[0],
            // &pubkey,
            &v,//.clone(),
            &verification_keys[0],
            pad.clone(),
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x1);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg.clone(),
            &v,
            delta,
            // mss1.xi.clone(),
            &verification_keys[0],
            &mss1,
            // mss1.c.clone(),
            // mss1.z.clone(),
            &pubkey.n.to_biguint().expect(""),
            pubkey.bytes_size,
            pad.clone(),
        );
        assert!(verified);

        let mss2 = sign_with_share(
            msg,
            delta,
            &shares[1],
            // &pubkey,
            &v,//.clone(),
            &verification_keys[1],
            pad,
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x2);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg,
            &v,
            delta,
            // mss2.xi.clone(),
            &verification_keys[1],
            &mss2,
            // mss2.c.clone(),
            // mss2.z.clone(),
            &pubkey.n.to_biguint().expect(""),
            pubkey.bytes_size,
            pad.clone(),
        );
        assert!(verified);

        let signature = combine_shares(
            msg.clone(),
            delta,
            vec![mss1, mss2],
            &shares[0], // &pubkey,
            l,
            pad.clone(),
        );
        let reg_sig = regular_signature(msg.clone(), &sk);
        // assert_eq!(signature.cmp(&reg_sig), Ordering::Equal);
        eprintln!("signature: {:?}", signature);
        eprintln!("regular: {:?}", reg_sig);

        let n = (sk.p.clone() * sk.q.clone()).to_biguint().expect("");
        eprintln!("n: {}", n.to_string());
        eprintln!("e: {}", sk.e.to_string());
        eprintln!("d: {}", sk.d.to_string());
        eprintln!("p: {}", sk.p.to_string());
        eprintln!("q: {}", sk.q.to_string());
        eprintln!("m: {}", sk.m.to_string());
        eprintln!("v: {}", v.to_string());
        assert!(verify_signature(
            msg,
            &signature.clone(),
            pad,
            &pubkey
        ));
    }

    #[test]
    fn test_negating() {
        let mut one = BigInt::one().to_bigint().expect(""); // .to_bigint();
        negate_sign(&mut one);
        assert_eq!(
            BigInt::one().to_bigint().expect("").cmp(&one),
            Ordering::Greater
        );
    }

    #[test]
    fn power_to_negative() {
        let num = BigInt::from(123u8);
        let exp = BigInt::from(13u8);
        let modulus = BigInt::from(1231u16);

        let res = num.modpow(&exp, &modulus);
        eprintln!("{:?}", res.mod_inverse(&modulus));
    }

    #[test]
    fn test_lambda() {
        lambda(2, 0, 1, 2, vec![1, 2]);
    }

    // #[test]
    // fn save_keys() {
    //     let l = 2;
    //     let k = 2;
    //     let t = 1;
    //     let bit_length = 2048;
    //     let msg = String::from("hello").into_bytes().as_slice();
    //     // dealer's part
    //     let sk = key_gen(bit_length, l, k).unwrap();
    //     let _ = save_key(&sk);
    //     let loaded_key = load_key().unwrap();
    //     assert_eq!(sk.p, loaded_key.p);
    //     assert_eq!(sk.q, loaded_key.q);
    //     assert_eq!(sk.d, loaded_key.d);
    //     assert_eq!(sk.m, loaded_key.m);
    //     assert_eq!(sk.e, loaded_key.e);
    // }
    #[test]
    fn show_bigint() {
        let mut rng = ChaCha20Rng::from_entropy();
        let i = rng.gen_bigint(512);
        eprintln!("{}", i.to_string());
    }

    #[test]
    fn convert_to_pem() {
        let l = 2;
        let k = 2;
        // let t = 1;
        let bit_length = 2048;
        // let sk = key_gen(bit_length, l, k).unwrap();
        // save_key(&sk);
        let sk = load_key().unwrap();

        let n = (sk.p.clone() * sk.q.clone()).to_biguint().expect("");
        let privkey = RsaPrivateKey::from_components(
            n,
            sk.e.to_biguint().expect(""),
            sk.d.to_biguint().expect(""),
            vec![
                sk.p.clone().to_biguint().expect(""),
                sk.q.clone().to_biguint().expect(""),
            ],
        )
        // assert_eq!(sk.d.modpow(sk.e)
        .expect("");
        let mut keyfile = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keyfile.push("resources/test/private_key.pem");
        privkey.write_pkcs1_pem_file(keyfile, LineEnding::LF);
        let pem = privkey.to_pkcs1_pem(LineEnding::LF).expect("");
        // eprintln!("{}", pem.to_string());
        // priveky
    }
    #[test]
    fn print_private() {
        let l = 2;
        let k = 2;
        // let t = 1;
        let bit_length = 2048;
        // let sk = key_gen(bit_length, l, k).unwrap();
        let sk = load_key().unwrap();

        let n = (sk.p.clone() * sk.q.clone()).to_biguint().expect("");
        eprintln!("n: {}", n.to_string());
        eprintln!("e: {}", sk.e.to_string());
        eprintln!("d: {}", sk.d.to_string());
        eprintln!("p: {}", sk.p.to_string());
        eprintln!("q: {}", sk.q.to_string());
        eprintln!("m: {}", sk.m.to_string());
    }

    #[test]
    fn test_stringifying() {
        let mut rng = ChaCha20Rng::from_entropy();
        let i = rng.gen_bigint(512);
        let i_string = i.to_string();
        let i2 = BigInt::from_str(&i_string).unwrap();
        assert_eq!(i.cmp(&i2), Ordering::Equal);
    }
    // TODO add a test where the delta factorial is bigger than the modulus
    // Step by step checking together with shoup.py
    #[test]
    fn s2s() {
        // let mut rng = ChaCha20Rng::from_entropy();
        // let r = rng.gen_range(2..7);
        // eprintln!("l = k = {}", r);
        let l = 2;
        let k = 2;
        // let t = k - 1;
        let bit_length = 256;
        let pad = PaddingScheme::PKCS1v15;
        let sk = key_gen(bit_length, l, k).unwrap();
        eprintln!("bytes_size: {}", sk.bytes_size);
        // let sk = load_key().unwrap();
        let pubkey = RSAThresholdPublicKey::from(&sk);
        let shares = generate_secret_shares(&sk, l, k);
        let (v, verification_keys) = generate_verification(&pubkey, shares.clone());
        let delta = factorial(l);
        // eprintln!("delta: {}", delta);

        // TODO randomize the message
        let msg = "hel why".as_bytes();
        let mut sign_shares = vec![];
        for (share, vkey) in zip(
            shares.iter().take(k),
            verification_keys.clone().iter().take(k),
        ) {
            let signed_share = sign_with_share(
                msg,
                delta,
                &share,
                // &pubkey,
                &v, //.clone(),
                &vkey,
                pad.clone(),
            );
            sign_shares.push(signed_share.clone());
            let verified = verify_proof(
                msg,
                &v,
                delta,
                &vkey,
                &signed_share,
                &pubkey.n.to_biguint().expect(""),
                pubkey.bytes_size,
                pad.clone(),
            );
            assert!(verified);
        }

        let signature = combine_shares(msg, delta, sign_shares, &shares[0], l, pad.clone());
        // let _reg_sig = regular_signature(msg.clone(), &sk);

        // FIXME apparently sometimes our signature is differente from the regular signature.
        // assert!(verify_signature(
        //     msg.clone(),
        //     &signature.clone(),
        //     pad.clone(),
        //     &pubkey
        // ));
        // assert_eq!(signature, reg_sig);
        let n = (sk.p.clone() * sk.q.clone()).to_biguint().expect("");
        let r_privkey = RsaPrivateKey::from_components(
            n.clone(),
            sk.e.to_biguint().expect(""),
            sk.d.to_biguint().expect(""),
            vec![
                sk.p.clone().to_biguint().expect(""),
                sk.q.clone().to_biguint().expect(""),
            ],
        )
        .expect("");
        let r_pub = r_privkey.to_public_key();
        // r_pub.verify
        // TODO verify against a RSA/RsaPublicKey
        // let padded = digest_msg(msg, pad, &n, pubkey.bytes_size);
        // eprintln!("padded len: \n{:?}", padded.to_bytes_be().1.len());
        // eprintln!("pad length: {}", pkcs1v15_sign_pad(&[], &msg, pubkey.bytes_size).unwrap().len());
        assert_eq!(
            r_pub.verify(
                // &mut ChaCha20Rng::from_entropy(),
                Pkcs1v15Sign::new_unprefixed(),
                // {
                //     hash_len: None,
                //     prefix: Box::new([0u8;0]), //pkcs1v15_generate_prefix::<Sha256>().into(),
                // },
                // &pkcs1v15_sign_pad(&[], &msg, pubkey.bytes_size).unwrap(),
                &msg,
                // &padded.to_bytes_be().1,
                &signature.to_bytes_be().1,
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_padding() {
        let k = 2048;
        // let prefix = &[]; //pkcs1v15_generate_prefix::<Sha256>();
        let hashed = Sha256::digest(b"hello");
        let mut padded = pkcs1v15_sign_pad(&[], &hashed, k).unwrap();
        assert_eq!(
            pkcs1v15_sign_unpad(&[], &hashed, &padded, k).unwrap(),
            ()
        );
    }

    #[test]
    fn test_key_conversions() {
        let l = 2;
        let k = 2;
        let sk = load_key().unwrap();
        RsaPublicKey::from(sk);
    }

    #[test]
    fn that_dealer_generates_identical_public_pkgs_to_each_signer() {
        let max_signers = 3;
        let min_signers = 3;
        let key_bit_length = 512;

        let Ok((_, public_pkgs)) = generate_with_dealer(max_signers, min_signers, key_bit_length)
        else {
            panic!("dealer generation has failed")
        };
        let Some(first) = public_pkgs.first() else {
            panic!("first public package is missing")
        };
        assert!(public_pkgs.iter().all(|pkg| pkg == first));
    }

    #[test]
    fn that_threshold_number_of_signers_generates_valid_signature() {
        let max_signers = 3;
        let min_signers = 2;
        let key_bit_length = 512;

        let Ok((secret_pkgs, public_pkgs)) =
            generate_with_dealer(max_signers, min_signers, key_bit_length)
        else {
            panic!("dealer generation has failed")
        };
        let Some(first) = public_pkgs.first() else {
            panic!("first public package is missing")
        };
        let v = &first.v;
        let vkey = &first.verification_keys;
        let padding_scheme = PaddingScheme::PKCS1v15;
        // let msg = String::from("hello").into_bytes();
        let msg = b"hello".as_slice();

        let pms: Vec<PartialMessageSignature> = secret_pkgs
            .iter()
            .enumerate()
            .map(|(i, share)| {
                share
                    .sign(
                        msg.clone(),
                        max_signers,
                        v.clone(),
                        &vkey[i],
                        padding_scheme,
                    )
                    .unwrap()
            })
            .collect();

        let delta = factorial(max_signers.into());
        // Check that all partial signatures verify
        for index in 0..3 {
            assert!(
                verify_proof(
                    msg,
                    v,
                    delta,
                    &vkey[index],
                    &pms[index],
                    &secret_pkgs[index].share.n,
                    secret_pkgs[index].share.key_bytes_size,
                    padding_scheme,
                ),
                "proof for {index} did not verify"
            );
        }

        let signature_3_of_3 = combine_shares(
            msg.clone(),
            delta,
            pms.clone(),
            &secret_pkgs[0].share,
            max_signers.into(),
            padding_scheme,
        );

        // The ideas is that every pair of signers should generate the same signature for a
        // deterministic padding scheme
        for pair in (0..max_signers).into_iter().combinations(2) {
            let first = pair[0] as usize;
            let second = pair[1] as usize;

            assert_eq!(
                signature_3_of_3,
                combine_shares(
                    msg.clone(),
                    delta,
                    vec![pms[first].clone(), pms[second].clone()],
                    &secret_pkgs[first].share,
                    max_signers.into(),
                    padding_scheme,
                ),
            "the signature 3 out of 3 does not match signature from parties [{first}, {second}]");
        }
    }

    // #[test]
    // fn that_key_generation_is_not_slow() {
    //     // FIXME this is just a dev test
    //     generate_p_and_q(2048);
    // }
}
