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

// use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Result as SerdeResult, Value};
use std::any::type_name;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Add, Div, Mul, MulAssign, Neg, Shr};
use std::str::FromStr;

// FIXME Check that the geneated values/shares etc. are not ones or zeroes for example?
// TODO: add PKCS1v5 padding
// TODO: add PSS padding --- needs message passing
// TODO: fix the k-out-of-l signatures that differ from the regular one when k < l
// TODO: prefer BigUint over BigInt

// Deal function to generate from
// inputs k-out-of-n
// return vec of PrivateShares and vec of VerificationKey
// SecretPackage and PublicPackage

// for signing send MessageSignRequest
// return PartialSignature
//
//
// PublicPackage: HashMap of PartialSignature VerificationKeys, VerificationKey
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicPackage {
    v: BigInt,
    verification_keys: Vec<RsaVerificationKey>,
    public_key: RsaPublicKey,
}
// TODO add unique IDs and also keep the unique ideas around
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretPackage {
    // TODO use bigger IDs? globally unique ids?
    pub uid: usize,
    pub gid: Option<usize>,
    // TODO This is not nice, but needed for meesign-crypto integration
    pub share: RsaSecretShare,
}

// dealer cobines/aggregates the signatures

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSAThresholdPrivateKey {
    n: BigInt,
    p: BigInt,
    q: BigInt,
    d: BigInt,
    m: BigInt,
    e: BigInt,
    // TODO follow RustCrypto/RSA convention of functions instead of fields
    bytes_size: usize,
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
    id: usize,
    share: BigInt,
    // m: BigInt,
}

// FIXME introduce lifetimes?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RsaVerificationKey {
    id: usize,
    key: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgSignatureShare {
    id: usize,
    xi: BigInt,
    z: BigInt,
    c: BigInt,
    // key: RSAThresholdPublicKey,
}

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

impl RSAThresholdPrivateKey {
    pub fn get_public(&self) -> RSAThresholdPublicKey {
        RSAThresholdPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
            bytes_size: self.bytes_size,
        }
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
    t: usize,
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

#[derive(Clone)]
enum PaddingScheme {
    NONE,
    PSS,
    PKCS1v15,
}

fn digest_msg<R: CryptoRngCore>(
    msg: String,
    scheme: PaddingScheme,
    _rng: &mut R,
    key: &RSAThresholdPublicKey,
) -> BigInt {
    let msg_digest = Sha256::digest(msg);
    // FIXME is this correct conversion?
    // TODO Add support for various hash functions
    let hashed = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&key.n);
    // TODO there are four variants for PSS
    match scheme {
        PaddingScheme::NONE => hashed,
        PaddingScheme::PSS => unimplemented!(),
        PaddingScheme::PKCS1v15 => {
            let prefix = pkcs1v15_generate_prefix::<Sha256>();
            BigInt::from_bytes_be(
                Sign::Plus,
                &pkcs1v15_sign_pad(&prefix, &hashed.to_bytes_be().1, key.bytes_size).unwrap(),
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
fn sign_with_share(
    msg: String,
    delta: usize,
    share: &RsaSecretShare,
    key: &RSAThresholdPublicKey,
    v: BigInt,
    vi: &RsaVerificationKey,
    scheme: PaddingScheme,
) -> MsgSignatureShare {
    // FIXME add some kind of blinding?
    let x = digest_msg(msg.clone(), scheme, &mut ChaCha20Rng::from_entropy(), key);
    // FIXME is this correct conversion?
    // let x = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&key.n);
    // eprintln!("x = {:?}", x);
    // let xi = BigInt::from_bytes_be(msg_digest);
    let mut exponent = BigInt::from(2u8);
    exponent.mul_assign(BigInt::from(delta));
    exponent.mul_assign(share.share.clone());
    // calculate the signature share
    let xi = x.modpow(&exponent, &key.n);
    // x_tilde
    let x_tilde = x.pow(4 * delta);
    let xi_squared: BigInt = xi.modpow(&BigInt::from(2u8), &key.n);

    // calculate the proof of correctness
    let n_bits = key.n.bits();
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
    let v_prime = v.modpow(&r, &key.n);
    let x_prime = x_tilde.modpow(&r, &key.n);
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

    MsgSignatureShare {
        id: share.id,
        xi: xi,
        z: z,
        c: c,
    }
}

fn lambda(delta: usize, i: usize, j: usize, l: usize, subset: Vec<usize>) -> BigInt {
    // FIXME usize might overflow? what about using BigInt
    let subset: Vec<usize> = subset.into_iter().filter(|&s| s != j).collect();
    // eprintln!("subset: {:?}, j: {}", subset, j);

    let numerator: i64 = subset.iter().map(|&j_p| i as i64 - j_p as i64).product();
    let denominator: i64 = subset.iter().map(|&j_p| j as i64 - j_p as i64).product();
    // eprintln!("numerator: {:?}", numerator);
    // eprintln!("denominator: {:?}", denominator);

    // TODO use mul and div
    let value = BigInt::from(delta as i64 * (numerator / denominator));
    // eprintln!("lambda: {}", value);
    value
}

fn factorial(value: usize) -> usize {
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
fn verify_proof(
    msg: String,
    v: BigInt,
    delta: usize,
    // xi: BigInt,
    vi: &RsaVerificationKey,
    // c: BigInt,
    // z: BigInt,
    mss: MsgSignatureShare,
    key: &RSAThresholdPublicKey,
    scheme: PaddingScheme,
) -> bool {
    let x = digest_msg(msg.clone(), scheme, &mut ChaCha20Rng::from_entropy(), key);
    let x_tilde: BigInt = x.pow(4 * delta);

    let xi_squared: BigInt = mss.xi.modpow(&BigInt::from(2u8), &key.n);

    let v2z = v.modpow(&mss.z, &key.n);
    // FIXME refactor param5 and param6 calculations
    // FIXME use checked_mul instead
    let param5 = v.modpow(&mss.z, &key.n);
    let tmp1 = vi.key.modpow(&mss.c, &key.n).mod_inverse(&key.n).expect("");
    let param5 = (param5 * tmp1).mod_floor(&key.n);

    let param6 = x_tilde.modpow(&mss.z, &key.n);
    let tmp2 = mss
        .xi
        .modpow(&(mss.c.clone().mul(BigInt::from(2u8))), &key.n)
        .mod_inverse(&key.n)
        .expect("");
    let param6 = (param6 * tmp2).mod_floor(&key.n);

    let mut commit = v.to_bytes_be().1;
    commit.extend(x_tilde.to_bytes_be().1);
    commit.extend(vi.key.to_bytes_be().1);
    commit.extend(xi_squared.to_bytes_be().1);
    commit.extend(param5.to_bytes_be().1);
    commit.extend(param6.to_bytes_be().1);
    mss.c
        .cmp(&BigInt::from_bytes_be(Sign::Plus, &Sha256::digest(commit)))
        == Ordering::Equal
}

fn save_key(key: &RSAThresholdPrivateKey) -> std::io::Result<()> {
    let mut keyfile = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    keyfile.push("resources/test/private_key.json");
    let mut handle = File::create(keyfile)?;
    handle.write_all(serde_json::to_string(key).unwrap().as_bytes())?;
    Ok(())
}

fn load_key() -> std::io::Result<RSAThresholdPrivateKey> {
    let mut keyfile = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    keyfile.push("resources/test/private_key.json");
    let mut handle = File::open(keyfile)?;

    let mut data = String::new();
    handle.read_to_string(&mut data)?;
    let key: RSAThresholdPrivateKey = serde_json::from_str(&data)?;
    Ok(key)
}

/// Combine signature shares.
fn combine_shares(
    msg: String,
    delta: usize,
    sign_shares: Vec<MsgSignatureShare>,
    key: &RSAThresholdPublicKey,
    l: usize,
    scheme: PaddingScheme,
) -> BigInt {
    // FIXME verify the shares prior to combining them
    let x = digest_msg(msg.clone(), scheme, &mut ChaCha20Rng::from_entropy(), key);
    // eprintln!("pz_x = {}", x);

    let mut w = BigInt::one();
    // FIXME the set is supposed to be dynamic
    let subset = sign_shares.iter().map(|s| s.id).collect::<Vec<usize>>();
    for (_, share) in sign_shares.iter().enumerate() {
        let lamb = lambda(delta, 0, share.id, l, subset.clone());

        // FIXME exponent might be negative - what then?
        let exponent = BigInt::from(2u8).mul(lamb);
        // eprintln!("exponent: {}", exponent);

        w.mul_assign(match exponent.cmp(&BigInt::zero()) {
            Ordering::Less => share
                .xi
                .modpow(&exponent.neg(), &key.n)
                .mod_inverse(&key.n)
                .expect(""),
            Ordering::Equal => BigInt::one(),
            Ordering::Greater => share.xi.modpow(&exponent, &key.n),
        });
        // w.mul_assign(share.modpow(&exponent, &key.n));
    }
    w = w.mod_floor(&key.n);
    let e_prime = BigInt::from(4u8).mul(delta.pow(2));
    let (g, Some(a), Some(b)) = extended_gcd(
        std::borrow::Cow::Borrowed(&e_prime.to_biguint().expect("")),
        std::borrow::Cow::Borrowed(&key.e.to_biguint().expect("")),
        true,
    ) else {
        todo!()
    };
    // eprintln!("a: {}", a);
    // eprintln!("e_prime: {}", e_prime);
    // eprintln!("b: {}", b);
    // eprintln!("pz_w = {}", w);
    // eprintln!("x: {}", x.to_string());
    assert_eq!(
        e_prime
            .clone()
            .mul(a.clone())
            .add(&key.e.clone().mul(b.clone()))
            .cmp(&BigInt::one()),
        Ordering::Equal,
        "The Bezout's equality e'a + eb != 1 does not hold.",
    );
    assert_eq!(g.cmp(&BigInt::one()), Ordering::Equal);
    let we = w.modpow(&key.e, &key.n);
    let xe_prime = x.modpow(&BigInt::from(e_prime), &key.n);
    assert_eq!(
        we.cmp(&BigInt::zero()),
        Ordering::Greater,
        "w^e is not positive"
    );
    assert_eq!(
        xe_prime.cmp(&BigInt::zero()),
        Ordering::Greater,
        "x^e' is not positive"
    );

    assert_eq!(
        we.cmp(&xe_prime),
        // .cmp(&x.modpow(&BigInt::from(e_prime), &key.n)),
        Ordering::Equal,
        "w^e != x^e'"
    );

    // NOTE raise to the negative power is not possible at the moment
    let first = match a.cmp(&BigInt::zero()) {
        Ordering::Less => w.modpow(&a.neg(), &key.n).mod_inverse(&key.n).expect(""),
        Ordering::Equal => BigInt::one(),
        Ordering::Greater => w.modpow(&a, &key.n),
    };
    let second = match b.cmp(&BigInt::zero()) {
        Ordering::Less => x.modpow(&b.neg(), &key.n).mod_inverse(&key.n).expect(""),
        Ordering::Equal => BigInt::one(),
        Ordering::Greater => x.modpow(&b, &key.n),
    };

    BigInt::from_bytes_be(
        Sign::Plus,
        &uint_to_zeroizing_be_pad(
            (first.mul(second).mod_floor(&key.n))
                .to_biguint()
                .expect(""),
            key.bytes_size,
        )
        .expect(""),
    )
}

fn verify_signature(
    msg: String,
    signature: &BigInt,
    scheme: PaddingScheme,
    key: &RSAThresholdPublicKey,
) -> bool {
    let hashed = Sha256::digest(msg);
    // FIXME is this correct conversion?
    // let hashed = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&key.n);

    let padded = signature.modpow(&key.e, &key.n).mod_floor(&key.n);

    match scheme {
        PaddingScheme::NONE => {
            match BigInt::from_bytes_be(Sign::Plus, &hashed)
                .mod_floor(&key.n)
                .cmp(&padded)
            {
                Ordering::Less | Ordering::Greater => false,
                Ordering::Equal => true,
            }
        }
        PaddingScheme::PSS => unimplemented!(),
        PaddingScheme::PKCS1v15 => {
            let prefix = pkcs1v15_generate_prefix::<Sha256>();
            pkcs1v15_sign_unpad(
                &prefix,
                &hashed,
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

fn regular_signature(msg: String, key: &RSAThresholdPrivateKey) -> BigInt {
    let msg_digest = Sha256::digest(msg);
    let modulus = &key.p.clone().mul(key.q.clone());
    let x = BigInt::from_bytes_be(Sign::Plus, &msg_digest).mod_floor(&modulus);

    x.modpow(&key.d, &modulus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};
    use std::iter::zip;
    // use test_log::test;

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
        let t = 1;
        let bit_length = 32;
        let sk = key_gen(bit_length, l, k, t);
        // eprintln!("{:?}", sk.get_public());
    }

    #[test]
    fn gen_shares() {
        let l = 3;
        let k = 2;
        let t = 1;
        let bit_length = 128;
        let sk = key_gen(bit_length, l, k, t).unwrap();
        let shares = generate_secret_shares(&sk, l, k);
        eprintln!("shares: {:?}", shares);
        let (v, vks) = generate_verification(&sk.get_public(), shares);
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
        cp;
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
        let t = 1;
        let bit_length = 32;
        let sk = key_gen(bit_length, l, k, t).unwrap();
        let pubkey = sk.get_public();
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
        let t = 1;
        let bit_length = 512;
        let msg = String::from("ahello");
        let pad = PaddingScheme::NONE;
        // dealer's part
        let sk = key_gen(bit_length, l, k, t).unwrap();
        // let sk = load_key().unwrap();
        let pubkey = sk.get_public();
        let shares = generate_secret_shares(&sk, l, k);
        let (v, verification_keys) = generate_verification(&pubkey, shares.clone());

        let delta = factorial(l);
        // distribute the shares
        // hash_all_the_things(&v, delta);

        let mss1 = sign_with_share(
            msg.clone(),
            delta,
            &shares[0],
            &pubkey,
            v.clone(),
            &verification_keys[0],
            pad.clone(),
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x1);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg.clone(),
            v.clone(),
            delta,
            // mss1.xi.clone(),
            &verification_keys[0],
            mss1.clone(),
            // mss1.c.clone(),
            // mss1.z.clone(),
            &pubkey,
            pad.clone(),
        );
        assert!(verified);

        let mss2 = sign_with_share(
            msg.clone(),
            delta,
            &shares[1],
            &pubkey,
            v.clone(),
            &verification_keys[1],
            pad.clone(),
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x2);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg.clone(),
            v.clone(),
            delta,
            // mss2.xi.clone(),
            &verification_keys[1],
            mss2.clone(),
            // mss2.c.clone(),
            // mss2.z.clone(),
            &pubkey,
            pad.clone(),
        );
        assert!(verified);

        let signature = combine_shares(
            msg.clone(),
            delta,
            vec![mss1, mss2],
            &pubkey,
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
            msg.clone(),
            &signature.clone(),
            pad.clone(),
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
    //     let msg = String::from("hello");
    //     // dealer's part
    //     let sk = key_gen(bit_length, l, k, t).unwrap();
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
        let t = 1;
        let bit_length = 2048;
        // let sk = key_gen(bit_length, l, k, t).unwrap();
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
        let t = 1;
        let bit_length = 2048;
        // let sk = key_gen(bit_length, l, k, t).unwrap();
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
        let t = k - 1;
        let bit_length = 512;
        let pad = PaddingScheme::PKCS1v15;
        let sk = key_gen(bit_length, l, k, t).unwrap();
        eprintln!("bytes_size: {}", sk.bytes_size);
        // let sk = load_key().unwrap();
        let pubkey = sk.get_public();
        let shares = generate_secret_shares(&sk, l, k);
        let (v, verification_keys) = generate_verification(&pubkey, shares.clone());
        let delta = factorial(l);
        // eprintln!("delta: {}", delta);

        // TODO randomize the message
        let msg = String::from("hello");
        let mut sign_shares = vec![];
        for (share, vkey) in zip(
            shares.iter().take(k),
            verification_keys.clone().iter().take(k),
        ) {
            let signed_share = sign_with_share(
                msg.clone(),
                delta,
                &share,
                &pubkey,
                v.clone(),
                &vkey,
                pad.clone(),
            );
            sign_shares.push(signed_share.clone());
            let verified = verify_proof(
                msg.clone(),
                v.clone(),
                delta,
                &vkey,
                signed_share,
                &pubkey,
                pad.clone(),
            );
            assert!(verified);
        }

        let signature = combine_shares(msg.clone(), delta, sign_shares, &pubkey, l, pad.clone());
        // let _reg_sig = regular_signature(msg.clone(), &sk);

        // FIXME apparently sometimes our signature is differente from the regular signature.
        assert!(verify_signature(
            msg.clone(),
            &signature.clone(),
            pad.clone(),
            &pubkey
        ));
        // assert_eq!(signature, reg_sig);
        let n = (sk.p.clone() * sk.q.clone()).to_biguint().expect("");
        let r_privkey = RsaPrivateKey::from_components(
            n,
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
        let hashed = Sha256::digest(msg);
        assert_eq!(
            r_pub.verify(
                // &mut ChaCha20Rng::from_entropy(),
                Pkcs1v15Sign {
                    hash_len: None,
                    prefix: pkcs1v15_generate_prefix::<Sha256>().into(),
                },
                &hashed,
                &signature.to_bytes_be().1,
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_padding() {
        let k = 2048;
        let prefix = pkcs1v15_generate_prefix::<Sha256>();
        let hashed = Sha256::digest(b"hello");
        let mut padded = pkcs1v15_sign_pad(&prefix, &hashed, k).unwrap();
        assert_eq!(
            pkcs1v15_sign_unpad(&prefix, &hashed, &padded, k).unwrap(),
            ()
        );
    }
}
