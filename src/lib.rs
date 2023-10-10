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
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Result as SerdeResult, Value};
use std::any::type_name;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Add, Div, Mul, MulAssign, Shr};
// pub fn generate_primes(modulus_bit_length: usize) -> (U2048, U2048) {
//     let p: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
//     let mut q: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
//     while p == q {
//         q = generate_safe_prime(Some(modulus_bit_length / 2));
//     }
//     (p, q)
// }
//

// FIXME Check that the geneated values/shares etc. are not ones or zeroes for example?
// TODO rewrite BigUint::new(vec! to ::from

// #[derive(Serialize, Deserialize)]
// pub struct Hello {
//     x: u32,
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct RSAThresholdPrivateKey {
    p: BigUint,
    q: BigUint,
    d: BigUint,
    m: BigUint,
    e: BigUint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RSAThresholdPublicKey {
    n: BigUint,
    e: BigUint,
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
    fn get_public(&self) -> RSAThresholdPublicKey {
        RSAThresholdPublicKey {
            n: self.p.clone().mul(self.q.clone()),
            e: self.e.clone(),
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
    let e: BigUint = BigUint::new(vec![0x10001]); // 65537

    // FIXME: compare against e directly
    if l > 65537 {
        return Err(KeyGenError::GroupTooBig);
    };

    let n = p.clone().mul(&q);
    // FIXME code without unwraps
    let p_prime = &p.checked_sub(&BigUint::one()).unwrap().shr(1);
    let q_prime = &q.checked_sub(&BigUint::one()).unwrap().shr(1);

    let m = p_prime.mul(q_prime);
    let dd = match e.clone().mod_inverse(&m) {
        Some(value) => value,
        None => return Err(KeyGenError::NoInverse),
    };
    assert!(dd.cmp(&BigInt::zero()) == Ordering::Greater);

    // TODO d is expected to be an Integer, not exactly modulo, it just needs to
    // satisfy the equation de = 1 mod m
    let d: BigUint = match dd.to_biguint() {
        Some(value) => value,
        None => return Err(KeyGenError::NoInverse),
    };
    assert_eq!(
        d.clone().mul(e.clone()).mod_floor(&m).cmp(&BigUint::one()),
        Ordering::Equal
    );

    Ok(RSAThresholdPrivateKey {
        p: p,
        q: q,
        d: d,
        m: m,
        e: e,
    })
}

fn evaluate_polynomial_mod(
    value: BigUint,
    coeffs: &Vec<BigUint>,
    modulus: &BigUint,
) -> Result<BigUint, PolynomialError> {
    let mut prev: BigUint = match coeffs.last() {
        Some(last) => last.clone(),
        None => return Err(PolynomialError::NoCoefficients),
    };

    for next in coeffs.iter().rev().skip(1) {
        // TODO what multiplication and addition is used for * and +, should we call functions
        // mul and add instead?
        prev = prev.mul(&value).add(next).mod_floor(modulus);
    }
    let rem = prev.mod_floor(modulus);
    Ok(rem)
}

// fn evaluate_polynomial_mod(value: U4096, coeffs: Vec<U4096>, modulus: U4096) -> U4096 {
//     let mut result = U4096::ZERO;
//     let ui = U4096::from_u32(i.try_into().unwrap());
//     for i in 1..=coeffs.len() {
//         eprintln!("{}", i);
//         ui.checked_mul(&coeffs[i]).unwrap(); //, &modulus, modulus.invert());
//                                              // , coeffs[0]),

//         // let iu: u32 = i.try_into().unwrap();
//         // result.add_mod(
//         //     &(U4096::from_u32(i.try_into().unwrap()) * coeffs[0]),
//         //     &modulus,
//         // );
//     }
//     U4096::ONE
// }

fn generate_secret_shares(key: &RSAThresholdPrivateKey, l: usize, k: usize) -> Vec<BigUint> {
    // generate random coefficients
    let mut rng = ChaCha20Rng::from_entropy();
    let mut a_coeffs: Vec<BigUint> = (0..=(k - 1))
        .map(|_| rng.gen_biguint_below(&key.m))
        .collect();
    // eprintln!("len coeffs: {}", a_coeffs.len());
    // fix a_0 to the private exponent
    a_coeffs[0] = key.d.clone();
    // calculate the individual shares
    let shares: Vec<BigUint> = (1..=l)
        .map(|i| evaluate_polynomial_mod(i.into(), &a_coeffs, &key.m).unwrap())
        .collect();
    shares
}

fn generate_verification(
    key: &RSAThresholdPublicKey,
    shares: Vec<BigUint>,
) -> (BigUint, Vec<BigUint>) {
    let mut rng = ChaCha20Rng::from_entropy();
    let two = BigUint::new(vec![2]);
    // FIXME: v is supposed to be from the subgroup of squares, is it?
    let v = rng.gen_biguint_range(&two, &key.n);
    assert_eq!(v.gcd(&key.n).cmp(&BigUint::one()), Ordering::Equal);
    let verification_keys = shares.iter().map(|s| v.modpow(s, &key.n)).collect();
    (v, verification_keys)
}

// fn hash_all_the_things(v: BigUint, delta: usize) -> BigUint {
//     // x ^ {4 * delta}
//     let x_tilde =
//     BigUint::one()
// }

/// _i = x^{2 \delta s_i} \in Q_n
fn sign_with_share(
    msg: String,
    delta: usize,
    share: &BigUint,
    key: &RSAThresholdPublicKey,
    v: BigUint,
    vi: &BigUint,
) -> (BigUint, BigUint, BigUint) {
    let msg_digest = Sha256::digest(msg);
    // FIXME is this correct conversion?
    let x = BigUint::from_bytes_be(&msg_digest);
    // eprintln!("x = {:?}", x);
    // let xi = BigUint::from_bytes_be(msg_digest);
    let mut exponent = BigUint::from(2u8);
    exponent.mul_assign(BigUint::from(delta));
    exponent.mul_assign(share);
    // calculate the signature share
    let xi = x.modpow(&exponent, &key.n);
    // x_tilde
    let x_tilde = x.pow(4 * delta);
    let xi_squared: BigUint = xi.modpow(&BigUint::from(2u8), &key.n);

    // calculate the proof of correctness
    let n_bits = key.n.bits();
    let hash_length = 256;
    let mut rng = ChaCha20Rng::from_entropy();
    let two = BigUint::from(2u8);

    let bound = two
        .pow(n_bits + 2 * hash_length)
        .checked_sub(&BigUint::one())
        .expect("");
    let r = rng.gen_biguint_below(&bound);
    // FIXME the next exponentiation should not be modulo
    let v_prime = v.modpow(&r, &key.n);
    let x_prime = x_tilde.modpow(&r, &key.n);
    // c =  hash(v, x_tilde, vi, xi^2, v^r, x^r)
    let mut commit = v.to_bytes_be();
    commit.extend(x_tilde.to_bytes_be());
    commit.extend(vi.to_bytes_be());
    commit.extend(xi_squared.to_bytes_be());
    commit.extend(v_prime.to_bytes_be());
    commit.extend(x_prime.to_bytes_be());

    let c = BigUint::from_bytes_be(&Sha256::digest(commit));
    let z = (share.mul(c.clone())).add(r);

    (xi, z, c)
}

// // Group signatures, where only the group members can verify the signature.
// fn combine_shares(shares: Vec<BigUint>) -> BigUint {
//     let w = BigUint::one();
//     w
// }

fn lambda(delta: usize, i: usize, j: usize, l: usize, subset: Vec<usize>) -> BigInt {
    // FIXME usize might overflow? what about using BigUint
    let subset: Vec<usize> = subset.into_iter().filter(|&s| s != j).collect();

    let numerator: i64 = subset.iter().map(|&j_p| i as i64 - j_p as i64).product();
    let denominator: i64 = subset.iter().map(|&j_p| j as i64 - j_p as i64).product();

    // TODO use mul and div
    BigInt::from(delta as i64 * (numerator / denominator))
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
fn generate_p_and_q(bit_length: usize) -> Result<(BigUint, BigUint), KeyGenError> {
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
    let p = BigUint::from_bytes_be(&crypto_p.to_be_bytes());
    let q = BigUint::from_bytes_be(&crypto_q.to_be_bytes());

    if p.bits() != half_bit_length || q.bits() != half_bit_length {
        return Err(KeyGenError::BitLength);
    }

    Ok((p, q))
}

// FIXME go through expects and fix them!
fn verify_proof(
    msg: String,
    v: BigUint,
    delta: usize,
    xi: BigUint,
    vi: &BigUint,
    c: BigUint,
    z: BigUint,
    key: &RSAThresholdPublicKey,
) -> bool {
    let msg_digest = Sha256::digest(msg);
    // FIXME is this correct conversion?
    let x = BigUint::from_bytes_be(&msg_digest);
    let x_tilde: BigUint = x.pow(4 * delta);

    let xi_squared: BigUint = xi.modpow(&BigUint::from(2u8), &key.n);

    let v2z = v.modpow(&z, &key.n);
    // minus c
    // let mut neg_c = c.to_bigint().expect("Cannot negate -c");
    // negate_sign(&mut neg_c);
    // v^z vi^{-c}
    // FIXME refactor param5 and param6 calculations
    // FIXME use checked_mul instead
    let param5 = v.modpow(&z, &key.n);
    let tmp1 = vi
        .modpow(&c, &key.n)
        .mod_inverse(&key.n)
        .expect("")
        .to_biguint()
        .expect("");
    let param5 = (param5 * tmp1).mod_floor(&key.n);

    let param6 = x_tilde.modpow(&z, &key.n);
    let tmp2 = xi
        .modpow(&(c.clone().mul(BigUint::from(2u8))), &key.n)
        .mod_inverse(&key.n)
        .expect("")
        .to_biguint()
        .expect("");
    let param6 = (param6 * tmp2).mod_floor(&key.n);

    // let vi2negc = vi
    //     .to_bigint()
    //     .expect("")
    //     .modpow(&neg_c, &key.n.to_bigint().expect(""));
    // let v2z_vi2negc = (v2z.to_bigint().expect("") * vi2negc)
    //     .to_biguint()
    //     .expect("");

    // let x_tilde2z = x_tilde.modpow(&z, &key.n);
    // let neg2c: BigInt = neg_c * 2;
    // let x_tilde2z_xi2negc: BigUint = (x_tilde2z.to_bigint().expect("") * neg2c)
    //     .to_biguint()
    //     .expect("");

    let mut commit = v.to_bytes_be();
    commit.extend(x_tilde.to_bytes_be());
    commit.extend(vi.to_bytes_be());
    commit.extend(xi_squared.to_bytes_be());
    commit.extend(param5.to_bytes_be());
    commit.extend(param6.to_bytes_be());
    // commit.extend(v2z_vi2negc.to_biguint().expect("").to_bytes_be());
    // commit.extend(x_tilde2z_xi2negc.to_bytes_be());
    // commit.
    c.cmp(&BigUint::from_bytes_be(&Sha256::digest(commit))) == Ordering::Equal
}

fn save_key(key: &RSAThresholdPrivateKey) -> std::io::Result<()> {
    unimplemented!();
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
    shares: Vec<BigUint>,
    key: &RSAThresholdPublicKey,
    l: usize,
) -> BigUint {
    let msg_digest = Sha256::digest(msg);
    // FIXME is this correct conversion?
    let x = BigUint::from_bytes_be(&msg_digest);

    let mut w = BigUint::one();
    // FIXME the set is supposed to be dynamic
    let subset = vec![1, 2];
    let e_prime = 4 * delta.pow(2);
    for (ik, share) in shares.iter().enumerate() {
        let lamb = lambda(delta, 0, ik, l, subset.clone());

        // FIXME exponent might be negative - what then?
        let mut exponent = BigInt::from(2u8).mul(lamb).to_biguint().expect("");

        w.mul_assign(share.modpow(&exponent, &key.n));
    }
    // FIXME use dynamic e not a static value
    // let (g, a, b) = egcd(e_prime, 0x10001);
    let (g, Some(a), Some(b)) = extended_gcd(
        std::borrow::Cow::Borrowed(&BigUint::from(e_prime)),
        std::borrow::Cow::Borrowed(&key.e),
        true,
    ) else {
        todo!()
    };
    assert_eq!(g.cmp(&BigInt::one()), Ordering::Equal);
    let y =
        w.modpow(&a.to_biguint().expect(""), &key.n) * x.modpow(&b.to_biguint().expect(""), &key.n);
    y
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
            BigUint::from(17u32),
            BigUint::from(63u32),
            BigUint::from(127u32),
        ];
        let modulus = BigUint::from(127u32);
        assert_eq!(
            evaluate_polynomial_mod(BigUint::from(2u32), &coeffs, &modulus).unwrap(),
            BigUint::from(16u32)
        );
    }

    #[test]
    fn evaluate_simple_polynomial() {
        let coeffs = vec![
            BigUint::from(1u64),
            BigUint::from(1u64),
            BigUint::from(1u64),
            BigUint::from(1u64),
        ];
        let modulus = BigUint::from(13u64);
        assert_eq!(
            evaluate_polynomial_mod(BigUint::from(1u32), &coeffs, &modulus).unwrap(),
            BigUint::from(4u64)
        );

        let coeffs = vec![
            BigUint::from(1u64),
            BigUint::from(2u64),
            BigUint::from(3u64),
            // BigUint::from(1u64),
        ];
        let modulus = BigUint::from(13u64);
        assert_eq!(
            evaluate_polynomial_mod(BigUint::from(100u32), &coeffs, &modulus).unwrap(),
            BigUint::from(2u32)
        );
    }

    #[test]
    fn another_polynomial_eval() {
        // h(x)=21231311311+x*31982323219+x^(2)*98212312334+x^(3)*43284+x^(4)*9381391389
        let coeffs = vec![
            BigUint::from(21231311311u64),
            BigUint::from(31982323219u64),
            BigUint::from(98212312334u64),
            BigUint::from(43284u32),
            BigUint::from(9381391389u64),
        ];
        let modulus = BigUint::from(7124072u64);
        assert_eq!(
            evaluate_polynomial_mod(BigUint::from(0u32), &coeffs, &modulus).unwrap(),
            BigUint::from(1576751u64)
        );
        // assert_eq!(
        //     evaluate_polynomial_mod(BigUint::from(1u32), &coeffs, &modulus).unwrap(),
        //     BigUint::from(2828353u64)
        // );
        assert_eq!(
            evaluate_polynomial_mod(BigUint::from(2u32), &coeffs, &modulus).unwrap(),
            BigUint::from(4139197u64)
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
        // let mut rng = ChaCha8Rng::from_seed([0; 32]);
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

    #[test]
    fn from_crypto_to_num() {
        let p: U256 = generate_safe_prime(Some(256));
        // let value = 32;
        // let x = match value {
        //     ..=32 => U64::generate_safe_prime(Some(value)),
        //     _ => U
        // }

        // eprintln!("{:?}", p);
        let bytes = p.to_be_bytes();
        // eprintln!("{:?}", bytes);
        let nb_p = BigUint::from_bytes_be(&bytes);
        // eprintln!("{:?}", nb_p.to_bytes_be());

        for (a, b) in zip(p.to_be_bytes(), nb_p.to_bytes_be()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn generating_small_primes_errors() {
        assert!(generate_p_and_q(1).is_err());

        let (p, q) = generate_p_and_q(100).unwrap();

        assert!(p > BigUint::one());
        assert!(q > BigUint::one());

        eprintln!("{:?}", p.to_bytes_be());
        eprintln!("{:?}", q.to_bytes_be());
    }

    #[test]
    fn it_works() {
        let one = Checked::new(U256::ONE);
        let two = one + Checked::new(U256::from(1u8));

        // assert_eq!(two, Checked::new(U2048::from(2)));
        assert_eq!(two.0.unwrap(), U256::from(2u8));

        // let mut rng = ChaCha8Rng::from_seed([0; 32]);
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
        eprintln!("{:?}", BigUint::zero().cmp(&BigUint::one()));
        eprintln!("{:?}", BigUint::one().cmp(&BigUint::zero()));
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
        // sign_with_share(String::from("hello"), 1, &shares[0], pubkey);
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
        let l = 2;
        let k = 2;
        let t = 1;
        let bit_length = 512;
        let msg = String::from("hello");
        // dealer's part
        // let sk = key_gen(bit_length, l, k, t).unwrap();
        let sk = load_key().unwrap();
        let pubkey = sk.get_public();
        let shares = generate_secret_shares(&sk, l, k);
        let (v, verification_keys) = generate_verification(&pubkey, shares.clone());

        let delta = factorial(l);
        // distribute the shares
        // hash_all_the_things(&v, delta);

        let (x1, z, c) = sign_with_share(
            msg.clone(),
            delta,
            &shares[0],
            &pubkey,
            v.clone(),
            &verification_keys[0],
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x1);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg.clone(),
            v.clone(),
            delta,
            x1.clone(),
            &verification_keys[0],
            c,
            z,
            &pubkey,
        );
        assert!(verified);

        let (x2, z, c) = sign_with_share(
            msg.clone(),
            delta,
            &shares[1],
            &pubkey,
            v.clone(),
            &verification_keys[1],
        );
        // eprintln!("{:?}", shares[0]);
        // eprintln!("{:?}", x1);
        // eprintln!("{:?}", z);
        // eprintln!("{:?}", c);
        let verified = verify_proof(
            msg.clone(),
            v.clone(),
            delta,
            x2.clone(),
            &verification_keys[1],
            c,
            z,
            &pubkey,
        );
        assert!(verified);

        combine_shares(msg.clone(), delta, vec![x1.clone(), x2.clone()], &pubkey, l);
    }

    #[test]
    fn test_negating() {
        let mut one = BigUint::one().to_bigint().expect(""); // .to_bigint();
        negate_sign(&mut one);
        assert_eq!(
            BigUint::one().to_bigint().expect("").cmp(&one),
            Ordering::Greater
        );
    }

    #[test]
    fn power_to_negative() {
        let num = BigUint::from(123u8);
        let exp = BigUint::from(13u8);
        let modulus = BigUint::from(1231u16);

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
}
