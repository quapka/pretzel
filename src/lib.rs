// Practical Threshold Signatures, Victor Shoup, 2000
// NOTE: what is the difference between # and #!?
#![allow(unused_imports)]
// use errors::{Error, Result};
#[cfg(not(test))]
use log::info;

use num_bigint::*;
#[cfg(test)]
use std::{println as info, println as warn};
use thiserror::Error;
// use std::error::Error
// use num_modular::*;
use crypto_bigint::*;
use crypto_primes::*;
// use num_prime::nt_funcs::*;
use num_integer::Integer;
use num_traits::{CheckedSub, One, Zero};
use rand::prelude::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};
use rand_core::CryptoRngCore;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::any::type_name;
use std::cmp::Ordering;
use std::ops::{Div, Mul, Shr};

// pub fn generate_primes(modulus_bit_length: usize) -> (U2048, U2048) {
//     let p: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
//     let mut q: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
//     while p == q {
//         q = generate_safe_prime(Some(modulus_bit_length / 2));
//     }
//     (p, q)
// }

#[derive(Debug)]
pub struct RSAThresholdPrivateKey {
    p: BigUint,
    q: BigUint,
    d: BigUint,
    m: BigUint,
    e: BigUint,
}

#[derive(Debug)]
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

// impl RSAThresholdPrivateKey {
//     fn get_public(&self) -> RSAThresholdPublicKey {
//         RSAThresholdPublicKey {
//             n: self.p * self.q,
//             e: self.e,
//         }
//     }
// }
//
// fn print_type_of<T>(_: &T) {
//     println!("{:?}", std::any::type_name::<T>())
// }

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

    let d: BigUint = match dd.to_biguint() {
        Some(value) => value,
        None => return Err(KeyGenError::NoInverse),
    };

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
        prev = prev * &value + next;
    }
    let rem = prev.mod_floor(modulus);
    Ok(rem)
}

// fn evaluate_polynomial_mod(value: U4096, coeffs: Vec<U4096>, modulus: U4096) -> U4096 {
//     let mut result = U4096::ZERO;
//     let ui = U4096::from_u32(i.try_into().unwrap());
//     for i in 1..=coeffs.len() {
//         println!("{}", i);
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

fn generate_secret_shares(key: RSAThresholdPrivateKey, l: usize, k: usize) -> Vec<BigUint> {
    // generate random coefficients
    let mut rng = ChaCha20Rng::from_entropy();
    let mut a_coeffs: Vec<BigUint> = (1..=(k - 1))
        .map(|_| rng.gen_biguint_below(&key.m))
        .collect();
    // fix a_0 to the private exponent
    a_coeffs[0] = key.d;
    // calculate the individual shares
    let shares: Vec<BigUint> = (1..=l)
        .map(|i| evaluate_polynomial_mod(i.into(), &a_coeffs, &key.m).unwrap())
        .collect();
    shares
}

fn generate_verification(key: RSAThresholdPrivateKey) {
    // FIXME
    // gen_biguint_below(key.
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
    fn gen_keys() {
        // generate_primes(32);
        let l = 3;
        let k = 2;
        let t = 1;
        let bit_length = 32;
        let sk = key_gen(bit_length, l, k, t);
        // println!("{:?}", sk.get_public());
    }

    #[test]
    fn gen_shares() {
        let l = 3;
        let k = 2;
        let t = 1;
        let bit_length = 128;
        let sk = key_gen(bit_length, l, k, t).unwrap();
        let shares = generate_secret_shares(sk, l, k);
        println!("shares: {:?}", shares);
    }

    #[test]
    fn is_safep_prime() {
        // let mut rng = ChaCha8Rng::from_seed([0; 32]);
        let mut rng = ChaCha20Rng::from_entropy();
        let p = rng.gen_prime(128);
        println!("{}", p);
        // println!("{:?}", p.to_bytes_be());
        let mut cp = U128::from_be_slice(&p.to_bytes_be());

        println!("{:?}", is_safe_prime(&cp));
        println!("{}", cp);
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

        // println!("{:?}", p);
        let bytes = p.to_be_bytes();
        // println!("{:?}", bytes);
        let nb_p = BigUint::from_bytes_be(&bytes);
        // println!("{:?}", nb_p.to_bytes_be());

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

        println!("{:?}", p.to_bytes_be());
        println!("{:?}", q.to_bytes_be());
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
        // println!("{}", key.bits());
    }

    #[test]
    fn test_ordering() {
        println!("{:?}", BigUint::zero().cmp(&BigUint::one()));
        println!("{:?}", BigUint::one().cmp(&BigUint::zero()));
    }
}
