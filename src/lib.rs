// Practical Threshold Signatures, Victor Shoup, 2000
// NOTE: what is the difference between # and #!?
#![allow(unused_imports)]
// use errors::{Error, Result};
use num_bigint::*;
// use num_modular::*;
use crypto_bigint::*;
use crypto_primes::*;
// use num_prime::nt_funcs::*;
use num_traits::{One, Zero};
use rand::prelude::*;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};
use rand_core::CryptoRngCore;
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn generate_primes(modulus_bit_length: usize) -> (U2048, U2048) {
    let p: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
    let mut q: U2048 = generate_safe_prime(Some(modulus_bit_length / 2));
    while p == q {
        q = generate_safe_prime(Some(modulus_bit_length / 2));
    }
    (p, q)
}

#[derive(Debug)]
pub struct RSAThresholdPrivateKey {
    p: U2048,
    q: U2048,
    d: U4096,
    m: U4096,
    e: U4096,
}

#[derive(Debug)]
pub struct RSAThresholdPublicKey {
    n: U4096,
    e: U4096,
}

impl RSAThresholdPrivateKey {
    fn get_public(&self) -> RSAThresholdPublicKey {
        RSAThresholdPublicKey {
            n: self.p * self.q,
            e: self.e,
        }
    }
}

/// `n_parties` equals the `l` parameter from the paper
pub fn key_gen(bit_length: usize, l: usize, k: usize, t: usize) -> RSAThresholdPrivateKey {
    // FIXME add bounds on l, k and t
    let (p, q) = generate_primes(bit_length);
    let e: U4096 = U4096::from_u32(0x10001);
    // FIXME worry about the sizes later
    // if l > e {
    //     println!(
    //         "The number of parties: {} is greater than expected ({})",
    //         l, e
    //     );
    //     panic!();
    // };

    let n = p * q;
    let one = Uint::ONE;
    // FIXME remove unwraps
    // shift right by one to divide by 2
    let pp = p.checked_sub(&one).unwrap().shr_vartime(1);
    let qq = q.checked_sub(&one).unwrap().shr_vartime(1);

    let m: U4096 = pp * qq;

    println!("p: {}", p);
    println!("m: {}", m.bits());

    RSAThresholdPrivateKey {
        p: p,
        q: q,
        d: e.inv_odd_mod(&n).0,
        m: m,
        e: e,
    }
}

fn nm_evaluate_polynomial_mod(value: BigUint, coeffs: &Vec<BigUint>, modulus: &BigUint) -> BigUint {
    let mut result = BigUint::zero();
    let mut x: BigUint;
    // NOTE is cloning necesary here?
    let mut bk: BigUint = coeffs[coeffs.len() - 1].clone();
    // let mut bk: BigUint = coeffs[coeffs.len() - 1].clone();
    for i in (0..=coeffs.len() - 2).rev() {
        bk = bk * &value + &coeffs[i];
    }
    // FIXME doing modulus like this seems very fishy
    let rem = bk.modpow(&BigUint::one(), modulus);
    rem
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
    let mut a_coeffs = vec![U2048::ONE; k];
    // generate random coefficients
    let mut rng = ChaCha20Rng::from_entropy();
    let modulus = NonZero::from_uint(key.m);
    let mut a_coeffs: Vec<U4096> = a_coeffs
        .iter()
        .map(|a| U4096::random_mod(&mut rng, &modulus))
        .collect();

    a_coeffs[0] = key.d;

    let nbi_a_coeffs: Vec<BigUint> = a_coeffs
        .iter()
        .map(|a| BigUint::from_bytes_be(&a.to_be_bytes()))
        .collect();

    let nbi_m = BigUint::from_bytes_be(&key.m.to_be_bytes());

    let mut shares: Vec<BigUint> = vec![];
    for i in 1..=l {
        shares.push(nm_evaluate_polynomial_mod(i.into(), &nbi_a_coeffs, &nbi_m));
    }
    shares
}

fn generate_verification(key: RSAThresholdPrivateKey) {
    // FIXME
    // gen_biguint_below(key.
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};

    #[test]
    fn test_evaluate_polynomial() {
        // let modulus = U4096::from_u32(64);
        // let coeffs = vec![U4096::ONE; 32];
        let coeffs = vec![
            BigUint::from(17u32),
            BigUint::from(63u32),
            BigUint::from(127u32),
        ];
        let modulus = BigUint::from(127u32);
        assert_eq!(
            nm_evaluate_polynomial_mod(BigUint::from(2u32), &coeffs, &modulus),
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
        println!("{:?}", sk.get_public());
    }

    #[test]
    fn gen_shares() {
        let l = 3;
        let k = 2;
        let t = 1;
        let bit_length = 128;
        let sk = key_gen(bit_length, l, k, t);
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
    fn from_crypto_to_num() {
        let p: U4096 = generate_safe_prime(Some(32));

        println!("{:?}", p);
        let bytes = p.to_be_bytes();
        println!("{:?}", bytes);
        println!("{:?}", BigUint::from_bytes_be(&bytes));
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
}
