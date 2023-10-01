// Practical Threshold Signatures, Victor Shoup, 2000
// NOTE: what is the difference between # and #!?
#![allow(unused_imports)]
// use errors::{Error, Result};
use num_bigint::{BigUint, RandPrime};
// use num_modular::*;
use num_prime::nt_funcs::*;
use num_traits::{One, Zero};
use rand_core::CryptoRngCore;
use rsa::RsaPrivateKey, RsaPublicKey;
user crypto_prime::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

// pub fn key_gen<R: CryptoRngCore + ?Sized>(rng: &mut R, modulus: usize) -> BigUint {
//     rng.gen_prime(modulus)
// }


pub fn generate_primes(modulus_bit_length: usize) -> (Uint, Uint) {
    let p = generate_safe_prime(modulus_bit_length / 2);
    let q = generate_safe_prime(modulus_bit_length / 2);
    while p == q {
        let q = generate_safe_prime(modulus_bit_length / 2);
    }
    p, q
}


pub struct RSAThresholdPrivateKey {
    p: Uint,
    q: Uint,
    d: Uint,
    m: Uint
}

pub struct RSAThresholdPublicKey {
    n: Uint,
    e: Uint,
}


/// `n_parties` equals the `l` parameter from the paper
pub fn key_gen(bit_length: usize, l: usize, k: usize, t:usize) -> () {
    // FIXME add bounds on l, k and t
    let p, q = generate_primes(bit_length);
    let e = 0x10001;
    if l > e {
        println!("The number of parties: {} is greater than expected ({})", l, e);
        panic!();
    }

    let n = p * q:
    let m = ((p - 1) / 2) * ((q - 1) / 2);

    let sk = RSAThresholdPrivateKey {
        p: p,
        q: q,
        d: e.inv_mod_odd(n),
        m: m,
    };

    let pk = RSAThresholdPublicKey {
        n: n,
        e e,
    };
}

fn generate_secret_shares(key: RSAThresholdPrivateKey, k:usize ) {
    let mut a_coeffs = vec![Uint::ONE, k];
    // generate random coefficients
    let a_coeffs: Vec<Uint> = v1.iter().map(|a| gen_range(0, key.m).collect();
    // make sure the constant one is `d`
    let a_coeffs[0] = key.d;

    let mut s
    // for a_seq.iter()
    //     gen_range(0, key.m);

}

// /// `p` is a safe prime if (p - 1) / 2 is also a prime
// fn generate_safe_prim<R: CryptoRngCore + ?Sized>(rng: &mut R) -> BigUint {
//     loop {
//         let candidate = rng.gen_prime(128);
//         if is_safe_prime(&candidate) {
//             return candidate;
//         }
//     }
// }
//
//

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng, ChaCha8Rng};

    #[test]
    fn it_works() {
        // let mut rng = ChaCha8Rng::from_seed([0; 32]);
        // let mut rng = ChaCha20Rng::from_entropy();
        // let modulus = 2048;
        // let key = key_gen(&mut rng, modulus);
        // println!("{}", key.bits());
    }
}
