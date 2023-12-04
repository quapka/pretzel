use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pretzel::*;
// use errors::{Error, Result};
use sha2::{Digest, Sha256};

use num_bigint::*;
use std::path::PathBuf;

#[cfg(test)]
use thiserror::Error;
use crypto_bigint::*;
use crypto_primes::*;
use std::iter::zip;
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

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Result as SerdeResult, Value};
use std::any::type_name;
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Add, Div, Mul, MulAssign, Neg, Shr};
use std::str::FromStr;

fn criterion_benchmark(c: &mut Criterion) {
    let coeffs = vec![
        BigUint::from(21231311311u64),
        BigUint::from(31982323219u64),
        BigUint::from(98212312334u64),
        BigUint::from(43284u32),
        BigUint::from(9381391389u64),
    ];
    let modulus = BigUint::from(7124072u64);
    c.bench_function("evaluate_polynomial", |b| {
        b.iter(|| evaluate_polynomial_mod(BigUint::from(0u32), &coeffs, &modulus))
    });
    c.bench_function("evaluate_polynomial", |b| {
        b.iter(|| evaluate_polynomial_mod(BigUint::from(2u32), &coeffs, &modulus))
    });

    let l = 2;
    let k = 2;
    // let t = k - 1;
    let bit_length = 256;
    let pad = PaddingScheme::PKCS1v15;
    let sk = load_key().unwrap();

    let pubkey = RSAThresholdPublicKey::from(&sk);
    let shares = generate_secret_shares(&sk, l, k);
    c.bench_function("generate_secret_shares", |b| {
        b.iter(|| generate_secret_shares(&sk, l, k))
    });
    let (v, verification_keys) = generate_verification(&pubkey, shares.clone());
    c.bench_function("generate_verification", |b| {
        b.iter(|| generate_verification(&pubkey, shares.clone()))
    });

    let delta = factorial(l);
    c.bench_function("factorial", |b| b.iter(|| factorial(l)));

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
            &v,
            &vkey,
            pad.clone(),
        );
        c.bench_function("sign_with_share", |b| {
            b.iter(|| {
                sign_with_share(
                    msg,
                    delta,
                    &share,
                    &v,
                    &vkey,
                    pad.clone(),
                )
            })
        });
        sign_shares.push(signed_share.clone());
        let verified = verify_proof(
            msg,
            &v,
            delta,
            &vkey,
            &signed_share,
            &pubkey.n,
            pubkey.bytes_size,
            pad.clone(),
        );
        c.bench_function("verify_proof", |b| {
            b.iter(|| {
                verify_proof(
                    msg,
                    &v,
                    delta,
                    &vkey,
                    &signed_share,
                    &pubkey.n,
                    pubkey.bytes_size,
                    pad.clone(),
                )
            })
        });
        assert!(verified);
    }

    let signature = combine_shares(msg, delta, sign_shares.clone(), &shares[0], l, pad.clone());
    c.bench_function("combine_shares", |b| {
        b.iter(|| combine_shares(msg, delta, sign_shares.clone(), &shares[0], l, pad.clone()))
    });
    let n = (sk.p.clone() * sk.q.clone());
    let r_privkey =
        RsaPrivateKey::from_components(n.clone(), sk.e, sk.d, vec![sk.p.clone(), sk.q.clone()])
            .expect("");
    let r_pub = r_privkey.to_public_key();
    assert_eq!(
        r_pub.verify(
            Pkcs1v15Sign::new_unprefixed(),
            &msg,
            &signature.unwrap(),
        ),
        Ok(()),
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
