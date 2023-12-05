use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::g2::{G2_GENERATOR_X, G2_GENERATOR_Y};
use ark_bn254::{Fq, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{short_weierstrass::Projective, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ethers::prelude::*;
use rand::thread_rng;
use std::convert::Into;

// get G1 generator
pub fn g1_generator() -> G1 {
    G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y).into()
}

// get G2 generator
pub fn g2_generator() -> G2 {
    G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y).into()
}

// random G1 element
pub fn g1_rand() -> G1 {
    let rng = &mut thread_rng();
    let r = Fr::rand(rng);
    g1_generator() * r
}

// random G2 element
pub fn g2_rand() -> G2 {
    let rng = &mut thread_rng();
    let r = Fr::rand(rng);
    g2_generator() * r
}

/***** from github.com/a16z/evm-powers-of-tau/src/utils.rs *****/
pub trait IntoBytes {
    fn serialize(self) -> Vec<u8>;
    fn into_bytes(self) -> ethers::prelude::Bytes;
}

impl<P: ark_ec::short_weierstrass::SWCurveConfig> IntoBytes for Projective<P> {
    fn serialize(self) -> Vec<u8> {
        let affine = self.into_affine();
        let mut serialized = Vec::new();
        affine.serialize_compressed(&mut serialized).unwrap();
        // let mut serialized = affine.x.to_bytes_le.unwrap();
        // let mut serialized_y = ark_ff::to_bytes!(affine.y).unwrap();
        // serialized.reverse();
        // serialized_y.reverse();
        // serialized.extend(serialized_y);
        serialized
    }

    fn into_bytes(self) -> ethers::prelude::Bytes {
        ethers::prelude::Bytes::from(self.serialize())
    }
}

pub fn contract_bytes_to_g1(b: &Bytes) -> G1 {
    assert!(b.len() == 64);
    let mut x_b = Vec::with_capacity(32);
    let mut y_b = Vec::with_capacity(32);

    for i in 0..32 {
        x_b.push(b.get(i).unwrap().clone());
    }
    for i in 32..64 {
        y_b.push(b.get(i).unwrap().clone());
    }
    let x = Fq::from_be_bytes_mod_order(x_b.as_slice());
    let y = Fq::from_be_bytes_mod_order(y_b.as_slice());

    // return projective representation
    G1Affine::new(x, y).into_group()
}
