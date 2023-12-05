use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::g2::{G2_GENERATOR_X, G2_GENERATOR_Y};
use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::{short_weierstrass::Projective, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
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
