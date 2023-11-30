use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::g2::{G2_GENERATOR_X, G2_GENERATOR_Y};
use ark_bn254::{Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
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
