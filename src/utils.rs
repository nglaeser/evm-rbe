use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::g2::{G2_GENERATOR_X, G2_GENERATOR_Y};
use ark_bn254::{G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};

// get G1 generator
pub fn g1_generator() -> G1 {
    G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y).into()
}

// get G2 generator
pub fn g2_generator() -> G2 {
    G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y).into()
}
