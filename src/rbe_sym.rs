use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ec::pairing::{Pairing, PairingOutput as GT};
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use rand::thread_rng;

use crate::utils;

pub struct Params {
    pub N: usize,
    pub n: usize,
    pub B: usize,
    pub g: G1,
}

pub struct CText(G1, GT<Bn254>, G1, GT<Bn254>);

// Generate CRS (punctured powers of tau)
pub fn setup(secparam: usize, N: usize) -> (Params, Vec<G1>) {
    let g1_generator: G1 = utils::g1_generator();

    // sample CRS trapdoor tau
    let rng = &mut thread_rng();
    let tau = Fr::rand(rng);
    let mut power_of_tau: Fr = tau;

    // compute powers of tau CRS
    let n = (N as f64).sqrt() as usize;
    let B = N / n as usize;
    let mut crs: Vec<G1> = Vec::with_capacity(2 * n - 1);
    let mut j = 1; // counter which skips n+1
    for i in 1..(2 * n + 1) {
        if j != n + 1 {
            // the (n+1)th power is punctured out
            crs.push(g1_generator * power_of_tau);
        }
        power_of_tau = power_of_tau * tau;
        j = j + 1;

        assert!(crs[j].into_affine().is_on_curve());
        assert!(crs[j]
            .into_affine()
            .is_in_correct_subgroup_assuming_on_curve());
    }
    // save parameters
    let params = Params {
        N,
        n,
        B,
        g: g1_generator,
    };

    (params, crs)
}

// KeyGen algorithm
pub fn gen(params: Params, crs: Vec<G1>, id: usize) -> Option<(G1, Fr, Vec<G1>)> {
    // check id is in range [1, N]
    if id < 1 || id > params.N {
        return None;
    }
    let id_bar = id % params.n + 1;

    // sample sk, pk
    let rng = &mut ark_std::rand::thread_rng();
    let sk = Fr::rand(rng);
    let pk = crs[id_bar - 1] * sk;

    // compute helping values
    // let crs_slice: Vec<G1> = crs[id_bar - 1..id_bar - 1 + params.n - 1].iter().collect();
    let a = crs[id_bar - 1..id_bar - 1 + params.n - 1]
        .iter()
        .map(|h| *h * sk)
        .collect();

    Some((pk, sk, a))
}

// Encryption algorithm TODO
/*
pub fn enc(params: Params, crs: Vec<G1>, pp: Vec<G1>, id: usize, m: GT<Bn254>) -> CText {
    let id_bar = id % params.n + 1;
    let k = id / params.n as usize;

    // sample randomness
    let rng = &mut ark_std::rand::thread_rng();
    let r = Fr::rand(rng);

    // compute ciphertext
    CText(
        pp[k],
        Bn254::pairing(pp[k], crs[params.n - id_bar]) * r, // TODO symmetric
        params.g * r,
        Bn254::pairing(crs[id_bar - 1], crs[params.n - id_bar]) * r + m, // TODO symmetric
    )
}
*/
