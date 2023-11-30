use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::pairing::{Pairing, PairingOutput as GT};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::UniformRand;
use rand::thread_rng;

use crate::utils;

#[derive(Clone, Copy)]
pub struct Params {
    pub capacity: usize,
    pub n: usize,
    pub num_blocks: usize,
}

#[derive(Clone, Copy)]
pub struct CText(G1, GT<Bn254>, G2, GT<Bn254>);

// #[derive(Clone)]
pub struct CRS {
    pub crs1: Vec<G1>,
    pub crs2: Vec<G2>,
}

// Generate CRS (punctured powers of tau)
pub fn setup(capacity: usize) -> (Params, CRS) {
    let g1_generator: G1 = utils::g1_generator();
    let g2_generator: G2 = utils::g2_generator();

    // sample CRS trapdoor tau
    let rng = &mut thread_rng();
    let tau = Fr::rand(rng);
    let mut power_of_tau: Fr = tau;

    // compute powers of tau CRS
    let n = (capacity as f64).sqrt() as usize;
    let num_blocks = capacity / n as usize;
    let mut crs1: Vec<G1> = Vec::with_capacity(2 * n - 1);
    let mut crs2: Vec<G2> = Vec::with_capacity(2 * n - 1);
    for i in 0..(2 * n) {
        if i == n {
            // the (n+1)th power is punctured out
            crs1.push(g1_generator);
            crs2.push(g2_generator);
        } else {
            crs1.push(g1_generator * power_of_tau);
            crs2.push(g2_generator * power_of_tau);

            // sanity checks
            assert!(crs1[i].into_affine().is_on_curve());
            assert!(crs1[i]
                .into_affine()
                .is_in_correct_subgroup_assuming_on_curve());
            assert!(crs2[i].into_affine().is_on_curve());
            assert!(crs2[i]
                .into_affine()
                .is_in_correct_subgroup_assuming_on_curve());
        }

        power_of_tau = power_of_tau * tau;
    }
    // save parameters
    let params = Params {
        capacity,
        n,
        num_blocks,
    };

    (params, CRS { crs1, crs2 })
}

// KeyGen algorithm
pub fn gen(params: Params, crs: &CRS, id: usize) -> Option<(G1, Fr, Vec<G1>)> {
    // check id is in range [1, N]
    if id < 1 || id > params.capacity {
        return None;
    }
    let id_bar = id % params.n;

    // sample sk, pk
    let rng = &mut ark_std::rand::thread_rng();
    let sk = Fr::rand(rng);
    let pk = crs.crs1[id_bar] * sk;

    // compute helping values
    // let crs_slice: Vec<G1> = crs[id_bar..id_bar + params.n - 1].iter().collect();
    let a = crs.crs1[id_bar..id_bar + params.n - 1]
        .iter()
        .map(|h| *h * sk)
        .collect();

    Some((pk, sk, a))
}

// Encryption algorithm
pub fn enc(params: Params, crs: &CRS, pp: Vec<G1>, id: usize, m: GT<Bn254>) -> CText {
    let id_bar = id % params.n;
    let k = id / params.n as usize;

    // sample randomness
    let rng = &mut ark_std::rand::thread_rng();
    let r = Fr::rand(rng);

    // compute ciphertext
    CText(
        pp[k],
        Bn254::pairing(pp[k], crs.crs2[params.n - id_bar]) * r,
        utils::g2_generator() * r,
        Bn254::pairing(crs.crs1[id_bar], crs.crs2[params.n - id_bar]) * r + m,
    )
}

// Fetch updates since blocknum from chain
pub fn update(blocknum: usize, id: usize) -> Vec<G1> {
    // TODO
    vec![]
}

// Decryption algorithm
pub fn dec(
    params: Params,
    crs: &CRS,
    id: usize,
    sk: Fr,
    u: Vec<G1>,
    ct: CText,
) -> Option<GT<Bn254>> {
    let id_bar = id % params.n;

    // find correct aux element to use
    let mut l = None;
    for item in u {
        let lhs = Bn254::pairing(ct.0, crs.crs2[params.n - id_bar]);
        let rhs = Bn254::pairing(item, utils::g2_generator())
            + Bn254::pairing(crs.crs1[id_bar] * sk, crs.crs2[params.n - id_bar]);
        if lhs == rhs {
            l = Some(item);
            break;
        }
    }
    // no fitting element found - requires update
    if l == None {
        return None;
    }
    let l = l.unwrap();

    let mut denom = ct.1 - Bn254::pairing(l, ct.2);
    denom = denom * sk.inverse().unwrap();
    let decrypted = ct.3 - denom;

    Some(decrypted)
}
