#[cfg(test)]
mod tests {
    extern crate rust_rbe;

    use rust_rbe::rbe_asym;
    use rust_rbe::utils::{g1_rand, g2_rand};

    use ark_bn254::{Bn254, G1Projective as G1};
    use ark_ec::pairing::{Pairing, PairingOutput};
    type GT = PairingOutput<Bn254>;
    use num_traits::identities::Zero;

    #[test]
    fn test_simple_enc_dec() {
        // setup
        let capacity = 100;
        let id = 3;
        let (params, crs) = rbe_asym::setup(capacity);
        // let aux: Vec<Vec<G1>> = Vec::with_capacity(capacity);
        let mut pp: Vec<G1> = vec![G1::zero(); params.n];
        let id_bar = id % params.n;

        // keygen
        let (pk, sk, _a) = rbe_asym::gen(params, &crs, id).unwrap();
        assert_eq!(pk, crs.crs1[id_bar] * sk);

        // simulate registration
        let k = id / params.n as usize;
        pp[k] = pp[k] + pk;

        // enc
        let m: GT = Bn254::pairing(g1_rand(), g2_rand());
        let ct = rbe_asym::enc(params, &crs, pp, id, m);
        // dec
        let m_prime = rbe_asym::dec(params, &crs, id, sk, vec![G1::zero()], ct).unwrap();
        assert_eq!(m, m_prime);
    }
}
