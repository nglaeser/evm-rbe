use ark_bn254::{G1Projective as G1, G2Projective as G2};
use ethers::{
    middleware::SignerMiddleware,
    prelude::*,
    utils::{Anvil, AnvilInstance},
};
use rust_rbe::{query, rbe_asym, utils};
use std::{sync::Arc, time::Duration};
use utils::IntoBytes;

const SYSTEM_CAPACITY: usize = 100;
const NUM_BUCKETS: usize = 10;
const BUCKET_SIZE: usize = 10;

abigen!(KC, "contracts/out/KeyCurator.sol/KeyCurator.json",);

#[tokio::test(flavor = "multi_thread")]
async fn primary() {
    let (contract, anvil, (capacity, init_crs1, init_crs2)) = launch_integration().await;
    // TODO continue...
}

/***** copied from https://github.com/a16z/evm-powers-of-tau *****/
async fn launch_integration() -> (
    kc::KC<SignerMiddleware<ethers::providers::Provider<ethers::providers::Http>, LocalWallet>>,
    AnvilInstance,
    (usize, Vec<G1>, Vec<G2>),
) {
    let anvil = Anvil::new().spawn();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .expect("Failed to create provider")
        .interval(Duration::from_millis(10u64));

    let anvil_chain_id = provider.get_chainid().await.unwrap();
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(anvil_chain_id.as_u64()));
    let client = Arc::new(client);

    let (sysparams, crs) = rbe_asym::setup(SYSTEM_CAPACITY);

    let init_crs1_serial: Vec<Bytes> = crs.crs1.iter().map(|item| item.into_bytes()).collect();
    let init_crs2_serial: Vec<Bytes> = crs.crs2.iter().map(|item| item.into_bytes()).collect();

    let constructor_params: (u32, Vec<Bytes>, Vec<Bytes>) = (
        sysparams.capacity as u32,
        init_crs1_serial,
        init_crs2_serial,
    );
    (
        KC::deploy(client, constructor_params)
            .unwrap()
            .legacy()
            .send()
            .await
            .unwrap(),
        anvil,
        (sysparams.capacity, crs.crs1, crs.crs2),
    )
}
