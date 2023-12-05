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
    /*** deploy contract (setup) ***/
    let (contract, anvil, (sysparams, crs)) = launch_integration().await;

    /*** Register party 1 (id = 5) ***/
    let id: U256 = U256::from(5);

    // keygen
    let (pk, sk, a) = rbe_asym::gen(sysparams, &crs, 5).unwrap();
    let a_serial: Vec<Bytes> = a.iter().map(|item| item.into_bytes()).collect();

    // call contract
    let tx = contract.register(id, pk.into_bytes(), a_serial);
    let pending_tx = tx.send().await;
    // Unwrap will panic if tx reverts
    let wait = pending_tx.unwrap().await;
    let receipt = wait.unwrap().unwrap();
    assert_eq!(receipt.status.unwrap().as_usize(), 1);
    println!("Update 1 gas usage: {}gwei", receipt.cumulative_gas_used);

    /*** check contract storage updated correctly ***/
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .expect("Failed to create provider")
        .interval(Duration::from_millis(10u64));
    let query_result = query::query_new_aux_values(&provider, contract.address(), 1).await;
    let queried_aux: Vec<G1> = query_result.unwrap();
    assert_eq!(queried_aux, a);

    // Clean
    drop(anvil);
}

/***** copied from https://github.com/a16z/evm-powers-of-tau *****/
async fn launch_integration() -> (
    kc::KC<SignerMiddleware<ethers::providers::Provider<ethers::providers::Http>, LocalWallet>>,
    AnvilInstance,
    (rbe_asym::Params, rbe_asym::CRS),
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
    assert!(init_crs1_serial.len() == init_crs2_serial.len());
    println!("CRS1 length: {}", init_crs1_serial.len());

    let constructor_params: (U256, Vec<Bytes>, Vec<Bytes>) = (
        U256::from(sysparams.capacity),
        init_crs1_serial,
        init_crs2_serial,
    );
    let deploy_result = KC::deploy(client.clone(), constructor_params.clone());
    // query::get_deployment_events(&provider, deploy_result.unwrap().address()).await;
    println!(
        "{:?}",
        deploy_result.unwrap() // .legacy()
                               // .send_with_receipt()
                               // .await
                               // .unwrap_err()
    );
    (
        KC::deploy(client, constructor_params)
            .unwrap()
            .legacy()
            .send()
            .await
            .unwrap(),
        anvil,
        (sysparams, crs),
    )
}
