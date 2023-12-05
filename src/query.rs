use ark_bn254::G1Projective as G1;
use ethers::abi::AbiDecode;
use ethers::prelude::{abigen, EthEvent, Filter, Http, Middleware, Provider, H160, U256};
use std::error::Error;
use std::sync::Arc;

use anyhow::Result;

use crate::utils;

abigen!(KC, "contracts/out/KeyCurator.sol/KeyCurator.json",);

#[derive(Debug, Clone, EthEvent)]
pub struct UserRegistered {
    pub registered_users: U256,
}

pub async fn query_new_aux_values(
    provider: &Provider<Http>,
    contract_address: H160,
    id: usize,
) -> Result<Vec<G1>> {
    let client = Arc::new(provider);

    let filter = Filter::new().address(contract_address);

    let mut logs = client.get_logs(&filter).await?;
    println!("{} new registrations", logs.iter().len());
    for log in logs.iter() {
        println!("{:?}", log);
    }
    loop {
        let tx_hash = logs
            .pop()
            .ok_or(QueryError)?
            .transaction_hash
            .ok_or(QueryError)?;

        let tx = client.get_transaction(tx_hash).await?.ok_or(QueryError)?;
        let receipt = client
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or(QueryError)?;

        if receipt.status.ok_or(QueryError)?.as_usize() == 0 {
            continue;
        }

        let decoded_input = RegisterCall::decode(&tx.input)?;
        let helping_values: Vec<G1> = decoded_input
            .helping_value_bytes
            .iter()
            .map(|g1| utils::contract_bytes_to_g1(g1))
            .collect();

        return Ok(helping_values);
    }
}

pub async fn get_deployment_events(provider: &Provider<Http>, contract_address: H160) {
    let client = Arc::new(provider);

    let filter = Filter::new()
        .address(contract_address)
        .event("ContractDeployed(uint,uint,uint)");

    let mut logs = client.get_logs(&filter).await;
    for log in logs.iter() {
        println!("{:?}", log);
    }
}

/***** copied from https://github.com/a16z/evm-powers-of-tau *****/
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct QueryError;

impl Error for QueryError {
    fn description(&self) -> &str {
        "Query failure".as_ref()
    }
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
