use ethers::prelude::{abigen, Contract, EthEvent, Filter, Http, Middleware, Provider, H160, U256};
use std::sync::Arc;

abigen!(KC, "contracts/out/KeyCurator.sol/KeyCurator.json",);

#[derive(Debug, Clone, EthEvent)]
pub struct UserRegistered {
    pub registered_users: U256,
}

pub async fn query_new_aux_values(provider: &Provider<Http>, contract_address: H160, id: usize) {
    let client = Arc::new(provider);

    let filter = Filter::new().address(contract_address);

    let mut logs = client.get_logs(&filter).await;
    println!("{} new registrations", logs.iter().len());
    for log in logs.iter() {
        println!("{:?}", log);
    }
}
