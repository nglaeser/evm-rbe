# EVM Registration-Based Encryption

Efficient Registration-Based Encryption (RBE) [[GKMR23](eprint.iacr.org/2022/1505)] on Ethereum.

The core smart contract implementing the Key Curator is in `contracts/KeyCurator.sol`.

The remainder of the system is run off-chain in Rust, with computations implemented in `src/` and tested in `tests/`.

## Usage

## Credits

- EC arithmetic via [arkworks-rs](https://github.com/arkworks-rs), usage [here](https://github.com/Pratyush/algebra-intro)
- The Solidity library for EC precompiles and much of the repo structure was based on [a16z's powers of tau](https://github.com/a16z/evm-powers-of-tau/tree/master)