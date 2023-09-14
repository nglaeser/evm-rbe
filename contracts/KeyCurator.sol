// SPDX-License-Identifier: MIT

pragma solidity >=0.8.16;

import "../lib/ec-crypto/AltBn128.sol";

/**
 * @title KeyCurator
 * @dev Run Key Curator of [GKMR18] RBE construction
 */
contract KeyCurator {
    uint256 number;
    uint256 public constant SYSTEM_CAPACITY = 600000;
    uint256 public constant NUM_BUCKETS = 775;
    uint256 public constant BUCKET_SIZE = 775;

    uint256 public registeredUsers = 0;

    // storage
    AltBn128.G1Point[NUM_BUCKETS] public pp;
    AltBn128.G1Point[2 * BUCKET_SIZE - 1] public crs;

    event UserRegistered(uint256 registeredUsers);

    /**
     * @dev Register a user in the RBE system
     * @param id registering user's identity string
     * @param pk registering user's public key
     * @param helping_values helping values derived from crs and sk
     */
    function register(uint256 id, AltBn128.G1Point calldata pk, AltBn128.G1Point[] calldata helping_values) public {
        require(helping_values.length == BUCKET_SIZE - 1);
        require(id >= 0 && id < SYSTEM_CAPACITY); // TODO allow id to be a bytes32 and map it to a uint

        // TODO check helping_values
        // e(pk, crs[n-1]) = e(a[n-1], g) = e(a[n-2], crs[0]) = ... = e(a[0], crs[n-2])

        // update public parameters
        if (pp[id].x == 0 && pp[id].y == 0) {
            pp[id] = pk;
        } else {
            pp[id] = AltBn128.g1Add(pp[id], pk);
        }

        registeredUsers += 1;
        emit UserRegistered(registeredUsers);
    }
}
