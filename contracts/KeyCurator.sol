// SPDX-License-Identifier: MIT

pragma solidity >=0.8.16;

import "./lib/ec-crypto/AltBn128.sol";

/**
 * @title KeyCurator
 * @dev Run Key Curator of [GKMR18] RBE construction
 */
contract KeyCurator {
    uint256 number;
    // uint256 public constant SYSTEM_CAPACITY = 600000;
    // uint256 public constant NUM_BUCKETS = 775;
    // uint256 public constant BUCKET_SIZE = 775;
    uint public system_capacity;
    uint public num_buckets;
    uint public bucket_size;

    uint256 public registeredUsers = 0;

    // storage
    // AltBn128.G1Point[NUM_BUCKETS] public pp;
    // AltBn128.G1Point[2 * BUCKET_SIZE - 1] public crs1;
    AltBn128.G1Point[] public pp;
    AltBn128.G1Point[] public crs1;
    AltBn128.G2Point[] public crs2;

    event UserRegistered(uint256 registeredUsers);

    /**
     * @dev Set up the RBE system (asymmetric)
     * @param crs1_bytes common reference string (punctured powers of tau) in G1
     * @param crs2_bytes copy of crs1 in G2
     */
    constructor(uint N, bytes[] memory crs1_bytes, bytes[] memory crs2_bytes) {
        require(crs1.length == crs2.length);
        // crs1.length = 2 * num_buckets - 1
        num_buckets = (crs1.length + 1) / 2;
        system_capacity = N;
        bucket_size = uint(system_capacity / num_buckets);

        uint256 i;
        for (i = 0; i < crs1.length; ++i) {
            crs1.push(AltBn128.g1Unmarshal(crs1_bytes[i]));
            crs2.push(AltBn128.g2Unmarshal(crs2_bytes[i]));
        }
    }

    /**
     * @dev Register a user in the RBE system
     * @param id registering user's identity string
     * @param pkBytes registering user's public key (compressed G1 in bytes)
     * @param helpingValueBytes helping values derived from crs and sk (compressed G1 in bytes)
     */
    function register(
        uint256 id,
        bytes calldata pkBytes,
        bytes[] calldata helpingValueBytes
    ) public {
        AltBn128.G1Point[] memory helpingValues = new AltBn128.G1Point[](
            helpingValueBytes.length
        );
        for (uint i = 0; i < helpingValues.length; i++) {
            helpingValues[i] = AltBn128.g1Unmarshal(helpingValueBytes[i]);
        }
        AltBn128.G1Point memory pk = AltBn128.g1Unmarshal(pkBytes);

        require(helpingValues.length == bucket_size - 1);
        require(id >= 0 && id < system_capacity); // TODO allow id to be a bytes32 and map it to a uint
        uint256 id_bar = id % bucket_size;

        /***** pairing check *****
         * check helping_values with pairing check:
         * e(pk, crs[n-1]) = e(a[n-1], g) = e(a[n-2], crs[0]) = ... = e(a[0], crs[n-2])
         */
        require(verifyHelpingValues(id_bar, helpingValues, crs2, pk));

        /***** update public parameters *****/
        if (pp[id_bar].x == 0 && pp[id_bar].y == 0) {
            // if pp bucket uninitialized
            pp[id_bar] = pk;
        } else {
            pp[id_bar] = AltBn128.g1Add(pp[id_bar], pk);
        }

        registeredUsers += 1;
        emit UserRegistered(registeredUsers);
    }

    function verifyHelpingValues(
        uint256 id_bar,
        AltBn128.G1Point[] memory helpingValues,
        AltBn128.G2Point[] memory crs,
        AltBn128.G1Point memory pk
    ) public view returns (bool) {
        // precompile for asymmetric multipairing check:
        // multipairing(a1^r1, b1, a2^(r2-r1), b2, ..., ak^(rk-r(k-1)), bk)
        // TODO multipairing in *symmetric* group would be more efficient but no precompile
        bytes memory payload = new bytes(bucket_size);
        bytes32 pk_bytes = AltBn128.g1Compress(pk);
        bytes memory crs_last_bytes = AltBn128.g2Compress(
            (crs[bucket_size - 1])
        );
        assembly {
            mstore(add(payload, 32), pk_bytes)
            mstore(add(payload, 64), crs_last_bytes)
        }
        bytes32 a_last_bytes = AltBn128.g1Compress(
            helpingValues[bucket_size - 1]
        );
        bytes memory g_bytes = AltBn128.g2Compress(AltBn128.g2());
        assembly {
            mstore(add(payload, 96), a_last_bytes)
            mstore(add(payload, 128), g_bytes)
        }
        for (uint256 i = 0; i < bucket_size - 1; i++) {
            uint256 j = bucket_size - 2 - i;
            if (j == id_bar) j--;
            if (i == id_bar) i++;

            bytes32 a_bytes = AltBn128.g1Compress(helpingValues[j]);
            bytes memory crs_bytes = AltBn128.g2Compress(crs[i]);
            assembly {
                mstore(add(payload, 96), a_bytes)
                mstore(add(payload, 128), crs_bytes)
            }
        }
        return AltBn128.multipairing(payload);
    }
}
