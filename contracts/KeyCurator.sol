// SPDX-License-Identifier: MIT

pragma solidity >=0.8.16;

import "./lib/ec-crypto/AltBn128.sol";
import "forge-std/console2.sol";

/**
 * @title KeyCurator
 * @dev Run Key Curator of [GKMR18] RBE construction
 */
contract KeyCurator {
    uint256 public system_capacity;
    uint256 public num_buckets;
    uint256 public bucket_size;

    uint256 public registeredUsers = 0;

    // storage
    AltBn128.G1Point[] public pp;
    AltBn128.G1Point[] public crs1;
    AltBn128.G2Point[] public crs2;

    event UserRegistered(uint256 registeredUsers);
    event ContractDeployed(
        uint system_capacity,
        uint num_buckets,
        uint bucket_size
    );

    /**
     * @dev Set up the RBE system (asymmetric)
     * @param _system_capacity maximum number of users who can register
     * @param _crs1_bytes common reference string (punctured powers of tau) in G1
     * @param _crs2_bytes copy of crs1 in G2
     */
    constructor(
        uint256 _system_capacity,
        bytes[] memory _crs1_bytes,
        bytes[] memory _crs2_bytes
    ) {
        require(_crs1_bytes.length == _crs2_bytes.length);
        require(_crs1_bytes.length > 0);
        // crs1 = new AltBn128.G1Point[](crs1_bytes.length);
        // crs2 = new AltBn128.G2Point[](crs2_bytes.length);

        // crs1.length will be (2 * num_buckets - 1)
        num_buckets = (_crs1_bytes.length + 1) / 2;
        console2.log("num_buckets:", num_buckets);
        assert(num_buckets != 0);

        system_capacity = _system_capacity;
        bucket_size = system_capacity / num_buckets;
        // emit ContractDeployed(system_capacity, num_buckets, bucket_size);

        uint256 i;
        for (i = 0; i < _crs1_bytes.length; i++) {
            crs1.push(AltBn128.g1Unmarshal(_crs1_bytes[i]));
            crs2.push(AltBn128.g2Unmarshal(_crs2_bytes[i]));
        }
        assert(crs1.length == _crs1_bytes.length);
        assert(crs2.length == _crs2_bytes.length);
        console2.log("crs1 length: ", crs1.length);
        console2.log("crs2 length: ", crs2.length);
    }

    function getSystemCapacity() public view returns (uint) {
        return system_capacity;
    }

    function getNumBuckets() public view returns (uint) {
        return num_buckets;
    }

    function getBucketSize() public view returns (uint) {
        return bucket_size;
    }

    function getRegisteredUsers() public view returns (uint) {
        return registeredUsers;
    }

    function getPP() public view returns (AltBn128.G1Point[] memory) {
        return pp;
    }

    function getCrs1() public view returns (AltBn128.G1Point[] memory) {
        return crs1;
    }

    function getCrs2() public view returns (AltBn128.G2Point[] memory) {
        return crs2;
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
        //     // precompile for asymmetric multipairing check:
        //     // multipairing(a1^r1, b1, a2^(r2-r1), b2, ..., ak^(rk-r(k-1)), bk)
        //     // TODO multipairing in *symmetric* group would be more efficient but no precompile
        //     bytes memory payload = new bytes(bucket_size);
        //     bytes32 pk_bytes = AltBn128.g1Compress(pk);
        //     bytes memory crs_last_bytes = AltBn128.g2Compress(
        //         (crs[bucket_size - 1])
        //     );
        //     assembly {
        //         mstore(add(payload, 32), pk_bytes)
        //         mstore(add(payload, 64), crs_last_bytes)
        //     }
        //     bytes32 a_last_bytes = AltBn128.g1Compress(
        //         helpingValues[bucket_size - 1]
        //     );
        //     bytes memory g_bytes = AltBn128.g2Compress(AltBn128.g2());
        //     assembly {
        //         mstore(add(payload, 96), a_last_bytes)
        //         mstore(add(payload, 128), g_bytes)
        //     }
        //     for (uint256 i = 0; i < bucket_size - 1; i++) {
        //         uint256 j = bucket_size - 2 - i;
        //         if (j == id_bar) j--;
        //         if (i == id_bar) i++;

        //         bytes32 a_bytes = AltBn128.g1Compress(helpingValues[j]);
        //         bytes memory crs_bytes = AltBn128.g2Compress(crs[i]);
        //         assembly {
        //             mstore(add(payload, 96), a_bytes)
        //             mstore(add(payload, 128), crs_bytes)
        //         }
        //     }
        //     return AltBn128.multipairing(payload);
        return true;
    }
}
