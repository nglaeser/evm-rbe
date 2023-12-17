pragma solidity >=0.8.16;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../contracts/lib/ec-crypto/AltBn128.sol";
import "../contracts/KeyCurator.sol";

contract KCTest is Test {
    uint256 testNumber;
    uint capacity = 100;
    uint num_buckets = 10;
    KeyCurator public kc;

    /// @dev Gets generator of G1 group.
    ///      Taken from AltBn128.sol
    uint256 internal constant g1x = 1;
    uint256 internal constant g1y = 2;

    function g1() internal pure returns (AltBn128.G1Point memory) {
        return AltBn128.G1Point(g1x, g1y);
    }

    /// @dev Gets generator of G2 group.
    ///      Taken from AltBn128.sol
    uint256 internal constant g2xx =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant g2xy =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant g2yx =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant g2yy =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;

    function g2() internal pure returns (AltBn128.G2Point memory) {
        return
            AltBn128.G2Point(
                AltBn128.GfP2(g2xx, g2xy),
                AltBn128.GfP2(g2yx, g2yy)
            );
    }

    /// @dev GfP2 from a pair of uint256.
    function gfP2FromBytes(
        bytes memory m
    ) internal pure returns (AltBn128.GfP2 memory) {
        require(m.length == 64, "Invalid G2 compressed bytes length");

        bytes32 x1;
        bytes32 x2;
        uint256 temp;

        // Extract two bytes32 from bytes array
        assembly {
            temp := add(m, 32)
            x1 := mload(temp)
            temp := add(m, 64)
            x2 := mload(temp)
        }

        bytes32 mX = bytes32(0);
        bytes1 leadX = x1[0] & 0x7f;
        // slither-disable-next-line incorrect-shift
        uint256 mask = 0xff << (31 * 8);
        mX = (x1 & ~bytes32(mask)) | (leadX >> 0);

        AltBn128.GfP2 memory x = AltBn128.GfP2(uint256(mX), uint256(x2));
        return x;
    }

    function setUp() public {
        testNumber = 42;
    }

    function test_Deploy() public {
        uint bucket_size = capacity / num_buckets;
        assert(bucket_size == 10);
        AltBn128.G1Point memory gen1 = g1();
        AltBn128.G2Point memory gen2 = g2();

        AltBn128.G1Point[] memory crs1 = new AltBn128.G1Point[](
            2 * num_buckets
        );
        AltBn128.G2Point[] memory crs2 = new AltBn128.G2Point[](crs1.length);
        bytes[] memory crs1_bytes = new bytes[](crs1.length);
        bytes[] memory crs2_bytes = new bytes[](crs1.length);

        uint256 i;
        for (i = 0; i < crs1.length; i++) {
            crs1[i] = gen1;
            crs2[i] = gen2;
            crs1_bytes[i] = AltBn128.g1Marshal(crs1[i]);
            crs2_bytes[i] = AltBn128.g2Marshal(crs2[i]);
        }

        kc = new KeyCurator(capacity, crs1_bytes, crs2_bytes);
        AltBn128.G1Point[] memory returnedCrs1 = kc.getCrs1();
        AltBn128.G2Point[] memory returnedCrs2 = kc.getCrs2();
        assert(crs1.length == returnedCrs1.length);
        assert(crs2.length == returnedCrs2.length);
        assert(kc.getSystemCapacity() == capacity);
        assert(kc.getNumBuckets() == num_buckets);
        // // console2.log("kc.crs1 length: ", returnedCrs1.length);
        // // console2.log("kc.crs2 length: ", returnedCrs2.length);
        // for (i = 0; i < crs1.length; i++) {
        //     // console2.log("crs1[%i]: (%s, %s)", i, crs1[i].x, crs1[i].y);
        //     // console2.log(
        //     //     "returnedCrs1[%i]: (%s, %s)",
        //     //     i,
        //     //     returnedCrs1[i].x,
        //     //     returnedCrs1[i].y
        //     // );
        //     assert(returnedCrs1[i].x == crs1[i].x);
        //     assert(returnedCrs1[i].y == crs1[i].y);
        //     assert(returnedCrs2[i].x.x == crs2[i].x.x);
        //     assert(returnedCrs2[i].x.y == crs2[i].x.y);
        //     assert(returnedCrs2[i].y.x == crs2[i].y.x);
        //     assert(returnedCrs2[i].y.y == crs2[i].y.y);
        // }
    }

    function test_Register() public {
        // TODO
    }

    function testFail_Subtract43() public {
        testNumber -= 43;
    }
}
