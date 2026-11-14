// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BlobStore} from "../../src/BlobStore.sol";

// Only the two cheatcodes needed; avoids vendoring forge-std.
interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
}

contract BlobStoreTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    BlobStore store = new BlobStore();
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);

    function test_storeAndRead() public {
        vm.prank(ALICE);
        store.store(hex"010203");
        assert(keccak256(store.records(ALICE)) == keccak256(hex"010203"));
    }

    function test_writeOnce() public {
        vm.prank(ALICE);
        store.store(hex"01");
        vm.expectRevert("exists");
        vm.prank(ALICE);
        store.store(hex"02");
        assert(keccak256(store.records(ALICE)) == keccak256(hex"01"));
    }

    function test_emptyRejected() public {
        vm.expectRevert("empty");
        vm.prank(ALICE);
        store.store("");
    }

    function test_perSenderIsolation() public {
        vm.prank(ALICE);
        store.store(hex"aa");
        assert(store.records(BOB).length == 0);
        vm.prank(BOB);
        store.store(hex"bb");
        assert(keccak256(store.records(ALICE)) == keccak256(hex"aa"));
        assert(keccak256(store.records(BOB)) == keccak256(hex"bb"));
    }
}
