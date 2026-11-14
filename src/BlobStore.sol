// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// One write-once byte string per address.
///
/// Durability only: everything here is public, so confidentiality comes entirely from
/// the client-side encryption. Records live in contract storage (consensus state), not
/// in event logs, so a plain eth_call can read them back after history expiry.
///
/// Keyed by msg.sender so no one else can ever write to, squat or overwrite your slot.
/// The cost is that you must remember (contract, address); both are public and not secret.
contract BlobStore {
    mapping(address => bytes) public records;

    function store(bytes calldata record) external {
        require(record.length != 0, "empty");
        require(records[msg.sender].length == 0, "exists");
        records[msg.sender] = record;
    }
}
