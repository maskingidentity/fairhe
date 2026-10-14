// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Ledger record of the bulky values posted as blob data (option O6)
/// @notice Instead of a data-availability layer, a party posts the bulky
/// values of registration and orders (keys, ciphertexts, with their proofs)
/// as the blobs of a type-3 transaction that calls post with the digests the
/// market records for them, in blob order, and the number of blobs of each.
/// The event records each digest with the versioned hashes of its blobs and
/// the poster; the counterparty retrieves the blobs within the retention
/// window, checks them against the versioned hashes and the value against
/// the digest. Nothing is stored in contract state.
contract BlobBoard {
    event Posted(address indexed poster, bytes32 indexed digest, bytes32[] versionedHashes);

    error BlobCount();

    function post(bytes32[] calldata digests, uint8[] calldata counts) external {
        if (digests.length == 0 || digests.length != counts.length) revert BlobCount();
        uint256 k;
        for (uint256 i = 0; i < digests.length; i++) {
            uint256 c = counts[i];
            if (c == 0) revert BlobCount();
            bytes32[] memory vhs = new bytes32[](c);
            for (uint256 j = 0; j < c; j++) {
                bytes32 vh = blobhash(k + j);
                if (vh == bytes32(0)) revert BlobCount();
                vhs[j] = vh;
            }
            k += c;
            emit Posted(msg.sender, digests[i], vhs);
        }
        // Every blob of the transaction belongs to a digest.
        if (blobhash(k) != bytes32(0)) revert BlobCount();
    }
}
