// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (C) 2024, Berachain Foundation. All rights reserved.
// Use of this software is govered by the Business Source License included
// in the LICENSE file of this repository and at www.mariadb.com/bsl11.
//
// ANY USE OF THE LICENSED WORK IN VIOLATION OF THIS LICENSE WILL AUTOMATICALLY
// TERMINATE YOUR RIGHTS UNDER THIS LICENSE FOR THE CURRENT AND ALL OTHER
// VERSIONS OF THE LICENSED WORK.
//
// THIS LICENSE DOES NOT GRANT YOU ANY RIGHT IN ANY TRADEMARK OR LOGO OF
// LICENSOR OR ITS AFFILIATES (PROVIDED THAT YOU MAY USE A TRADEMARK OR LOGO OF
// LICENSOR AS EXPRESSLY REQUIRED BY THIS LICENSE).
//
// TO THE EXTENT PERMITTED BY APPLICABLE LAW, THE LICENSED WORK IS PROVIDED ON
// AN “AS IS” BASIS. LICENSOR HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS,
// EXPRESS OR IMPLIED, INCLUDING (WITHOUT LIMITATION) WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND
// TITLE.

package merkle

import (
	sha256 "github.com/minio/sha256-simd"
)

// VerifyProof given a tree root, a leaf, the generalized merkle index
// of the leaf in the tree, and the proof itself.
func VerifyProof[RootT, ProofT ~[32]byte](
	root, leaf RootT,
	merkleIndex uint64,
	proof []ProofT,
) bool {
	//#nosec:G701 `int`` is at minimum 32-bits and thus a
	// uint8 will always fit.
	if len(proof) > int(^uint8(0)) {
		return false
	}
	return IsValidMerkleBranch(
		leaf,
		proof,
		//#nosec:G701 // we check the length of the proof above.
		uint8(len(proof)),
		merkleIndex,
		root,
	)
}

// IsValidMerkleBranch as per the Ethereum 2.0 spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
//
//nolint:lll // link.
func IsValidMerkleBranch[RootT, BranchT ~[32]byte](
	leaf RootT, branch []BranchT, depth uint8, index uint64, root RootT,
) bool {
	//#nosec:G701 `int`` is at minimum 32-bits and thus a
	// uint8 will always fit.
	if len(branch) != int(depth) {
		return false
	}
	return RootFromBranch(leaf, branch, depth, index) == root
}

// RootFromBranch calculates the Merkle root from a leaf and a branch.
// Inspired by:
// https://github.com/sigp/lighthouse/blob/2cd0e609f59391692b4c8e989e26e0dac61ff801/consensus/merkle_proof/src/lib.rs#L357
//
//nolint:lll
func RootFromBranch[RootT, BranchT ~[32]byte](
	leaf RootT,
	branch []BranchT,
	depth uint8,
	index uint64,
) RootT {
	merkleRoot := leaf
	var hashInput [64]byte
	for i := range depth {
		//nolint:mnd // from spec.
		ithBit := (index >> i) & 0x01
		if ithBit == 1 {
			copy(hashInput[:32], branch[i][:])
			copy(hashInput[32:], merkleRoot[:])
		} else {
			copy(hashInput[:32], merkleRoot[:])
			copy(hashInput[32:], branch[i][:])
		}
		merkleRoot = sha256.Sum256(hashInput[:])
	}
	return merkleRoot
}
