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

package types_test

import (
	"testing"

	"github.com/berachain/beacon-kit/mod/consensus-types/pkg/types"
	engineprimitives "github.com/berachain/beacon-kit/mod/engine-primitives/pkg/engine-primitives"
	"github.com/berachain/beacon-kit/mod/primitives/pkg/bytes"
	"github.com/berachain/beacon-kit/mod/primitives/pkg/eip4844"
	"github.com/berachain/beacon-kit/mod/primitives/pkg/math"
	"github.com/berachain/beacon-kit/mod/primitives/pkg/version"
	"github.com/stretchr/testify/require"
)

// generateValidBeaconBlockDeneb generates a valid beacon block for the Deneb.
func generateValidBeaconBlockDeneb() *types.BeaconBlockDeneb {
	// Initialize your block here
	var byteArray [256]byte
	byteSlice := byteArray[:]
	return &types.BeaconBlockDeneb{
		BeaconBlockHeaderBase: types.BeaconBlockHeaderBase{
			Slot:            10,
			ProposerIndex:   5,
			ParentBlockRoot: bytes.B32{1, 2, 3, 4, 5},
			StateRoot:       bytes.B32{5, 4, 3, 2, 1},
		},
		Body: &types.BeaconBlockBodyDeneb{
			ExecutionPayload: &types.ExecutableDataDeneb{
				LogsBloom: byteSlice,

				ExtraData:    []byte{},
				Transactions: [][]byte{},
				Withdrawals:  []*engineprimitives.Withdrawal{},
			},
			BlobKzgCommitments: []eip4844.KZGCommitment{},
		},
	}
}

func TestBeaconBlockForDeneb(t *testing.T) {
	block := &types.BeaconBlockDeneb{
		BeaconBlockHeaderBase: types.BeaconBlockHeaderBase{
			Slot:            10,
			ProposerIndex:   5,
			ParentBlockRoot: bytes.B32{1, 2, 3, 4, 5},
		},
	}
	require.NotNil(t, block)
}

// Test the case where the fork version is not supported.
func TestEmptyBeaconBlockInvalidForkVersion(t *testing.T) {
	require.Panics(t, func() {
		(&types.BeaconBlock{}).Empty(100)
	})
}

func TestBeaconBlockFromSSZ(t *testing.T) {
	originalBlock := generateValidBeaconBlockDeneb()

	originalBlock.Body.Deposits = []*types.Deposit{}

	sszBlock, err := originalBlock.MarshalSSZ()
	require.NoError(t, err)
	require.NotNil(t, sszBlock)

	wrappedBlock := &types.BeaconBlock{}
	wrappedBlock, err = wrappedBlock.NewFromSSZ(sszBlock, version.Deneb)
	require.NoError(t, err)
	require.NotNil(t, wrappedBlock)

	block, ok := wrappedBlock.RawBeaconBlock.(*types.BeaconBlockDeneb)
	require.True(t, ok)
	require.Equal(t, originalBlock, block)
}

func TestBeaconBlockFromSSZForkVersionNotSupported(t *testing.T) {
	wrappedBlock := &types.BeaconBlock{}
	_, err := wrappedBlock.NewFromSSZ([]byte{}, 1)
	require.ErrorIs(t, err, types.ErrForkVersionNotSupported)
}
func TestBeaconBlockDeneb(t *testing.T) {
	block := generateValidBeaconBlockDeneb()

	require.NotNil(t, block.Body)
	require.Equal(t, version.Deneb, block.Version())
	require.False(t, block.IsNil())

	// Set a new state root and test the SetStateRoot and GetBody methods
	newStateRoot := [32]byte{1, 1, 1, 1, 1}
	block.SetStateRoot(newStateRoot)
	require.Equal(t, newStateRoot, [32]byte(block.StateRoot))

	// Test the GetBody method
	require.Equal(
		t, &types.BeaconBlockBody{RawBeaconBlockBody: block.Body},
		block.GetBody(),
	)

	// Test the GetHeader method
	header := block.GetHeader()
	require.NotNil(t, header)
	require.Equal(t, block.Slot, header.Slot)
	require.Equal(t, block.ProposerIndex, header.ProposerIndex)
	require.Equal(t, block.ParentBlockRoot, header.ParentBlockRoot)
	require.Equal(t, block.StateRoot, header.StateRoot)
}

func TestBeaconBlockDeneb_MarshalUnmarshalSSZ(t *testing.T) {
	block := *generateValidBeaconBlockDeneb()
	block.Body.Deposits = []*types.Deposit{}

	sszBlock, err := block.MarshalSSZ()
	require.NoError(t, err)
	require.NotNil(t, sszBlock)

	var unmarshalledBlock types.BeaconBlockDeneb
	err = unmarshalledBlock.UnmarshalSSZ(sszBlock)
	require.NoError(t, err)

	block.Body.Deposits = []*types.Deposit{}

	require.Equal(t, block, unmarshalledBlock)
}

func TestBeaconBlockDeneb_HashTreeRoot(t *testing.T) {
	block := generateValidBeaconBlockDeneb()
	hashRoot, err := block.HashTreeRoot()
	require.NoError(t, err)
	require.NotNil(t, hashRoot)
}

func TestBeaconBlockEmpty(t *testing.T) {
	block := &types.BeaconBlock{}
	emptyBlock := block.Empty(version.Deneb)
	require.NotNil(t, emptyBlock)
	require.IsType(t, &types.BeaconBlockDeneb{}, emptyBlock.RawBeaconBlock)
}

func TestNewWithVersion(t *testing.T) {
	slot := math.Slot(10)
	proposerIndex := math.ValidatorIndex(5)
	parentBlockRoot := bytes.B32{1, 2, 3, 4, 5}

	block, err := (&types.BeaconBlock{}).NewWithVersion(
		slot, proposerIndex, parentBlockRoot, version.Deneb,
	)
	require.NoError(t, err)
	require.NotNil(t, block)

	// Check the block's fields
	require.NotNil(t, block.RawBeaconBlock)
	require.Equal(t, slot, block.RawBeaconBlock.GetSlot())
	require.Equal(t, proposerIndex, block.RawBeaconBlock.GetProposerIndex())
	require.Equal(t, parentBlockRoot, block.RawBeaconBlock.GetParentBlockRoot())
	require.Equal(t, version.Deneb, block.RawBeaconBlock.Version())
}

func TestNewWithVersionInvalidForkVersion(t *testing.T) {
	slot := math.Slot(10)
	proposerIndex := math.ValidatorIndex(5)
	parentBlockRoot := bytes.B32{1, 2, 3, 4, 5}

	_, err := (&types.BeaconBlock{}).NewWithVersion(
		slot,
		proposerIndex,
		parentBlockRoot,
		100,
	) // 100 is an invalid fork version
	require.ErrorIs(t, err, types.ErrForkVersionNotSupported)
}

func TestBeaconBlockDeneb_GetTree(t *testing.T) {
	block := generateValidBeaconBlockDeneb()
	tree, err := block.GetTree()
	require.NoError(t, err)
	require.NotNil(t, tree)
}
