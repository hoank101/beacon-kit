// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (C) 2024, Berachain Foundation. All rights reserved.
// Use of this software is governed by the Business Source License included
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

package proof

import "github.com/berachain/beacon-kit/mod/node-api/handlers/utils"

// Get the slot from the given input of block id, beacon state, and beacon
// block header for the resolved slot.
func (h *Handler[
	ContextT, BeaconBlockHeaderT, BeaconStateT, _, _, _,
]) resolveBlockID(blockID string) (
	uint64, BeaconStateT, BeaconBlockHeaderT, error,
) {
	var (
		beaconState BeaconStateT
		blockHeader BeaconBlockHeaderT
	)

	slot, err := utils.SlotFromBlockID(blockID, h.backend)
	if err != nil {
		return slot, beaconState, blockHeader, err
	}

	beaconState, err = h.backend.StateFromSlot(slot)
	if err != nil {
		return slot, beaconState, blockHeader, err
	}

	blockHeader, err = h.getBlockHeaderFromState(beaconState)
	return slot, beaconState, blockHeader, err
}

// getBlockHeaderFromState returns the block header from the given state.
//
// TODO: remove once issue #1777 is fixed.
func (h *Handler[
	_, BeaconBlockHeaderT, BeaconStateT, _, _, _,
]) getBlockHeaderFromState(bs BeaconStateT) (BeaconBlockHeaderT, error) {
	blockHeader, err := bs.GetLatestBlockHeader()
	if err != nil {
		return blockHeader, err
	}

	// The state root must be patched onto the latest block header since it is
	// committed to state with a 0 state root.
	stateRoot, err := bs.HashTreeRoot()
	blockHeader.SetStateRoot(stateRoot)
	return blockHeader, err
}