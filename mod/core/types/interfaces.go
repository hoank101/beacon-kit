// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Berachain Foundation
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package types

import (
	"github.com/berachain/beacon-kit/mod/primitives"
	ssz "github.com/ferranbt/fastssz"
)

// BeaconBlockBody is the interface for a beacon block body.
type BeaconBlockBody interface {
	WriteOnlyBeaconBlockBody
	ReadOnlyBeaconBlockBody
}

// WriteOnlyBeaconBlockBody is the interface for a write-only beacon block body.
type WriteOnlyBeaconBlockBody interface {
	SetDeposits([]*primitives.Deposit)
	SetEth1Data(*primitives.Eth1Data)
	SetExecutionData(primitives.ExecutionPayload) error
	SetBlobKzgCommitments(primitives.Commitments)
}

// ReadOnlyBeaconBlockBody is the interface for
// a read-only beacon block body.
type ReadOnlyBeaconBlockBody interface {
	ssz.Marshaler
	ssz.Unmarshaler
	ssz.HashRoot
	IsNil() bool

	// Execution returns the execution data of the block.
	GetDeposits() []*primitives.Deposit
	GetEth1Data() *primitives.Eth1Data
	GetGraffiti() primitives.Bytes32
	GetRandaoReveal() primitives.BLSSignature
	GetExecutionPayload() primitives.ExecutionPayload
	GetBlobKzgCommitments() primitives.Commitments
	GetTopLevelRoots() ([][32]byte, error)
}

// ChainSpec represents a chain spec.
// TODO: use in the BeaconBlockBody for merkleization.
type ChainSpec interface {
	MaxDepositsPerBlock() uint64
}
