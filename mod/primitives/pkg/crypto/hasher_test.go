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

package crypto_test

import (
	"crypto/sha256"
	"testing"

	"github.com/berachain/beacon-kit/mod/primitives/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestCombi(t *testing.T) {
	// Initialize the hasher function
	hashFunc := func(data []byte) [32]byte {
		var result [32]byte
		hash := sha256.Sum256(data)
		copy(result[:], hash[:])
		return result
	}
	hasher := crypto.NewHasher[[32]byte](hashFunc)

	tests := []struct {
		name     string
		a, b     [32]byte
		expected [32]byte
	}{
		{
			name: "Simple combination",
			a:    [32]byte{1, 2, 3, 4},
			b:    [32]byte{5, 6, 7, 8},
			expected: [32]uint8{
				0x25, 0xb3, 0x45, 0x5a, 0x41, 0x7, 0x6d, 0xab, 0x87, 0x50, 0x14,
				0x3a, 0xa5, 0xaa, 0xd, 0x82, 0x10, 0xe5, 0x87, 0x70, 0x26, 0x92,
				0x58, 0xb8, 0x77, 0x0, 0x87, 0x88, 0x43, 0x96, 0x26, 0x94},
		},
		{
			name: "Another combination",
			a:    [32]byte{9, 10, 11, 12},
			b:    [32]byte{13, 14, 15, 16},
			expected: [32]uint8{
				0x98, 0xfa, 0xf7, 0x2, 0x11, 0xf3, 0xfb, 0x38, 0xb5, 0x6e, 0xaf,
				0x37, 0xf1, 0x85, 0x86, 0x18, 0x5a, 0x61, 0x3d, 0x75, 0x9, 0xe,
				0xb7, 0x4d, 0x64, 0xd7, 0x28, 0x5, 0xde, 0xe6, 0x1, 0xdc},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasher.Combi(tc.a, tc.b)
			require.Equal(t, tc.expected, result,
				"TestCase %s", tc.name)
		})
	}
}

func TestMixIn(t *testing.T) {
	// Initialize the hasher function
	hashFunc := func(data []byte) [32]byte {
		var result [32]byte
		hash := sha256.Sum256(data)
		copy(result[:], hash[:])
		return result
	}
	hasher := crypto.NewHasher[[32]byte](hashFunc)

	tests := []struct {
		name     string
		a        [32]byte
		i        uint64
		expected [32]byte
	}{
		{
			name: "MixIn with integer 1",
			a:    [32]byte{1, 2, 3, 4},
			i:    1,
			expected: [32]uint8{
				0xbb, 0xf4, 0xca, 0x27, 0x91, 0x22, 0x75, 0xe2, 0xef, 0xba, 0xe2,
				0x32, 0xba, 0xf5, 0xfe, 0x8a, 0x41, 0xa, 0xdb, 0x23, 0x31, 0xae,
				0x51, 0xdf, 0xcf, 0x8, 0x8d, 0x40, 0xa9, 0xe8, 0xf2, 0xcf},
		},
		{
			name: "MixIn with integer 2",
			a:    [32]byte{5, 6, 7, 8},
			i:    2,
			expected: [32]uint8{
				0x6c, 0x67, 0x4b, 0x75, 0xc8, 0x87, 0x2, 0xa4, 0x84, 0x64, 0x78,
				0x28, 0x32, 0xea, 0xc, 0xa7, 0x45, 0x71, 0x74, 0xc2, 0x4e, 0x7c,
				0x4c, 0x0, 0x4f, 0xc9, 0xdd, 0x35, 0xe4, 0x61, 0x37, 0xa4},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasher.MixIn(tc.a, tc.i)
			require.Equal(t, tc.expected, result,
				"TestCase %s", tc.name)
		})
	}
}
