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

package bytes_test

import (
	"testing"

	"github.com/berachain/beacon-kit/mod/primitives/pkg/bytes"
	"github.com/berachain/beacon-kit/mod/primitives/pkg/ssz/types"
	"github.com/stretchr/testify/require"
)

func TestBytes4MarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  string
	}{
		{
			name:  "valid bytes",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  `"0x01020304"`,
		},
		{
			name:  "all zeros",
			input: bytes.B4{0x00, 0x00, 0x00, 0x00},
			want:  `"0x00000000"`,
		},
		{
			name:  "all ones",
			input: bytes.B4{0xFF, 0xFF, 0xFF, 0xFF},
			want:  `"0xffffffff"`,
		},
		{
			name:  "mixed bytes",
			input: bytes.B4{0xAA, 0xBB, 0xCC, 0xDD},
			want:  `"0xaabbccdd"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.MarshalJSON()
			require.NoError(t, err, "Test case: %s", tt.name)
			require.JSONEq(t, tt.want, string(got), "Test case: %s", tt.name)
		})
	}
}

func TestBytes4SizeSSZ(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  int
	}{
		{
			name:  "size of B4",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  bytes.B4Size,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.SizeSSZ()
			require.Equal(t, tt.want, got, "Test case: %s", tt.name)
		})
	}
}

func TestBytes4MarshalSSZ(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  []byte
	}{
		{
			name:  "marshal B4",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  []byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.MarshalSSZ()

			require.NoError(t, err, "Test case: %s", tt.name)
			require.Equal(t, tt.want, got, "Test case: %s", tt.name)
		})
	}
}

func TestBytes4IsFixed(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  bool
	}{
		{
			name:  "is fixed",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.IsFixed()
			require.Equal(t, tt.want, got, "Test case: %s", tt.name)
		})
	}
}

func TestBytes4Type(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  types.Type
	}{
		{
			name:  "type of B4",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  types.Composite,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.Type()
			require.Equal(t, tt.want, got, "Test case: %s", tt.name)
		})
	}
}

func TestBytes4HashTreeRoot(t *testing.T) {
	tests := []struct {
		name  string
		input bytes.B4
		want  [32]byte
	}{
		{
			name:  "hash tree root",
			input: bytes.B4{0x01, 0x02, 0x03, 0x04},
			want:  [32]byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.HashTreeRoot()
			require.NoError(t, err, "Test case: %s", tt.name)
			require.Equal(t, tt.want, got, "Test case: %s", tt.name)
		})
	}
}
