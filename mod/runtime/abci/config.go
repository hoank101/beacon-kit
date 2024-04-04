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

package abci

import (
	"github.com/berachain/beacon-kit/mod/node-builder/config/flags"
	"github.com/berachain/beacon-kit/mod/node-builder/utils/cli/parser"
)

const (
	// defaultBeaconBlockPosition is the default position of the beacon block in
	// the proposal.
	defaultBeaconBlockPosition = 0
	// defaultBlobSidecarsBlockPosition is the default position of the blob
	// sidecars in the proposal.
	defaultBlobSidecarsBlockPosition = 1
)

// DefaultABCIConfig returns the default configuration for the proposal service.
func DefaultABCIConfig() Config {
	return Config{
		BeaconBlockPosition:       defaultBeaconBlockPosition,
		BlobSidecarsBlockPosition: defaultBlobSidecarsBlockPosition,
	}
}

// ABCI is a configuration struct for the cosmos proposal handler.
type Config struct {
	// BeaconBlockPosition is the position of the beacon block
	// in the cometbft proposal.
	BeaconBlockPosition uint

	// BlobSidecarsBlockPosition is the position of the blob sidecars
	// in the cometbft proposal.
	BlobSidecarsBlockPosition uint
}

// Parse parses the configuration.
func (c Config) Parse(parser parser.AppOptionsParser) (*Config, error) {
	var err error
	if c.BeaconBlockPosition, err = parser.GetUint(
		flags.BeaconBlockPosition,
	); err != nil {
		return nil, err
	}

	if c.BlobSidecarsBlockPosition, err = parser.GetUint(
		flags.BlobSidecarsBlockPosition,
	); err != nil {
		return nil, err
	}

	return &c, nil
}