// Copyright 2023 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"encoding/json"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	types "github.com/ethereum-optimism/optimism/l2geth/core/types"
	p2p "github.com/ethereum/go-ethereum/p2p"
)

// Status returns geth status information
// for determining node healthiness.
func (ec *Client) Status(ctx context.Context) (
	*RosettaTypes.BlockIdentifier,
	int64,
	*RosettaTypes.SyncStatus,
	[]*RosettaTypes.Peer,
	error,
) {
	header, err := ec.safeBlockHeader(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	var syncStatus *RosettaTypes.SyncStatus
	if ec.supportsSyncing {
		progress, err := ec.syncProgress(ctx)
		if err != nil {
			return nil, -1, nil, nil, err
		}
		if progress != nil {
			currentIndex := int64(progress.CurrentBlock)
			targetIndex := int64(progress.HighestBlock)

			syncStatus = &RosettaTypes.SyncStatus{
				CurrentIndex: &currentIndex,
				TargetIndex:  &targetIndex,
			}
		}
	} else {
		syncStatus = &RosettaTypes.SyncStatus{
			Synced: RosettaTypes.Bool(true),
			Stage:  RosettaTypes.String("SYNCED"),
		}
	}

	var peers []*RosettaTypes.Peer
	if ec.supportsPeering {
		peers, err = ec.peers(ctx)
		if err != nil {
			return nil, -1, nil, nil, err
		}
	} else {
		peers = []*RosettaTypes.Peer{}
	}

	return &RosettaTypes.BlockIdentifier{
			Hash:  header.Hash().Hex(),
			Index: header.Number.Int64(),
		},
		convertTime(header.Time),
		syncStatus,
		peers,
		nil
}

// safeBlockHeader returns the current height from safe chain
// the /network/status should always interact with safe chain to ensure the safety of sync
func (ec *Client) safeBlockHeader(ctx context.Context) (*types.Header, error) {
	var head *types.Header

	err := ec.c.CallContext(ctx, &head, "eth_getBlockByNumber", "safe", false)
	if err == nil && head == nil {
		return nil, ethereum.NotFound
	}

	return head, err
}

// Peers retrieves all peers of the node.
func (ec *Client) peers(ctx context.Context) ([]*RosettaTypes.Peer, error) {
	var info []*p2p.PeerInfo

	if ec.skipAdminCalls {
		return []*RosettaTypes.Peer{}, nil
	}

	if err := ec.c.CallContext(ctx, &info, "admin_peers"); err != nil {
		return nil, err
	}

	peers := make([]*RosettaTypes.Peer, len(info))
	for i, peerInfo := range info {
		peers[i] = &RosettaTypes.Peer{
			PeerID: peerInfo.ID,
			Metadata: map[string]interface{}{
				"name":      peerInfo.Name,
				"enode":     peerInfo.Enode,
				"caps":      peerInfo.Caps,
				"enr":       peerInfo.ENR,
				"protocols": peerInfo.Protocols,
			},
		}
	}

	return peers, nil
}

// TODO: make this a sequencer height check instead
// syncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) syncProgress(ctx context.Context) (*ethereum.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "eth_syncing"); err != nil {
		return nil, err
	}

	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}

	var progress rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}

	return &ethereum.SyncProgress{
		StartingBlock: uint64(progress.StartingBlock),
		CurrentBlock:  uint64(progress.CurrentBlock),
		HighestBlock:  uint64(progress.HighestBlock),
		PulledStates:  uint64(progress.PulledStates),
		KnownStates:   uint64(progress.KnownStates),
	}, nil
}
