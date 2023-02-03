package optimism

import (
	"context"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/p2p"
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
	header, err := ec.blockHeader(ctx, nil)
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
