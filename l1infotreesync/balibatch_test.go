package l1infotreesync

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/0xPolygon/cdk-contracts-tooling/contracts/elderberry/polygonzkevmglobalexitrootv2"
	"github.com/0xPolygon/cdk/etherman"
	mocks_l1infotreesync "github.com/0xPolygon/cdk/l1infotreesync/mocks"
	"github.com/0xPolygon/cdk/log"
	"github.com/0xPolygon/cdk/reorgdetector"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBenchBali(t *testing.T) {
	rdm := mocks_l1infotreesync.NewReorgDetectorMock(t)
	rdm.On("Subscribe", mock.Anything).Return(&reorgdetector.Subscription{}, nil)
	rdm.On("AddBlockToTrack", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ctx := context.Background()
	dbPath := path.Join(t.TempDir(), "bench.sqlite")
	gerAddr := common.HexToAddress("0x2968d6d736178f8fe7393cc33c87f29d9c287e78")
	verifyAddr := common.HexToAddress("0xe2ef6215adc132df6913c8dd16487abf118d1764")
	client, err := ethclient.Dial("https://virtual.sepolia.rpc.tenderly.co/8641ab94-d07b-4adb-bec5-08fb56f33006")
	require.NoError(t, err)
	syncer, err := New(ctx, dbPath, gerAddr, verifyAddr, 500_000, etherman.LatestBlock, rdm, client, time.Millisecond, 4794471, 100*time.Millisecond, 3,
		FlagAllowWrongContractsAddrs)
	require.NoError(t, err)
	now := time.Now()
	go syncer.Start(ctx)
	currentBlock, err := client.BlockNumber(ctx)
	require.NoError(t, err)
	for {
		lpb, err := syncer.GetLastProcessedBlock(ctx)
		require.NoError(t, err)
		if lpb >= currentBlock {
			break
		}
		log.Infof("syncer last processed block %d", lpb)
		time.Sleep(time.Second)
	}
	elapsed := time.Since(now)

	gerSc, err := polygonzkevmglobalexitrootv2.NewPolygonzkevmglobalexitrootv2(gerAddr, client)
	require.NoError(t, err)
	expectedRoot, err := gerSc.GetRoot(&bind.CallOpts{Pending: false})
	require.NoError(t, err)
	actualRoot, err := syncer.GetLastL1InfoTreeRoot(ctx)
	require.NoError(t, err)
	require.Equal(t, common.Hash(expectedRoot), actualRoot.Hash)
	depositCount, err := gerSc.DepositCount(nil)
	require.NoError(t, err)
	log.Infof("processed %d deposits in %f seconds", depositCount.Int64(), elapsed.Seconds())
}
