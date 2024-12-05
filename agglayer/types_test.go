package agglayer

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"

	cdkcommon "github.com/0xPolygon/cdk/common"
	"github.com/0xPolygon/cdk/log"
	"github.com/0xPolygon/cdk/tree/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const (
	expectedSignedCertificateEmptyMetadataJSON = `{"network_id":1,"height":1,"prev_local_exit_root":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"new_local_exit_root":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"bridge_exits":[{"leaf_type":"Transfer","token_info":null,"dest_network":0,"dest_address":"0x0000000000000000000000000000000000000000","amount":"1","metadata":[]}],"imported_bridge_exits":[{"bridge_exit":{"leaf_type":"Transfer","token_info":null,"dest_network":0,"dest_address":"0x0000000000000000000000000000000000000000","amount":"1","metadata":[]},"claim_data":null,"global_index":{"mainnet_flag":false,"rollup_index":1,"leaf_index":1}}],"metadata":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":{"r":"0x0000000000000000000000000000000000000000000000000000000000000000","s":"0x0000000000000000000000000000000000000000000000000000000000000000","odd_y_parity":false}}`
	expectedSignedCertificateyMetadataJSON     = `{"network_id":1,"height":1,"prev_local_exit_root":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"new_local_exit_root":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"bridge_exits":[{"leaf_type":"Transfer","token_info":null,"dest_network":0,"dest_address":"0x0000000000000000000000000000000000000000","amount":"1","metadata":[1,2,3]}],"imported_bridge_exits":[{"bridge_exit":{"leaf_type":"Transfer","token_info":null,"dest_network":0,"dest_address":"0x0000000000000000000000000000000000000000","amount":"1","metadata":[]},"claim_data":null,"global_index":{"mainnet_flag":false,"rollup_index":1,"leaf_index":1}}],"metadata":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":{"r":"0x0000000000000000000000000000000000000000000000000000000000000000","s":"0x0000000000000000000000000000000000000000000000000000000000000000","odd_y_parity":false}}`
)

func TestGenericError_Error(t *testing.T) {
	err := GenericError{"test", "value"}
	require.Equal(t, "[Agglayer Error] test: value", err.Error())
}

func TestCertificateHeaderID(t *testing.T) {
	certificate := CertificateHeader{
		Height:        1,
		CertificateID: common.HexToHash("0x123"),
	}
	require.Equal(t, "1/0x0000000000000000000000000000000000000000000000000000000000000123", certificate.ID())

	var certNil *CertificateHeader
	require.Equal(t, "nil", certNil.ID())
}

func TestCertificateHeaderString(t *testing.T) {
	certificate := CertificateHeader{
		Height:        1,
		CertificateID: common.HexToHash("0x123"),
	}
	require.Equal(t, "Height: 1, CertificateID: 0x0000000000000000000000000000000000000000000000000000000000000123, PreviousLocalExitRoot: nil, NewLocalExitRoot: 0x0000000000000000000000000000000000000000000000000000000000000000. Status: Pending. Errors: []",
		certificate.String())

	var certNil *CertificateHeader
	require.Equal(t, "nil", certNil.String())
}

func TestMarshalJSON(t *testing.T) {
	cert := SignedCertificate{
		Certificate: &Certificate{
			NetworkID:         1,
			Height:            1,
			PrevLocalExitRoot: common.Hash{},
			NewLocalExitRoot:  common.Hash{},
			BridgeExits: []*BridgeExit{
				{
					LeafType:           LeafTypeAsset,
					DestinationAddress: common.Address{},
					Amount:             big.NewInt(1),
				},
			},
			ImportedBridgeExits: []*ImportedBridgeExit{
				{
					BridgeExit: &BridgeExit{
						LeafType:           LeafTypeAsset,
						DestinationAddress: common.Address{},
						Amount:             big.NewInt(1),
						Metadata:           []byte{},
					},
					ClaimData: nil,
					GlobalIndex: &GlobalIndex{
						MainnetFlag: false,
						RollupIndex: 1,
						LeafIndex:   1,
					},
				},
			},
		},

		Signature: &Signature{
			R:         common.Hash{},
			S:         common.Hash{},
			OddParity: false,
		},
	}
	data, err := json.Marshal(cert)
	require.NoError(t, err)
	log.Info(string(data))
	require.Equal(t, expectedSignedCertificateEmptyMetadataJSON, string(data))

	cert.BridgeExits[0].Metadata = []byte{1, 2, 3}
	data, err = json.Marshal(cert)
	require.NoError(t, err)
	log.Info(string(data))
	require.Equal(t, expectedSignedCertificateyMetadataJSON, string(data))
}

func TestSignedCertificate_Copy(t *testing.T) {
	t.Parallel()

	t.Run("copy with non-nil fields", func(t *testing.T) {
		t.Parallel()

		original := &SignedCertificate{
			Certificate: &Certificate{
				NetworkID:         1,
				Height:            100,
				PrevLocalExitRoot: [32]byte{0x01},
				NewLocalExitRoot:  [32]byte{0x02},
				BridgeExits: []*BridgeExit{
					{
						LeafType:           LeafTypeAsset,
						TokenInfo:          &TokenInfo{OriginNetwork: 1, OriginTokenAddress: common.HexToAddress("0x123")},
						DestinationNetwork: 2,
						DestinationAddress: common.HexToAddress("0x456"),
						Amount:             big.NewInt(1000),
						Metadata:           []byte{0x01, 0x02},
					},
				},
				ImportedBridgeExits: []*ImportedBridgeExit{
					{
						BridgeExit: &BridgeExit{
							LeafType:           LeafTypeMessage,
							TokenInfo:          &TokenInfo{OriginNetwork: 1, OriginTokenAddress: common.HexToAddress("0x789")},
							DestinationNetwork: 3,
							DestinationAddress: common.HexToAddress("0xabc"),
							Amount:             big.NewInt(2000),
							Metadata:           []byte{0x03, 0x04},
						},
						ClaimData:   &ClaimFromMainnnet{},
						GlobalIndex: &GlobalIndex{MainnetFlag: true, RollupIndex: 1, LeafIndex: 2},
					},
				},
				Metadata: common.HexToHash("0xdef"),
			},
			Signature: &Signature{
				R:         common.HexToHash("0x111"),
				S:         common.HexToHash("0x222"),
				OddParity: true,
			},
		}

		certificateCopy := original.CopyWithDefaulting()

		require.NotNil(t, certificateCopy)
		require.NotSame(t, original, certificateCopy)
		require.NotSame(t, original.Certificate, certificateCopy.Certificate)
		require.Same(t, original.Signature, certificateCopy.Signature)
		require.Equal(t, original, certificateCopy)
	})

	t.Run("copy with nil BridgeExits, ImportedBridgeExits and Signature", func(t *testing.T) {
		t.Parallel()

		original := &SignedCertificate{
			Certificate: &Certificate{
				NetworkID:           1,
				Height:              100,
				PrevLocalExitRoot:   [32]byte{0x01},
				NewLocalExitRoot:    [32]byte{0x02},
				BridgeExits:         nil,
				ImportedBridgeExits: nil,
				Metadata:            common.HexToHash("0xdef"),
			},
			Signature: nil,
		}

		certificateCopy := original.CopyWithDefaulting()

		require.NotNil(t, certificateCopy)
		require.NotSame(t, original, certificateCopy)
		require.NotSame(t, original.Certificate, certificateCopy.Certificate)
		require.NotNil(t, certificateCopy.Signature)
		require.Equal(t, original.NetworkID, certificateCopy.NetworkID)
		require.Equal(t, original.Height, certificateCopy.Height)
		require.Equal(t, original.PrevLocalExitRoot, certificateCopy.PrevLocalExitRoot)
		require.Equal(t, original.NewLocalExitRoot, certificateCopy.NewLocalExitRoot)
		require.Equal(t, original.Metadata, certificateCopy.Metadata)
		require.NotNil(t, certificateCopy.BridgeExits)
		require.NotNil(t, certificateCopy.ImportedBridgeExits)
		require.Empty(t, certificateCopy.BridgeExits)
		require.Empty(t, certificateCopy.ImportedBridgeExits)
	})
}

func TestGlobalIndex_UnmarshalFromMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    map[string]interface{}
		want    *GlobalIndex
		wantErr bool
	}{
		{
			name: "valid data",
			data: map[string]interface{}{
				"rollup_index": uint32(0),
				"leaf_index":   uint32(2),
				"mainnet_flag": true,
			},
			want: &GlobalIndex{
				RollupIndex: 0,
				LeafIndex:   2,
				MainnetFlag: true,
			},
			wantErr: false,
		},
		{
			name: "missing rollup_index",
			data: map[string]interface{}{
				"leaf_index":   uint32(2),
				"mainnet_flag": true,
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
		{
			name: "invalid rollup_index type",
			data: map[string]interface{}{
				"rollup_index": "invalid",
				"leaf_index":   uint32(2),
				"mainnet_flag": true,
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
		{
			name: "missing leaf_index",
			data: map[string]interface{}{
				"rollup_index": uint32(1),
				"mainnet_flag": true,
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
		{
			name: "invalid leaf_index type",
			data: map[string]interface{}{
				"rollup_index": uint32(1),
				"leaf_index":   "invalid",
				"mainnet_flag": true,
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
		{
			name: "missing mainnet_flag",
			data: map[string]interface{}{
				"rollup_index": uint32(1),
				"leaf_index":   uint32(2),
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
		{
			name: "invalid mainnet_flag type",
			data: map[string]interface{}{
				"rollup_index": uint32(1),
				"leaf_index":   uint32(2),
				"mainnet_flag": "invalid",
			},
			want:    &GlobalIndex{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := &GlobalIndex{}
			err := g.UnmarshalFromMap(tt.data)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, g)
			}
		})
	}
}

func TestUnmarshalCertificateHeaderUnknownError(t *testing.T) {
	rawCertificateHeader := `{
		"network_id": 14,
		"height": 0,
		"epoch_number": null,
		"certificate_index": null,
		"certificate_id": "0x3af88c9ca106822bd141fdc680dcb888f4e9d4997fad1645ba3d5d747059eb32",
		"new_local_exit_root": "0x625e889ced3c31277c6653229096374d396a2fd3564a8894aaad2ff935d2fc8c",
		"metadata": "0x0000000000000000000000000000000000000000000000000000000000002f3d",
		"status": {
			"InError": {
				"error": {
					"ProofVerificationFailed": {
						"Plonk": "the verifying key does not match the inner plonk bn254 proof's committed verifying key"
					}
				}
			}
		}
	}`

	var result *CertificateHeader
	err := json.Unmarshal([]byte(rawCertificateHeader), &result)
	require.NoError(t, err)
	require.NotNil(t, result)

	expectedErr := &GenericError{
		Key:   "ProofVerificationFailed",
		Value: "{\"Plonk\":\"the verifying key does not match the inner plonk bn254 proof's committed verifying key\"}",
	}

	require.Equal(t, expectedErr, result.Error)
}

func TestConvertNumeric(t *testing.T) {
	tests := []struct {
		name        string
		value       float64
		target      reflect.Type
		expected    interface{}
		expectedErr error
	}{
		// Integer conversions
		{"FloatToInt", 42.5, reflect.TypeOf(int(0)), int(42), nil},
		{"FloatToInt8", 127.5, reflect.TypeOf(int8(0)), int8(127), nil},
		{"FloatToInt16", 32767.5, reflect.TypeOf(int16(0)), int16(32767), nil},
		{"FloatToInt32", 2147483647.5, reflect.TypeOf(int32(0)), int32(2147483647), nil},
		{"FloatToInt64", -10000000000000000.9, reflect.TypeOf(int64(0)), int64(-10000000000000000), nil},

		// Unsigned integer conversions
		{"FloatToUint", 42.5, reflect.TypeOf(uint(0)), uint(42), nil},
		{"FloatToUint8", 255.5, reflect.TypeOf(uint8(0)), uint8(255), nil},
		{"FloatToUint16", 65535.5, reflect.TypeOf(uint16(0)), uint16(65535), nil},
		{"FloatToUint32", 4294967295.5, reflect.TypeOf(uint32(0)), uint32(4294967295), nil},
		{"FloatToUint64", 10000000000000000.9, reflect.TypeOf(uint64(0)), uint64(10000000000000000), nil},

		// Float conversions
		{"FloatToFloat32", 3.14, reflect.TypeOf(float32(0)), float32(3.14), nil},
		{"FloatToFloat64", 3.14, reflect.TypeOf(float64(0)), float64(3.14), nil},

		// Unsupported type
		{"UnsupportedType", 3.14, reflect.TypeOf("string"), nil, errors.New("unsupported target type string")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertNumeric(tt.value, tt.target)
			if tt.expectedErr != nil {
				require.ErrorContains(t, err, tt.expectedErr.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create a dummy TokenInfo (mocking as needed).
func createDummyTokenInfo() *TokenInfo {
	return &TokenInfo{
		OriginNetwork:      1,
		OriginTokenAddress: common.HexToAddress("0x2345"),
	}
}

// Helper function to create a dummy GlobalIndex.
func createDummyGlobalIndex() *GlobalIndex {
	return &GlobalIndex{
		MainnetFlag: false,
		RollupIndex: 1,
		LeafIndex:   1,
	}
}

// Helper function to create a dummy Claim (mock as needed).
func createDummyClaim() *ClaimFromMainnnet {
	return &ClaimFromMainnnet{
		ProofLeafMER: &MerkleProof{
			Root: common.HexToHash("0x1234"),
			Proof: [common.HashLength]common.Hash{
				common.HexToHash("0x1234"),
				common.HexToHash("0x5678"),
			},
		},
		ProofGERToL1Root: &MerkleProof{
			Root: common.HexToHash("0x5678"),
			Proof: [common.HashLength]common.Hash{
				common.HexToHash("0x5678"),
				common.HexToHash("0x1234"),
			},
		},
		L1Leaf: &L1InfoTreeLeaf{
			L1InfoTreeIndex: 1,
			RollupExitRoot:  common.HexToHash("0x987654321"),
			MainnetExitRoot: common.HexToHash("0x123456789"),
			Inner:           &L1InfoTreeLeafInner{},
		},
	}
}

func TestCertificateHash(t *testing.T) {
	// Test inputs
	prevLocalExitRoot := [common.HashLength]byte{}
	newLocalExitRoot := [common.HashLength]byte{}
	copy(prevLocalExitRoot[:], bytes.Repeat([]byte{0x01}, common.HashLength))
	copy(newLocalExitRoot[:], bytes.Repeat([]byte{0x02}, common.HashLength))

	// Create dummy BridgeExits
	bridgeExits := []*BridgeExit{
		{
			LeafType:           LeafTypeAsset,
			TokenInfo:          createDummyTokenInfo(),
			DestinationNetwork: 1,
			DestinationAddress: common.HexToAddress("0x0000000000000000000000000000000000000001"),
			Amount:             big.NewInt(100),
			Metadata:           []byte("metadata1"),
		},
		{
			LeafType:           LeafTypeMessage,
			TokenInfo:          createDummyTokenInfo(),
			DestinationNetwork: 2,
			DestinationAddress: common.HexToAddress("0x0000000000000000000000000000000000000002"),
			Amount:             big.NewInt(200),
			Metadata:           []byte("metadata2"),
		},
	}

	// Create dummy ImportedBridgeExits
	importedBridgeExits := []*ImportedBridgeExit{
		{
			BridgeExit: &BridgeExit{
				LeafType:           LeafTypeAsset,
				TokenInfo:          createDummyTokenInfo(),
				DestinationNetwork: 3,
				DestinationAddress: common.HexToAddress("0x0000000000000000000000000000000000000003"),
				Amount:             big.NewInt(300),
				Metadata:           []byte("metadata3"),
			},
			ClaimData:   createDummyClaim(),
			GlobalIndex: createDummyGlobalIndex(),
		},
		{
			BridgeExit: &BridgeExit{
				LeafType:           LeafTypeAsset,
				TokenInfo:          createDummyTokenInfo(),
				DestinationNetwork: 4,
				DestinationAddress: common.HexToAddress("0x0000000000000000000000000000000000000004"),
				Amount:             big.NewInt(400),
				Metadata:           []byte("metadata4"),
			},
			ClaimData:   createDummyClaim(),
			GlobalIndex: createDummyGlobalIndex(),
		},
	}

	metadata := common.HexToHash("0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234")

	// Create the certificate
	certificate := &Certificate{
		NetworkID:           1,
		Height:              100,
		PrevLocalExitRoot:   prevLocalExitRoot,
		NewLocalExitRoot:    newLocalExitRoot,
		BridgeExits:         bridgeExits,
		ImportedBridgeExits: importedBridgeExits,
		Metadata:            metadata,
	}

	// Manually calculate the expected hash
	bridgeExitsHashes := [][]byte{
		bridgeExits[0].Hash().Bytes(),
		bridgeExits[1].Hash().Bytes(),
	}
	importedBridgeExitsHashes := [][]byte{
		importedBridgeExits[0].Hash().Bytes(),
		importedBridgeExits[1].Hash().Bytes(),
	}

	bridgeExitsPart := crypto.Keccak256(bridgeExitsHashes...)
	importedBridgeExitsPart := crypto.Keccak256(importedBridgeExitsHashes...)

	expectedHash := crypto.Keccak256Hash(
		cdkcommon.Uint32ToBytes(1),
		cdkcommon.Uint64ToBytes(100),
		prevLocalExitRoot[:],
		newLocalExitRoot[:],
		bridgeExitsPart,
		importedBridgeExitsPart,
	)

	// Test the certificate hash
	calculatedHash := certificate.Hash()

	require.Equal(t, calculatedHash, expectedHash)
}

func TestCertificate_HashToSign(t *testing.T) {
	c := &Certificate{
		NewLocalExitRoot: common.HexToHash("0xabcd"),
		ImportedBridgeExits: []*ImportedBridgeExit{
			{
				GlobalIndex: &GlobalIndex{
					MainnetFlag: true,
					RollupIndex: 23,
					LeafIndex:   1,
				},
			},
			{
				GlobalIndex: &GlobalIndex{
					MainnetFlag: false,
					RollupIndex: 15,
					LeafIndex:   2,
				},
			},
		},
	}

	globalIndexHashes := make([][]byte, len(c.ImportedBridgeExits))
	for i, importedBridgeExit := range c.ImportedBridgeExits {
		globalIndexHashes[i] = importedBridgeExit.GlobalIndex.Hash().Bytes()
	}

	expectedHash := crypto.Keccak256Hash(
		c.NewLocalExitRoot[:],
		crypto.Keccak256Hash(globalIndexHashes...).Bytes(),
	)

	certHash := c.HashToSign()
	require.Equal(t, expectedHash, certHash)
}

func TestClaimFromMainnnet_MarshalJSON(t *testing.T) {
	// Test data
	merkleProof := &MerkleProof{
		Root: common.HexToHash("0x1"),
		Proof: [types.DefaultHeight]common.Hash{
			common.HexToHash("0x2"),
			common.HexToHash("0x3"),
		},
	}

	l1InfoTreeLeaf := &L1InfoTreeLeaf{
		L1InfoTreeIndex: 42,
		RollupExitRoot:  [common.HashLength]byte{0xaa, 0xbb, 0xcc},
		MainnetExitRoot: [common.HashLength]byte{0xdd, 0xee, 0xff},
		Inner: &L1InfoTreeLeafInner{
			GlobalExitRoot: common.HexToHash("0x1"),
			BlockHash:      common.HexToHash("0x2"),
			Timestamp:      1672531200, // Example timestamp
		},
	}

	claim := &ClaimFromMainnnet{
		ProofLeafMER:     merkleProof,
		ProofGERToL1Root: merkleProof,
		L1Leaf:           l1InfoTreeLeaf,
	}

	// Marshal the ClaimFromMainnnet struct to JSON
	expectedJSON, err := claim.MarshalJSON()
	require.NoError(t, err)

	var actualClaim ClaimFromMainnnet
	err = json.Unmarshal(expectedJSON, &actualClaim)
	require.NoError(t, err)
}
