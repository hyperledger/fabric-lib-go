/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protoutil_test

import (
	"crypto/sha256"
	"encoding/asn1"
	"math"
	"testing"

	"github.com/hyperledger/fabric-lib-go/protoutil"
	"github.com/hyperledger/fabric-lib-go/protoutil/mocks"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var testChannelID = "myuniquetestchainid"

func TestNewBlock(t *testing.T) {
	var block *common.Block
	require.Nil(t, block.GetHeader())
	require.Nil(t, block.GetData())
	require.Nil(t, block.GetMetadata())

	data := &common.BlockData{
		Data: [][]byte{{0, 1, 2}},
	}
	block = protoutil.NewBlock(uint64(0), []byte("datahash"))
	require.Equal(t, []byte("datahash"), block.Header.PreviousHash, "Incorrect previous hash")
	require.NotNil(t, block.GetData())
	require.NotNil(t, block.GetMetadata())
	block.GetHeader().DataHash = protoutil.ComputeBlockDataHash(data)

	dataHash := protoutil.ComputeBlockDataHash(data)

	asn1Bytes, err := asn1.Marshal(struct {
		Number       int64
		PreviousHash []byte
		DataHash     []byte
	}{
		Number:       0,
		DataHash:     dataHash,
		PreviousHash: []byte("datahash"),
	})
	headerHash := sha256.Sum256(asn1Bytes)
	require.NoError(t, err)
	require.Equal(t, asn1Bytes, protoutil.BlockHeaderBytes(block.Header), "Incorrect marshaled blockheader bytes")
	require.Equal(t, headerHash[:], protoutil.BlockHeaderHash(block.Header), "Incorrect blockheader hash")
}

func TestGoodBlockHeaderBytes(t *testing.T) {
	goodBlockHeader := &common.BlockHeader{
		Number:       1,
		PreviousHash: []byte("foo"),
		DataHash:     []byte("bar"),
	}

	_ = protoutil.BlockHeaderBytes(goodBlockHeader) // Should not panic

	goodBlockHeaderMaxNumber := &common.BlockHeader{
		Number:       math.MaxUint64,
		PreviousHash: []byte("foo"),
		DataHash:     []byte("bar"),
	}

	_ = protoutil.BlockHeaderBytes(goodBlockHeaderMaxNumber) // Should not panic
}

func TestGetMetadataFromBlock(t *testing.T) {
	t.Run("new block", func(t *testing.T) {
		block := protoutil.NewBlock(0, nil)
		md, err := protoutil.GetMetadataFromBlock(block, common.BlockMetadataIndex_ORDERER)
		require.NoError(t, err, "Unexpected error extracting metadata from new block")
		require.Nil(t, md.Value, "Expected metadata field value to be nil")
		require.Equal(t, 0, len(md.Value), "Expected length of metadata field value to be 0")
		md = protoutil.GetMetadataFromBlockOrPanic(block, common.BlockMetadataIndex_ORDERER)
		require.NotNil(t, md, "Expected to get metadata from block")
	})
	t.Run("no metadata", func(t *testing.T) {
		block := protoutil.NewBlock(0, nil)
		block.Metadata = nil
		_, err := protoutil.GetMetadataFromBlock(block, common.BlockMetadataIndex_ORDERER)
		require.Error(t, err, "Expected error with nil metadata")
		require.Contains(t, err.Error(), "no metadata in block")
	})
	t.Run("no metadata at index", func(t *testing.T) {
		block := protoutil.NewBlock(0, nil)
		block.Metadata.Metadata = [][]byte{{1, 2, 3}}
		_, err := protoutil.GetMetadataFromBlock(block, common.BlockMetadataIndex_LAST_CONFIG)
		require.Error(t, err, "Expected error with nil metadata")
		require.Contains(t, err.Error(), "no metadata at index")
	})
	t.Run("malformed metadata", func(t *testing.T) {
		block := protoutil.NewBlock(0, nil)
		block.Metadata.Metadata[common.BlockMetadataIndex_ORDERER] = []byte("bad metadata")
		_, err := protoutil.GetMetadataFromBlock(block, common.BlockMetadataIndex_ORDERER)
		require.Error(t, err, "Expected error with malformed metadata")
		require.Contains(t, err.Error(), "error unmarshalling metadata at index [ORDERER]")
		require.Panics(t, func() {
			_ = protoutil.GetMetadataFromBlockOrPanic(block, common.BlockMetadataIndex_ORDERER)
		}, "Expected panic with malformed metadata")
	})
}

func TestGetConsenterMetadataFromBlock(t *testing.T) {
	cases := []struct {
		name       string
		value      []byte
		signatures []byte
		orderer    []byte
		pass       bool
	}{
		{
			name:       "empty",
			value:      nil,
			signatures: nil,
			orderer:    nil,
			pass:       true,
		},
		{
			name:  "signature only",
			value: []byte("hello"),
			signatures: protoutil.MarshalOrPanic(&common.Metadata{
				Value: protoutil.MarshalOrPanic(&common.OrdererBlockMetadata{
					ConsenterMetadata: protoutil.MarshalOrPanic(&common.Metadata{Value: []byte("hello")}),
				}),
			}),
			orderer: nil,
			pass:    true,
		},
		{
			name:  "both signatures and orderer",
			value: []byte("hello"),
			signatures: protoutil.MarshalOrPanic(&common.Metadata{
				Value: protoutil.MarshalOrPanic(&common.OrdererBlockMetadata{
					ConsenterMetadata: protoutil.MarshalOrPanic(&common.Metadata{Value: []byte("hello")}),
				}),
			}),
			orderer: protoutil.MarshalOrPanic(&common.Metadata{Value: []byte("hello")}),
			pass:    true,
		},
		{
			name:       "malformed OrdererBlockMetadata",
			signatures: protoutil.MarshalOrPanic(&common.Metadata{Value: []byte("malformed")}),
			orderer:    nil,
			pass:       false,
		},
	}

	for _, test := range cases {
		block := protoutil.NewBlock(0, nil)
		block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = test.signatures
		result, err := protoutil.GetConsenterMetadataFromBlock(block)

		if test.pass {
			require.NoError(t, err)
			require.Equal(t, result.Value, test.value)
		} else {
			require.Error(t, err)
		}
	}
}

func TestInitBlockMeta(t *testing.T) {
	// block with no metadata
	block := &common.Block{}
	protoutil.InitBlockMetadata(block)
	// should have 3 entries
	require.Equal(t, 5, len(block.Metadata.Metadata), "Expected block to have 5 metadata entries")

	// block with a single entry
	block = &common.Block{
		Metadata: &common.BlockMetadata{},
	}
	block.Metadata.Metadata = append(block.Metadata.Metadata, []byte{})
	protoutil.InitBlockMetadata(block)
	// should have 3 entries
	require.Equal(t, 5, len(block.Metadata.Metadata), "Expected block to have 5 metadata entries")
}

func TestCopyBlockMetadata(t *testing.T) {
	srcBlock := protoutil.NewBlock(0, nil)
	dstBlock := &common.Block{}

	metadata, _ := proto.Marshal(&common.Metadata{
		Value: []byte("orderer metadata"),
	})
	srcBlock.Metadata.Metadata[common.BlockMetadataIndex_ORDERER] = metadata
	protoutil.CopyBlockMetadata(srcBlock, dstBlock)

	// check that the copy worked
	require.Equal(t, len(srcBlock.Metadata.Metadata), len(dstBlock.Metadata.Metadata),
		"Expected target block to have same number of metadata entries after copy")
	require.Equal(t, metadata, dstBlock.Metadata.Metadata[common.BlockMetadataIndex_ORDERER],
		"Unexpected metadata from target block")
}

func TestGetLastConfigIndexFromBlock(t *testing.T) {
	index := uint64(2)
	block := protoutil.NewBlock(0, nil)

	t.Run("block with last config metadata in signatures field", func(t *testing.T) {
		block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&common.Metadata{
			Value: protoutil.MarshalOrPanic(&common.OrdererBlockMetadata{
				LastConfig: &common.LastConfig{Index: 2},
			}),
		})
		result, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.NoError(t, err, "Unexpected error returning last config index")
		require.Equal(t, index, result, "Unexpected last config index returned from block")
		result = protoutil.GetLastConfigIndexFromBlockOrPanic(block)
		require.Equal(t, index, result, "Unexpected last config index returned from block")
	})

	t.Run("block with malformed signatures", func(t *testing.T) {
		block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = []byte("apple")
		_, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve metadata: error unmarshalling metadata at index [SIGNATURES]")
	})

	t.Run("block with malformed orderer block metadata", func(t *testing.T) {
		block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&common.Metadata{Value: []byte("banana")})
		_, err := protoutil.GetLastConfigIndexFromBlock(block)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal orderer block metadata")
	})

}

func TestBlockSignatureVerifierEmptyMetadata(t *testing.T) {
	policies := mocks.Policy{}

	verify := protoutil.BlockSignatureVerifier(true, nil, &policies)

	header := &common.BlockHeader{}
	md := &common.BlockMetadata{}

	err := verify(header, md)
	require.ErrorContains(t, err, "no signatures in block metadata")
}

func TestBlockSignatureVerifierByIdentifier(t *testing.T) {
	consenters := []*common.Consenter{
		{
			Id:       1,
			Host:     "host1",
			Port:     8001,
			MspId:    "msp1",
			Identity: []byte("identity1"),
		},
		{
			Id:       2,
			Host:     "host2",
			Port:     8002,
			MspId:    "msp2",
			Identity: []byte("identity2"),
		},
		{
			Id:       3,
			Host:     "host3",
			Port:     8003,
			MspId:    "msp3",
			Identity: []byte("identity3"),
		},
	}

	policies := mocks.Policy{}

	verify := protoutil.BlockSignatureVerifier(true, consenters, &policies)

	header := &common.BlockHeader{}
	md := &common.BlockMetadata{
		Metadata: [][]byte{
			protoutil.MarshalOrPanic(&common.Metadata{Signatures: []*common.MetadataSignature{
				{
					Signature:        []byte{},
					IdentifierHeader: protoutil.MarshalOrPanic(&common.IdentifierHeader{Identifier: 1}),
				},
				{
					Signature:        []byte{},
					IdentifierHeader: protoutil.MarshalOrPanic(&common.IdentifierHeader{Identifier: 3}),
				},
			}}),
		},
	}

	err := verify(header, md)
	require.NoError(t, err)
	signatureSet := policies.EvaluateSignedDataArgsForCall(0)
	require.Len(t, signatureSet, 2)
	require.Equal(t, protoutil.MarshalOrPanic(&msp.SerializedIdentity{Mspid: "msp1", IdBytes: []byte("identity1")}), signatureSet[0].Identity)
	require.Equal(t, protoutil.MarshalOrPanic(&msp.SerializedIdentity{Mspid: "msp3", IdBytes: []byte("identity3")}), signatureSet[1].Identity)
}

func TestBlockSignatureVerifierByCreator(t *testing.T) {
	consenters := []*common.Consenter{
		{
			Id:       1,
			Host:     "host1",
			Port:     8001,
			MspId:    "msp1",
			Identity: []byte("identity1"),
		},
		{
			Id:       2,
			Host:     "host2",
			Port:     8002,
			MspId:    "msp2",
			Identity: []byte("identity2"),
		},
		{
			Id:       3,
			Host:     "host3",
			Port:     8003,
			MspId:    "msp3",
			Identity: []byte("identity3"),
		},
	}

	policies := mocks.Policy{}

	verify := protoutil.BlockSignatureVerifier(true, consenters, &policies)

	header := &common.BlockHeader{}
	md := &common.BlockMetadata{
		Metadata: [][]byte{
			protoutil.MarshalOrPanic(&common.Metadata{Signatures: []*common.MetadataSignature{
				{
					Signature:       []byte{},
					SignatureHeader: protoutil.MarshalOrPanic(&common.SignatureHeader{Creator: []byte("creator1")}),
				},
			}}),
		},
	}

	err := verify(header, md)
	require.NoError(t, err)
	signatureSet := policies.EvaluateSignedDataArgsForCall(0)
	require.Len(t, signatureSet, 1)
	require.Equal(t, []byte("creator1"), signatureSet[0].Identity)
}

func TestVerifyTransactionsAreWellFormed(t *testing.T) {
	originalBlock := &common.Block{
		Data: &common.BlockData{
			Data: [][]byte{
				marshalOrPanic(&common.Envelope{
					Payload:   []byte{1, 2, 3},
					Signature: []byte{4, 5, 6},
				}),
				marshalOrPanic(&common.Envelope{
					Payload:   []byte{7, 8, 9},
					Signature: []byte{10, 11, 12},
				}),
			},
		},
	}

	forgedBlock := proto.Clone(originalBlock).(*common.Block)
	tmp := make([]byte, len(forgedBlock.Data.Data[0])+len(forgedBlock.Data.Data[1]))
	copy(tmp, forgedBlock.Data.Data[0])
	copy(tmp[len(forgedBlock.Data.Data[0]):], forgedBlock.Data.Data[1])
	forgedBlock.Data.Data = [][]byte{tmp} // Replace transactions {0,1} with transaction {0 || 1}

	for _, tst := range []struct {
		name          string
		expectedError string
		block         *common.Block
	}{
		{
			name: "config block",
			block: &common.Block{Data: &common.BlockData{
				Data: [][]byte{
					protoutil.MarshalOrPanic(
						&common.Envelope{
							Payload: protoutil.MarshalOrPanic(&common.Payload{
								Header: &common.Header{
									ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
										Type: int32(common.HeaderType_CONFIG),
									}),
								},
							}),
						}),
				},
			}},
		},
		{
			name:          "no block data",
			block:         &common.Block{},
			expectedError: "empty block",
		},
		{
			name:          "no transactions",
			block:         &common.Block{Data: &common.BlockData{}},
			expectedError: "empty block",
		},
		{
			name: "single transaction",
			block: &common.Block{Data: &common.BlockData{Data: [][]byte{marshalOrPanic(&common.Envelope{
				Payload:   []byte{1, 2, 3},
				Signature: []byte{4, 5, 6},
			})}}},
		},
		{
			name:  "good block",
			block: originalBlock,
		},
		{
			name:          "forged block",
			block:         forgedBlock,
			expectedError: "transaction 0 has 10 trailing bytes",
		},
		{
			name:          "no signature",
			expectedError: "transaction 0 has no signature",
			block: &common.Block{
				Data: &common.BlockData{
					Data: [][]byte{
						marshalOrPanic(&common.Envelope{
							Payload: []byte{1, 2, 3},
						}),
					},
				},
			},
		},
		{
			name:          "no payload",
			expectedError: "transaction 0 has no payload",
			block: &common.Block{
				Data: &common.BlockData{
					Data: [][]byte{
						marshalOrPanic(&common.Envelope{
							Signature: []byte{4, 5, 6},
						}),
					},
				},
			},
		},
		{
			name:          "transaction invalid",
			expectedError: "cannot parse invalid wire-format data",
			block: &common.Block{
				Data: &common.BlockData{
					Data: [][]byte{
						marshalOrPanic(&common.Envelope{
							Payload:   []byte{1, 2, 3},
							Signature: []byte{4, 5, 6},
						})[9:],
					},
				},
			},
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			if tst.block == nil || tst.block.Data == nil {
				err := protoutil.VerifyTransactionsAreWellFormed(tst.block.Data)
				require.EqualError(t, err, "empty block")
			} else {
				err := protoutil.VerifyTransactionsAreWellFormed(tst.block.Data)
				if tst.expectedError == "" {
					require.NoError(t, err)
				} else {
					require.Contains(t, err.Error(), tst.expectedError)
				}
			}
		})
	}
}
