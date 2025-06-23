/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protoutil_test

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-lib-go/protoutil"
	"github.com/hyperledger/fabric-lib-go/protoutil/fakes"
	"github.com/stretchr/testify/require"
)

func TestGetPayloads(t *testing.T) {
	var txAction *peer.TransactionAction
	var err error

	// good
	ccActionBytes, _ := proto.Marshal(&peer.ChaincodeAction{
		Results: []byte("results"),
	})
	proposalResponsePayload := &peer.ProposalResponsePayload{
		Extension: ccActionBytes,
	}
	proposalResponseBytes, err := proto.Marshal(proposalResponsePayload)
	require.NoError(t, err)
	ccActionPayload := &peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponseBytes,
		},
	}
	ccActionPayloadBytes, _ := proto.Marshal(ccActionPayload)
	txAction = &peer.TransactionAction{
		Payload: ccActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.NoError(t, err, "Unexpected error getting payload bytes")
	t.Logf("error1 [%s]", err)

	// nil proposal response extension
	proposalResponseBytes, err = proto.Marshal(&peer.ProposalResponsePayload{
		Extension: nil,
	})
	require.NoError(t, err)
	ccActionPayloadBytes, _ = proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponseBytes,
		},
	})
	txAction = &peer.TransactionAction{
		Payload: ccActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.Error(t, err, "Expected error with nil proposal response extension")
	t.Logf("error2 [%s]", err)

	// malformed proposal response payload
	ccActionPayloadBytes, _ = proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: []byte("bad payload"),
		},
	})
	txAction = &peer.TransactionAction{
		Payload: ccActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.Error(t, err, "Expected error with malformed proposal response payload")
	t.Logf("error3 [%s]", err)

	// malformed proposal response payload extension
	proposalResponseBytes, _ = proto.Marshal(&peer.ProposalResponsePayload{
		Extension: []byte("bad extension"),
	})
	ccActionPayloadBytes, _ = proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponseBytes,
		},
	})
	txAction = &peer.TransactionAction{
		Payload: ccActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.Error(t, err, "Expected error with malformed proposal response extension")
	t.Logf("error4 [%s]", err)

	// nil proposal response payload extension
	proposalResponseBytes, _ = proto.Marshal(&peer.ProposalResponsePayload{
		ProposalHash: []byte("hash"),
	})
	ccActionPayloadBytes, _ = proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: proposalResponseBytes,
		},
	})
	txAction = &peer.TransactionAction{
		Payload: ccActionPayloadBytes,
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.Error(t, err, "Expected error with nil proposal response extension")
	t.Logf("error5 [%s]", err)

	// malformed transaction action payload
	txAction = &peer.TransactionAction{
		Payload: []byte("bad payload"),
	}
	_, _, err = protoutil.GetPayloads(txAction)
	require.Error(t, err, "Expected error with malformed transaction action payload")
	t.Logf("error6 [%s]", err)
}

func TestDeduplicateEndorsements(t *testing.T) {
	signID := &fakes.SignerSerializer{}
	signID.SerializeReturns([]byte("signer"), nil)
	signerBytes, err := signID.Serialize()
	require.NoError(t, err, "Unexpected error serializing signing identity")

	proposal := &peer.Proposal{
		Header: protoutil.MarshalOrPanic(&common.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
				Extension: protoutil.MarshalOrPanic(&peer.ChaincodeHeaderExtension{}),
			}),
			SignatureHeader: protoutil.MarshalOrPanic(&common.SignatureHeader{
				Creator: signerBytes,
			}),
		}),
	}
	responses := []*peer.ProposalResponse{
		{Payload: []byte("payload"), Endorsement: &peer.Endorsement{Endorser: []byte{5, 4, 3}}, Response: &peer.Response{Status: int32(200)}},
		{Payload: []byte("payload"), Endorsement: &peer.Endorsement{Endorser: []byte{5, 4, 3}}, Response: &peer.Response{Status: int32(200)}},
	}

	transaction, err := protoutil.CreateSignedTx(proposal, signID, responses...)
	require.NoError(t, err)
	require.True(t, proto.Equal(transaction, transaction), "got: %#v, want: %#v", transaction, transaction)

	pl := protoutil.UnmarshalPayloadOrPanic(transaction.Payload)
	tx, err := protoutil.UnmarshalTransaction(pl.Data)
	require.NoError(t, err)
	ccap, err := protoutil.UnmarshalChaincodeActionPayload(tx.Actions[0].Payload)
	require.NoError(t, err)
	require.Len(t, ccap.Action.Endorsements, 1)
	require.Equal(t, []byte{5, 4, 3}, ccap.Action.Endorsements[0].Endorser)
}

func TestCreateSignedTx(t *testing.T) {
	var err error
	prop := &peer.Proposal{}

	signID := &fakes.SignerSerializer{}
	signID.SerializeReturns([]byte("signer"), nil)
	signerBytes, err := signID.Serialize()
	require.NoError(t, err, "Unexpected error serializing signing identity")

	ccHeaderExtensionBytes := protoutil.MarshalOrPanic(&peer.ChaincodeHeaderExtension{})
	chdrBytes := protoutil.MarshalOrPanic(&common.ChannelHeader{
		Extension: ccHeaderExtensionBytes,
	})
	shdrBytes := protoutil.MarshalOrPanic(&common.SignatureHeader{
		Creator: signerBytes,
	})
	responses := []*peer.ProposalResponse{{}}

	// malformed signature header
	headerBytes := protoutil.MarshalOrPanic(&common.Header{
		SignatureHeader: []byte("bad signature header"),
	})
	prop.Header = headerBytes
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with malformed signature header")

	// set up the header bytes for the remaining tests
	headerBytes, _ = proto.Marshal(&common.Header{
		ChannelHeader:   chdrBytes,
		SignatureHeader: shdrBytes,
	})
	prop.Header = headerBytes

	nonMatchingTests := []struct {
		responses     []*peer.ProposalResponse
		expectedError string
	}{
		// good response followed by bad response
		{
			[]*peer.ProposalResponse{
				{Payload: []byte("payload"), Response: &peer.Response{Status: int32(200)}},
				{Payload: []byte{}, Response: &peer.Response{Status: int32(500), Message: "failed to endorse"}},
			},
			"proposal response was not successful, error code 500, msg failed to endorse",
		},
		// bad response followed by good response
		{
			[]*peer.ProposalResponse{
				{Payload: []byte{}, Response: &peer.Response{Status: int32(500), Message: "failed to endorse"}},
				{Payload: []byte("payload"), Response: &peer.Response{Status: int32(200)}},
			},
			"proposal response was not successful, error code 500, msg failed to endorse",
		},
	}
	for i, nonMatchingTest := range nonMatchingTests {
		_, err = protoutil.CreateSignedTx(prop, signID, nonMatchingTest.responses...)
		require.EqualErrorf(t, err, nonMatchingTest.expectedError, "Expected non-matching response error '%v' for test %d", nonMatchingTest.expectedError, i)
	}

	// good responses, but different payloads
	responses = []*peer.ProposalResponse{
		{Payload: []byte("payload"), Response: &peer.Response{Status: int32(200)}},
		{Payload: []byte("payload2"), Response: &peer.Response{Status: int32(200)}},
	}
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	if err == nil || strings.HasPrefix(err.Error(), "ProposalResponsePayloads do not match (base64):") == false {
		require.FailNow(t, "Error is expected when response payloads do not match")
	}

	// no endorsement
	responses = []*peer.ProposalResponse{{
		Payload: []byte("payload"),
		Response: &peer.Response{
			Status: int32(200),
		},
	}}
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with no endorsements")

	// success
	responses = []*peer.ProposalResponse{{
		Payload:     []byte("payload"),
		Endorsement: &peer.Endorsement{},
		Response: &peer.Response{
			Status: int32(200),
		},
	}}
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.NoError(t, err, "Unexpected error creating signed transaction")
	t.Logf("error: [%s]", err)

	//
	//
	// additional failure cases
	prop = &peer.Proposal{}
	responses = []*peer.ProposalResponse{}
	// no proposal responses
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with no proposal responses")

	// missing proposal header
	responses = append(responses, &peer.ProposalResponse{})
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with no proposal header")

	// bad proposal payload
	prop.Payload = []byte("bad payload")
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with malformed proposal payload")

	// bad payload header
	prop.Header = []byte("bad header")
	_, err = protoutil.CreateSignedTx(prop, signID, responses...)
	require.Error(t, err, "Expected error with malformed proposal header")
}

func TestCreateSignedTxNoSigner(t *testing.T) {
	_, err := protoutil.CreateSignedTx(nil, nil, &peer.ProposalResponse{})
	require.ErrorContains(t, err, "signer is required when creating a signed transaction")
}

func TestCreateSignedTxStatus(t *testing.T) {
	serializedExtension, err := proto.Marshal(&peer.ChaincodeHeaderExtension{})
	require.NoError(t, err)
	serializedChannelHeader, err := proto.Marshal(&common.ChannelHeader{
		Extension: serializedExtension,
	})
	require.NoError(t, err)

	signingID := &fakes.SignerSerializer{}
	signingID.SerializeReturns([]byte("signer"), nil)
	serializedSigningID, err := signingID.Serialize()
	require.NoError(t, err)
	serializedSignatureHeader, err := proto.Marshal(&common.SignatureHeader{
		Creator: serializedSigningID,
	})
	require.NoError(t, err)

	header := &common.Header{
		ChannelHeader:   serializedChannelHeader,
		SignatureHeader: serializedSignatureHeader,
	}

	serializedHeader, err := proto.Marshal(header)
	require.NoError(t, err)

	proposal := &peer.Proposal{
		Header: serializedHeader,
	}

	tests := []struct {
		status      int32
		expectedErr string
	}{
		{status: 0, expectedErr: "proposal response was not successful, error code 0, msg response-message"},
		{status: 199, expectedErr: "proposal response was not successful, error code 199, msg response-message"},
		{status: 200, expectedErr: ""},
		{status: 201, expectedErr: ""},
		{status: 399, expectedErr: ""},
		{status: 400, expectedErr: "proposal response was not successful, error code 400, msg response-message"},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(int(tc.status)), func(t *testing.T) {
			response := &peer.ProposalResponse{
				Payload:     []byte("payload"),
				Endorsement: &peer.Endorsement{},
				Response: &peer.Response{
					Status:  tc.status,
					Message: "response-message",
				},
			}

			_, err := protoutil.CreateSignedTx(proposal, signingID, response)
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestCreateSignedEnvelope(t *testing.T) {
	var env *common.Envelope
	channelID := "mychannelID"
	msg := &common.ConfigEnvelope{}

	id := &fakes.SignerSerializer{}
	id.SignReturnsOnCall(0, []byte("goodsig"), nil)
	id.SignReturnsOnCall(1, nil, errors.New("bad signature"))
	env, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG, channelID,
		id, msg, int32(1), uint64(1))
	require.NoError(t, err, "Unexpected error creating signed envelope")
	require.NotNil(t, env, "Envelope should not be nil")
	// mock sign returns the bytes to be signed
	require.Equal(t, []byte("goodsig"), env.Signature, "Unexpected signature returned")
	payload := &common.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	require.NoError(t, err, "Failed to unmarshal payload")
	data := &common.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, data)
	require.NoError(t, err, "Expected payload data to be a config envelope")
	require.Equal(t, msg, data, "Payload data does not match expected value")

	_, err = protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG, channelID,
		id, &common.ConfigEnvelope{}, int32(1), uint64(1))
	require.Error(t, err, "Expected sign error")
}

func TestCreateSignedEnvelopeNilSigner(t *testing.T) {
	var env *common.Envelope
	channelID := "mychannelID"
	msg := &common.ConfigEnvelope{}

	env, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG, channelID,
		nil, msg, int32(1), uint64(1))
	require.NoError(t, err, "Unexpected error creating signed envelope")
	require.NotNil(t, env, "Envelope should not be nil")
	require.Empty(t, env.Signature, "Signature should have been empty")
	payload := &common.Payload{}
	err = proto.Unmarshal(env.Payload, payload)
	require.NoError(t, err, "Failed to unmarshal payload")
	data := &common.ConfigEnvelope{}
	err = proto.Unmarshal(payload.Data, data)
	require.NoError(t, err, "Expected payload data to be a config envelope")
	require.Equal(t, msg, data, "Payload data does not match expected value")
}

func TestGetSignedProposal(t *testing.T) {
	var signedProp *peer.SignedProposal
	var err error

	sig := []byte("signature")

	signID := &fakes.SignerSerializer{}
	signID.SignReturns(sig, nil)

	prop := &peer.Proposal{}
	propBytes, _ := proto.Marshal(prop)
	signedProp, err = protoutil.GetSignedProposal(prop, signID)
	require.NoError(t, err, "Unexpected error getting signed proposal")
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes did not match expected value")
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected value")

	_, err = protoutil.GetSignedProposal(nil, signID)
	require.Error(t, err, "Expected error with nil proposal")
	_, err = protoutil.GetSignedProposal(prop, nil)
	require.Error(t, err, "Expected error with nil signing identity")
}

func TestMockSignedEndorserProposalOrPanic(t *testing.T) {
	var prop *peer.Proposal
	var signedProp *peer.SignedProposal

	ccProposal := &peer.ChaincodeProposalPayload{}
	cis := &peer.ChaincodeInvocationSpec{}
	chainID := "testchannelid"
	sig := []byte("signature")
	creator := []byte("creator")
	cs := &peer.ChaincodeSpec{
		ChaincodeId: &peer.ChaincodeID{
			Name: "mychaincode",
		},
	}

	signedProp, prop = protoutil.MockSignedEndorserProposalOrPanic(chainID, cs,
		creator, sig)
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected result")
	propBytes, _ := proto.Marshal(prop)
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes do not match expected value")
	err := proto.Unmarshal(prop.Payload, ccProposal)
	require.NoError(t, err, "Expected ChaincodeProposalPayload")
	err = proto.Unmarshal(ccProposal.Input, cis)
	require.NoError(t, err, "Expected ChaincodeInvocationSpec")
	require.Equal(t, cs.ChaincodeId.Name, cis.ChaincodeSpec.ChaincodeId.Name,
		"Chaincode name did not match expected value")
}

func TestMockSignedEndorserProposal2OrPanic(t *testing.T) {
	var prop *peer.Proposal
	var signedProp *peer.SignedProposal

	ccProposal := &peer.ChaincodeProposalPayload{}
	cis := &peer.ChaincodeInvocationSpec{}
	chainID := "testchannelid"
	sig := []byte("signature")
	signID := &fakes.SignerSerializer{}
	signID.SignReturns(sig, nil)

	signedProp, prop = protoutil.MockSignedEndorserProposal2OrPanic(chainID,
		&peer.ChaincodeSpec{}, signID)
	require.Equal(t, sig, signedProp.Signature,
		"Signature did not match expected result")
	propBytes, _ := proto.Marshal(prop)
	require.Equal(t, propBytes, signedProp.ProposalBytes,
		"Proposal bytes do not match expected value")
	err := proto.Unmarshal(prop.Payload, ccProposal)
	require.NoError(t, err, "Expected ChaincodeProposalPayload")
	err = proto.Unmarshal(ccProposal.Input, cis)
	require.NoError(t, err, "Expected ChaincodeInvocationSpec")
}

func TestGetBytesProposalPayloadForTx(t *testing.T) {
	input := &peer.ChaincodeProposalPayload{
		Input:        []byte("input"),
		TransientMap: make(map[string][]byte),
	}
	expected, _ := proto.Marshal(&peer.ChaincodeProposalPayload{
		Input: []byte("input"),
	})

	result, err := protoutil.GetBytesProposalPayloadForTx(input)
	require.NoError(t, err, "Unexpected error getting proposal payload")
	require.Equal(t, expected, result, "Payload does not match expected value")

	_, err = protoutil.GetBytesProposalPayloadForTx(nil)
	require.Error(t, err, "Expected error with nil proposal payload")
}

func TestGetProposalHash2(t *testing.T) {
	expectedHashHex := "7b622ef4e1ab9b7093ec3bbfbca17d5d6f14a437914a6839319978a7034f7960"
	expectedHash, _ := hex.DecodeString(expectedHashHex)
	hdr := &common.Header{
		ChannelHeader:   []byte("chdr"),
		SignatureHeader: []byte("shdr"),
	}
	propHash, err := protoutil.GetProposalHash2(hdr, []byte("ccproppayload"))
	require.NoError(t, err, "Unexpected error getting hash2 for proposal")
	require.Equal(t, expectedHash, propHash, "Proposal hash did not match expected hash")

	_, err = protoutil.GetProposalHash2(&common.Header{}, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with nil arguments")
}

func TestGetProposalHash1(t *testing.T) {
	expectedHashHex := "d4c1e3cac2105da5fddc2cfe776d6ec28e4598cf1e6fa51122c7f70d8076437b"
	expectedHash, _ := hex.DecodeString(expectedHashHex)
	hdr := &common.Header{
		ChannelHeader:   []byte("chdr"),
		SignatureHeader: []byte("shdr"),
	}

	ccProposal, _ := proto.Marshal(&peer.ChaincodeProposalPayload{})

	propHash, err := protoutil.GetProposalHash1(hdr, ccProposal)
	require.NoError(t, err, "Unexpected error getting hash for proposal")
	require.Equal(t, expectedHash, propHash, "Proposal hash did not match expected hash")

	_, err = protoutil.GetProposalHash1(hdr, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with malformed chaincode proposal payload")

	_, err = protoutil.GetProposalHash1(&common.Header{}, []byte("ccproppayload"))
	require.Error(t, err, "Expected error with nil arguments")
}

func TestGetorComputeTxIDFromEnvelope(t *testing.T) {
	t.Run("txID is present in the envelope", func(t *testing.T) {
		txID := "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492"
		envelopeBytes := createSampleTxEnvelopeBytes(txID)
		actualTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(envelopeBytes)
		require.Nil(t, err)
		require.Equal(t, "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492", actualTxID)
	})

	t.Run("txID is not present in the envelope", func(t *testing.T) {
		txID := ""
		envelopeBytes := createSampleTxEnvelopeBytes(txID)
		actualTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(envelopeBytes)
		require.Nil(t, err)
		require.Equal(t, "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492", actualTxID)
	})
}

func createSampleTxEnvelopeBytes(txID string) []byte {
	chdr := &common.ChannelHeader{
		TxId: "709184f9d24f6ade8fcd4d6521a6eef295fef6c2e67216c58b68ac15e8946492",
	}
	chdrBytes := protoutil.MarshalOrPanic(chdr)

	shdr := &common.SignatureHeader{
		Nonce:   []byte("nonce"),
		Creator: []byte("creator"),
	}
	shdrBytes := protoutil.MarshalOrPanic(shdr)

	hdr := &common.Header{
		ChannelHeader:   chdrBytes,
		SignatureHeader: shdrBytes,
	}

	payload := &common.Payload{
		Header: hdr,
	}
	payloadBytes := protoutil.MarshalOrPanic(payload)

	envelope := &common.Envelope{
		Payload: payloadBytes,
	}
	return protoutil.MarshalOrPanic(envelope)
}
