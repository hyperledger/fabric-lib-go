/*
Copyright Quantova Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"encoding/hex"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/mocks"
	"github.com/stretchr/testify/require"
)

// Known answer vectors for the hash algorithms exposed by the software
// provider. SHA256 and SHA384 digests are the published examples in FIPS 180-4.
// SHA3_256 and SHA3_384 digests are the published examples in FIPS 202. The
// SHA3 family shares the Keccak permutation used by the FIPS 204 and FIPS 205
// post quantum signature standards, so pinning its output keeps that
// foundation standards correct as the provider evolves.
var (
	katEmpty    = []byte("")
	katABC      = []byte("abc")
	katTwoBlock = []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
)

type hashKnownAnswer struct {
	name   string
	opts   bccsp.HashOpts
	input  []byte
	digest string
}

var hashKnownAnswers = []hashKnownAnswer{
	{"SHA256/empty", &bccsp.SHA256Opts{}, katEmpty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"SHA256/abc", &bccsp.SHA256Opts{}, katABC, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{"SHA256/twoblock", &bccsp.SHA256Opts{}, katTwoBlock, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	{"SHA384/empty", &bccsp.SHA384Opts{}, katEmpty, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
	{"SHA384/abc", &bccsp.SHA384Opts{}, katABC, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
	{"SHA384/twoblock", &bccsp.SHA384Opts{}, katTwoBlock, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"},
	{"SHA3_256/empty", &bccsp.SHA3_256Opts{}, katEmpty, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
	{"SHA3_256/abc", &bccsp.SHA3_256Opts{}, katABC, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
	{"SHA3_256/twoblock", &bccsp.SHA3_256Opts{}, katTwoBlock, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"},
	{"SHA3_384/empty", &bccsp.SHA3_384Opts{}, katEmpty, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
	{"SHA3_384/abc", &bccsp.SHA3_384Opts{}, katABC, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
	{"SHA3_384/twoblock", &bccsp.SHA3_384Opts{}, katTwoBlock, "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"},
}

func TestHashKnownAnswers(t *testing.T) {
	t.Parallel()

	csp, err := NewWithParams(256, "SHA2", &mocks.KeyStore{})
	require.NoError(t, err)

	for _, tc := range hashKnownAnswers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			digest, err := csp.Hash(tc.input, tc.opts)
			require.NoError(t, err)
			require.Equal(t, tc.digest, hex.EncodeToString(digest))
		})
	}
}

func TestGetHashKnownAnswers(t *testing.T) {
	t.Parallel()

	csp, err := NewWithParams(256, "SHA2", &mocks.KeyStore{})
	require.NoError(t, err)

	for _, tc := range hashKnownAnswers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, err := csp.GetHash(tc.opts)
			require.NoError(t, err)

			_, err = h.Write(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.digest, hex.EncodeToString(h.Sum(nil)))
		})
	}
}
