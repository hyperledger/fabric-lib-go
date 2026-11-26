/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// checkMLDSAOpts rejects any opts that announce a pre-hash (including crypto.MLDSAMu):
// this provider only does pure ML-DSA over the full message, on both sign and verify.
func checkMLDSAOpts(opts bccsp.SignerOpts) error {
	if opts != nil && opts.HashFunc() != 0 {
		return errors.New("ML-DSA signs the full message: opts must not specify a hash function")
	}
	return nil
}

// signMLDSA signs msg with pure ML-DSA. Like Ed25519, ML-DSA signs the full
// message: callers must not pre-hash it. A context string can be set via *mldsa.Options.
func signMLDSA(k *mldsa.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if err := checkMLDSAOpts(opts); err != nil {
		return nil, err
	}
	return k.Sign(rand.Reader, msg, opts)
}

// verifyMLDSA verifies a pure ML-DSA signature over the full message msg.
// An invalid signature is reported as (false, nil), like the other verifiers.
func verifyMLDSA(k *mldsa.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	if err := checkMLDSAOpts(opts); err != nil {
		return false, err
	}
	// Only a context string is meaningful for verification
	mldsaOpts, _ := opts.(*mldsa.Options)
	return mldsa.Verify(k, msg, signature, mldsaOpts) == nil, nil
}

type mldsaSigner struct{}

// Sign signs msg with the ML-DSA private key k.
func (s *mldsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signMLDSA(k.(*mldsaPrivateKey).privKey, msg, opts)
}

type mldsaPrivateKeyVerifier struct{}

// Verify verifies signature over msg using the public part of the ML-DSA private key k.
func (v *mldsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyMLDSA(k.(*mldsaPrivateKey).privKey.PublicKey(), signature, msg, opts)
}

type mldsaPublicKeyKeyVerifier struct{}

// Verify verifies signature over msg using the ML-DSA public key k.
func (v *mldsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyMLDSA(k.(*mldsaPublicKey).pubKey, signature, msg, opts)
}
