/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

// mldsaOptions maps signer options to ML-DSA options.
// Only pure ML-DSA is supported: msg is the full message, not a digest.
func mldsaOptions(opts bccsp.SignerOpts) (*mldsa.Options, error) {
	if opts == nil {
		return nil, nil
	}
	if o, ok := opts.(*mldsa.Options); ok {
		return o, nil
	}
	if opts.HashFunc() != 0 {
		return nil, fmt.Errorf("ML-DSA signs the full message, hash function [%v] not supported", opts.HashFunc())
	}
	return nil, nil
}

func signMLDSA(k *mldsa.PrivateKey, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("invalid ML-DSA private key. It must be different from nil")
	}
	o, err := mldsaOptions(opts)
	if err != nil {
		return nil, err
	}
	return k.Sign(rand.Reader, msg, o)
}

// verifyMLDSA returns an error for invalid inputs, and false for an invalid signature.
// mldsa.Verify does not tell the two apart, so the inputs are checked first.
func verifyMLDSA(k *mldsa.PublicKey, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	if k == nil || *k == (mldsa.PublicKey{}) {
		return false, errors.New("invalid ML-DSA public key. It must be different from nil or zero")
	}
	o, err := mldsaOptions(opts)
	if err != nil {
		return false, err
	}
	if o != nil && len(o.Context) > 255 {
		return false, fmt.Errorf("ML-DSA context too long [%d bytes], the maximum is 255", len(o.Context))
	}
	return mldsa.Verify(k, msg, signature, o) == nil, nil
}

type mldsaSigner struct{}

func (s *mldsaSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signMLDSA(k.(*mldsaPrivateKey).privKey, msg, opts)
}

type mldsaPrivateKeyVerifier struct{}

func (v *mldsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	sk := k.(*mldsaPrivateKey).privKey
	if sk == nil {
		return false, errors.New("invalid ML-DSA private key. It must be different from nil")
	}
	return verifyMLDSA(sk.PublicKey(), signature, msg, opts)
}

type mldsaPublicKeyKeyVerifier struct{}

func (v *mldsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyMLDSA(k.(*mldsaPublicKey).pubKey, signature, msg, opts)
}

type mldsaKeyGenerator struct {
	params mldsa.Parameters
}

func (kg *mldsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := mldsa.GenerateKey(kg.params)
	if err != nil {
		return nil, fmt.Errorf("Failed generating %s key: [%s]", kg.params, err)
	}

	return &mldsaPrivateKey{privKey}, nil
}

type mldsaPrivateKeyImportOptsKeyImporter struct{}

func (*mldsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[MLDSAPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[MLDSAPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKCS#8 to ML-DSA private key [%s]", err)
	}

	mldsaSK, ok := lowLevelKey.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ML-DSA private key. Invalid raw material.")
	}

	return &mldsaPrivateKey{mldsaSK}, nil
}

type mldsaGoPublicKeyImportOptsKeyImporter struct{}

func (*mldsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*mldsa.PublicKey)
	if !ok || lowLevelKey == nil {
		return nil, errors.New("Invalid raw material. Expected *mldsa.PublicKey.")
	}

	return &mldsaPublicKey{lowLevelKey}, nil
}
