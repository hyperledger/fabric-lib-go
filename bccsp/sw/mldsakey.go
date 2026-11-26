/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

type mldsaPrivateKey struct {
	privKey *mldsa.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *mldsaPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *mldsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	return mldsaSKI(k.privKey.PublicKey())
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *mldsaPrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mldsaPrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mldsaPrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("invalid ML-DSA private key. It must be different from nil")
	}
	return &mldsaPublicKey{k.privKey.PublicKey()}, nil
}

type mldsaPublicKey struct {
	pubKey *mldsa.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *mldsaPublicKey) Bytes() (raw []byte, err error) {
	if k.pubKey == nil {
		return nil, errors.New("invalid ML-DSA public key. It must be different from nil")
	}
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *mldsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	return mldsaSKI(k.pubKey)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *mldsaPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *mldsaPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *mldsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

// mldsaSKI hashes the FIPS 204 public key encoding, as done for Ed25519.
func mldsaSKI(pk *mldsa.PublicKey) []byte {
	hash := sha256.New()
	hash.Write(pk.Bytes())
	return hash.Sum(nil)
}
