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

// SKI returns the subject key identifier of this key:
// the SHA-256 of the raw public key encoding, as for Ed25519.
func (k *mldsaPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	hash := sha256.Sum256(k.privKey.PublicKey().Bytes())
	return hash[:]
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
func (k *mldsaPrivateKey) PublicKey() (bccsp.Key, error) {
	return &mldsaPublicKey{k.privKey.PublicKey()}, nil
}

type mldsaPublicKey struct {
	pubKey *mldsa.PublicKey
}

// Bytes returns the public key in PKIX DER format.
func (k *mldsaPublicKey) Bytes() ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return raw, nil
}

// SKI returns the subject key identifier of this key:
// the SHA-256 of the raw public key encoding, as for Ed25519.
func (k *mldsaPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	hash := sha256.Sum256(k.pubKey.Bytes())
	return hash[:]
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
func (k *mldsaPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
