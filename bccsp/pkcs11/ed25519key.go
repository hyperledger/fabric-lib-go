/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pkcs11

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
)

type ed25519PrivateKey struct {
	ski []byte
	pub ed25519PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *ed25519PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *ed25519PrivateKey) SKI() []byte {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *ed25519PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *ed25519PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *ed25519PrivateKey) PublicKey() (bccsp.Key, error) {
	return &k.pub, nil
}

type ed25519PublicKey struct {
	ski []byte
	pub *ed25519.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *ed25519PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *ed25519PublicKey) SKI() []byte {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *ed25519PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *ed25519PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *ed25519PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
