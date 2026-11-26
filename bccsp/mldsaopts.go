/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

const (
	// MLDSA ML-DSA (FIPS 204) Algorithm, any parameter set (key import).
	MLDSA = "MLDSA"

	// MLDSA44 ML-DSA with the ML-DSA-44 parameter set
	MLDSA44 = "MLDSA44"

	// MLDSA65 ML-DSA with the ML-DSA-65 parameter set
	MLDSA65 = "MLDSA65"

	// MLDSA87 ML-DSA with the ML-DSA-87 parameter set
	MLDSA87 = "MLDSA87"
)

// MLDSA44KeyGenOpts contains options for ML-DSA key generation with the ML-DSA-44 parameter set.
type MLDSA44KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA44KeyGenOpts) Algorithm() string {
	return MLDSA44
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA44KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSA65KeyGenOpts contains options for ML-DSA key generation with the ML-DSA-65 parameter set.
type MLDSA65KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA65KeyGenOpts) Algorithm() string {
	return MLDSA65
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA65KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSA87KeyGenOpts contains options for ML-DSA key generation with the ML-DSA-87 parameter set.
type MLDSA87KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *MLDSA87KeyGenOpts) Algorithm() string {
	return MLDSA87
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSA87KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSAPrivateKeyImportOpts contains options for ML-DSA private key importation in PKCS#8 DER format.
type MLDSAPrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MLDSAPrivateKeyImportOpts) Algorithm() string {
	return MLDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSAPrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// MLDSAGoPublicKeyImportOpts contains options for ML-DSA key importation from *mldsa.PublicKey.
type MLDSAGoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *MLDSAGoPublicKeyImportOpts) Algorithm() string {
	return MLDSA
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *MLDSAGoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
