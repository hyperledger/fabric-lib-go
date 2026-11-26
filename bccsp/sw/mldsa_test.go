/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

// newMLDSATestCSP returns a SW BCCSP backed by a file keystore in dir.
func newMLDSATestCSP(t *testing.T, pwd []byte, dir string) bccsp.BCCSP {
	ks, err := NewFileBasedKeyStore(pwd, dir, false)
	require.NoError(t, err)
	csp, err := NewWithParams(256, "SHA2", ks)
	require.NoError(t, err)
	return csp
}

func TestMLDSAKeyGenSignVerifyAndReload(t *testing.T) {
	t.Parallel()

	params := map[string]bccsp.KeyGenOpts{
		"ML-DSA-44": &bccsp.MLDSA44KeyGenOpts{},
		"ML-DSA-65": &bccsp.MLDSA65KeyGenOpts{},
		"ML-DSA-87": &bccsp.MLDSA87KeyGenOpts{},
	}
	pwds := map[string][]byte{"plain": nil, "encrypted": []byte("secret")}

	for paramName, opts := range params {
		for pwdName, pwd := range pwds {
			t.Run(paramName+"/"+pwdName, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				csp := newMLDSATestCSP(t, pwd, dir)

				// Generate a persistent key and check it has the requested parameter set
				k, err := csp.KeyGen(opts)
				require.NoError(t, err)
				require.True(t, k.Private())
				require.Equal(t, paramName, k.(*mldsaPrivateKey).privKey.PublicKey().Parameters().String())
				pk, err := k.PublicKey()
				require.NoError(t, err)

				// Sign the full message and verify with both the private and the public key
				msg := []byte("hello post-quantum world")
				sig, err := csp.Sign(k, msg, nil)
				require.NoError(t, err)
				for _, vk := range []bccsp.Key{k, pk} {
					valid, err := csp.Verify(vk, sig, msg, nil)
					require.NoError(t, err)
					require.True(t, valid)
				}

				// A tampered message must not verify
				valid, err := csp.Verify(pk, sig, []byte("tampered"), nil)
				require.NoError(t, err)
				require.False(t, valid)

				// A fresh CSP on the same keystore must load the key by SKI and sign with it
				reloaded, err := newMLDSATestCSP(t, pwd, dir).GetKey(k.SKI())
				require.NoError(t, err)
				require.True(t, reloaded.Private())
				require.Equal(t, k.SKI(), reloaded.SKI())
				sig, err = csp.Sign(reloaded, msg, nil)
				require.NoError(t, err)
				valid, err = csp.Verify(pk, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)
			})
		}
	}
}

func TestMLDSAContextMustMatch(t *testing.T) {
	t.Parallel()

	csp := newMLDSATestCSP(t, nil, t.TempDir())
	k, err := csp.KeyGen(&bccsp.MLDSA65KeyGenOpts{Temporary: true})
	require.NoError(t, err)

	// A signature bound to a context verifies only with the same context
	msg := []byte("msg")
	sig, err := csp.Sign(k, msg, &mldsa.Options{Context: "fabric"})
	require.NoError(t, err)
	valid, err := csp.Verify(k, sig, msg, &mldsa.Options{Context: "fabric"})
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = csp.Verify(k, sig, msg, nil)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestMLDSARejectsPrehashOpts(t *testing.T) {
	t.Parallel()

	csp := newMLDSATestCSP(t, nil, t.TempDir())
	k, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("msg")
	sig, err := csp.Sign(k, msg, nil)
	require.NoError(t, err)

	// External-mu and classic hash opts are refused on both sides, so no unverifiable mode exists
	for _, opts := range []crypto.SignerOpts{crypto.MLDSAMu, crypto.SHA256} {
		_, err := csp.Sign(k, msg, opts)
		require.ErrorContains(t, err, "must not specify a hash function")
		_, err = csp.Verify(k, sig, msg, opts)
		require.ErrorContains(t, err, "must not specify a hash function")
	}

	// crypto.Hash(0), as passed by crypto/x509, means "full message" and is accepted
	sig, err = csp.Sign(k, msg, crypto.Hash(0))
	require.NoError(t, err)
	valid, err := csp.Verify(k, sig, msg, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, valid)
}

func TestMLDSAImportFromX509AndPKCS8(t *testing.T) {
	t.Parallel()

	csp := newMLDSATestCSP(t, nil, t.TempDir())

	// Build a self-signed ML-DSA certificate with the standard library
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mldsa"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, sk.PublicKey(), sk)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// The public key imported from the certificate verifies a standard library signature
	pk, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("msg")
	sig, err := sk.Sign(nil, msg, nil)
	require.NoError(t, err)
	valid, err := csp.Verify(pk, sig, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)

	// The private key imported from PKCS#8 matches the certificate and signs verifiable messages
	pkcs8, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	k, err := csp.KeyImport(pkcs8, &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, pk.SKI(), k.SKI())
	sig, err = csp.Sign(k, msg, nil)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(sk.PublicKey(), msg, sig, nil))

	// The PKIX bytes of the public key round-trip through the standard library
	raw, err := pk.Bytes()
	require.NoError(t, err)
	parsed, err := x509.ParsePKIXPublicKey(raw)
	require.NoError(t, err)
	require.True(t, sk.PublicKey().Equal(parsed))
}

func TestMLDSAPublicKeyStoreAndReload(t *testing.T) {
	t.Parallel()

	csp := newMLDSATestCSP(t, nil, t.TempDir())

	// Import a non-ephemeral public key so the keystore persists it
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	pk, err := csp.KeyImport(sk.PublicKey(), &bccsp.MLDSAGoPublicKeyImportOpts{})
	require.NoError(t, err)

	// The reloaded key is the same public key and still verifies signatures
	reloaded, err := csp.GetKey(pk.SKI())
	require.NoError(t, err)
	require.IsType(t, &mldsaPublicKey{}, reloaded)
	require.False(t, reloaded.Private())
	require.Equal(t, pk.SKI(), reloaded.SKI())
	msg := []byte("msg")
	sig, err := sk.Sign(nil, msg, nil)
	require.NoError(t, err)
	valid, err := csp.Verify(reloaded, sig, msg, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestMLDSAPEMRoundTrip(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)

	for name, pwd := range map[string][]byte{"plain": nil, "encrypted": []byte("secret")} {
		t.Run(name, func(t *testing.T) {
			// Private keys decode back to the same key
			skPEM, err := privateKeyToPEM(sk, pwd)
			require.NoError(t, err)
			skBack, err := pemToPrivateKey(skPEM, pwd)
			require.NoError(t, err)
			require.True(t, sk.Equal(skBack))

			// Public keys decode back to the same key
			pkPEM, err := publicKeyToPEM(sk.PublicKey(), pwd)
			require.NoError(t, err)
			pkBack, err := pemToPublicKey(pkPEM, pwd)
			require.NoError(t, err)
			require.True(t, sk.PublicKey().Equal(pkBack))
		})
	}

	// Nil keys are rejected instead of panicking
	_, err = privateKeyToPEM((*mldsa.PrivateKey)(nil), nil)
	require.ErrorContains(t, err, "invalid ml-dsa private key")
	_, err = publicKeyToPEM((*mldsa.PublicKey)(nil), nil)
	require.ErrorContains(t, err, "invalid ml-dsa public key")
}

func TestMLDSAPrivateKeyImportInvalidInput(t *testing.T) {
	t.Parallel()

	ki := &mldsaPrivateKeyImportOptsKeyImporter{}

	// A valid PKCS#8 blob that holds a non-ML-DSA key
	_, edSK, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(edSK)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		raw    interface{}
		errMsg string
	}{
		"wrong type": {raw: "not bytes", errMsg: "Invalid raw material. Expected byte array."},
		"empty":      {raw: []byte{}, errMsg: "Invalid raw. It must not be nil."},
		"garbage":    {raw: []byte("garbage"), errMsg: "Failed converting PKCS#8 to ML-DSA private key"},
		"non-ML-DSA": {raw: edPKCS8, errMsg: "Failed casting to ML-DSA private key"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ki.KeyImport(tc.raw, &bccsp.MLDSAPrivateKeyImportOpts{})
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

func TestMLDSACertificateViaCryptoSigner(t *testing.T) {
	t.Parallel()

	csp := newMLDSATestCSP(t, nil, t.TempDir())
	k, err := csp.KeyGen(&bccsp.MLDSA87KeyGenOpts{Temporary: true})
	require.NoError(t, err)

	// x509 signs the full TBS through the BCCSP-backed crypto.Signer, as fabric-ca does
	cs, err := signer.New(csp, k)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mldsa-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, cs.Public(), cs)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA87, cert.SignatureAlgorithm)
	require.NoError(t, cert.CheckSignatureFrom(cert))
}
