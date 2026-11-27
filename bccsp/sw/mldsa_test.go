/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

var mldsaKeyGenOpts = map[string]bccsp.KeyGenOpts{
	"ML-DSA-44": &bccsp.MLDSA44KeyGenOpts{Temporary: true},
	"ML-DSA-65": &bccsp.MLDSA65KeyGenOpts{Temporary: true},
	"ML-DSA-87": &bccsp.MLDSA87KeyGenOpts{Temporary: true},
}

func newMLDSATestCSP(t *testing.T, ks bccsp.KeyStore) bccsp.BCCSP {
	t.Helper()
	csp, err := NewDefaultSecurityLevelWithKeystore(ks)
	require.NoError(t, err)
	return csp
}

func TestMLDSASignVerify(t *testing.T) {
	t.Parallel()

	for name, opts := range mldsaKeyGenOpts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			csp := newMLDSATestCSP(t, NewDummyKeyStore())

			k, err := csp.KeyGen(opts)
			require.NoError(t, err)
			require.True(t, k.Private())
			require.False(t, k.Symmetric())
			pk, err := k.PublicKey()
			require.NoError(t, err)
			require.Equal(t, k.SKI(), pk.SKI())

			msg := []byte("hello world")
			sig, err := csp.Sign(k, msg, nil)
			require.NoError(t, err)
			require.Equal(t, k.(*mldsaPrivateKey).privKey.PublicKey().Parameters().SignatureSize(), len(sig))

			for _, key := range []bccsp.Key{k, pk} {
				valid, err := csp.Verify(key, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)

				valid, err = csp.Verify(key, sig, []byte("tampered"), nil)
				require.NoError(t, err)
				require.False(t, valid)

				tampered := append([]byte(nil), sig...)
				tampered[0] ^= 0xff
				valid, err = csp.Verify(key, tampered, msg, nil)
				require.NoError(t, err)
				require.False(t, valid)
			}

			other, err := csp.KeyGen(opts)
			require.NoError(t, err)
			valid, err := csp.Verify(other, sig, msg, nil)
			require.NoError(t, err)
			require.False(t, valid)
		})
	}
}

func TestMLDSAOptions(t *testing.T) {
	t.Parallel()
	csp := newMLDSATestCSP(t, NewDummyKeyStore())

	k, err := csp.KeyGen(&bccsp.MLDSA65KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("hello world")

	// The context must match.
	sig, err := csp.Sign(k, msg, &mldsa.Options{Context: "fabric"})
	require.NoError(t, err)
	valid, err := csp.Verify(k, sig, msg, &mldsa.Options{Context: "fabric"})
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = csp.Verify(k, sig, msg, nil)
	require.NoError(t, err)
	require.False(t, valid)

	// Pre-hashed messages are rejected.
	_, err = csp.Sign(k, msg, crypto.SHA256)
	require.ErrorContains(t, err, "ML-DSA signs the full message")
	_, err = csp.Verify(k, sig, msg, crypto.SHA256)
	require.ErrorContains(t, err, "ML-DSA signs the full message")

	// Zero hash function signs the full message.
	sig, err = csp.Sign(k, msg, crypto.Hash(0))
	require.NoError(t, err)
	valid, err = csp.Verify(k, sig, msg, crypto.Hash(0))
	require.NoError(t, err)
	require.True(t, valid)
}

func TestMLDSAInvalidInputs(t *testing.T) {
	t.Parallel()
	csp := newMLDSATestCSP(t, NewDummyKeyStore())

	k, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	msg := []byte("hello world")
	sig, err := csp.Sign(k, msg, nil)
	require.NoError(t, err)

	// A context longer than 255 bytes is an error, not an invalid signature.
	_, err = csp.Verify(k, sig, msg, &mldsa.Options{Context: strings.Repeat("x", 256)})
	require.ErrorContains(t, err, "ML-DSA context too long")

	// Nil and zero keys are errors, not panics or invalid signatures.
	_, err = csp.Verify(&mldsaPublicKey{&mldsa.PublicKey{}}, sig, msg, nil)
	require.ErrorContains(t, err, "invalid ML-DSA public key")
	_, err = csp.Verify(&mldsaPublicKey{}, sig, msg, nil)
	require.ErrorContains(t, err, "invalid ML-DSA public key")
	_, err = csp.Verify(&mldsaPrivateKey{}, sig, msg, nil)
	require.ErrorContains(t, err, "invalid ML-DSA private key")
	_, err = csp.Sign(&mldsaPrivateKey{}, msg, nil)
	require.ErrorContains(t, err, "invalid ML-DSA private key")
	_, err = (&mldsaPrivateKey{}).PublicKey()
	require.ErrorContains(t, err, "invalid ML-DSA private key")
	_, err = (&mldsaPublicKey{}).Bytes()
	require.ErrorContains(t, err, "invalid ML-DSA public key")
}

func TestMLDSAKeyImport(t *testing.T) {
	t.Parallel()
	csp := newMLDSATestCSP(t, NewDummyKeyStore())

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	// PKCS#8 private key
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	require.NoError(t, err)
	k, err := csp.KeyImport(der, &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.True(t, k.Private())
	require.Equal(t, mldsaSKI(sk.PublicKey()), k.SKI())

	// Go public key
	pk, err := csp.KeyImport(sk.PublicKey(), &bccsp.MLDSAGoPublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, k.SKI(), pk.SKI())
	raw, err := pk.Bytes()
	require.NoError(t, err)
	parsed, err := x509.ParsePKIXPublicKey(raw)
	require.NoError(t, err)
	require.True(t, sk.PublicKey().Equal(parsed))

	// X.509 certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mldsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, sk.PublicKey(), sk)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	certKey, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.False(t, certKey.Private())
	require.Equal(t, k.SKI(), certKey.SKI())

	sig, err := csp.Sign(k, []byte("msg"), nil)
	require.NoError(t, err)
	valid, err := csp.Verify(certKey, sig, []byte("msg"), nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestMLDSAKeyImportInvalid(t *testing.T) {
	t.Parallel()
	csp := newMLDSATestCSP(t, NewDummyKeyStore())

	_, err := csp.KeyImport("not bytes", &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Invalid raw material. Expected byte array.")
	_, err = csp.KeyImport([]byte{}, &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Invalid raw. It must not be nil.")
	_, err = csp.KeyImport([]byte("garbage"), &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Failed converting PKCS#8 to ML-DSA private key")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	_, err = csp.KeyImport(ecDER, &bccsp.MLDSAPrivateKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Failed casting to ML-DSA private key")

	_, err = csp.KeyImport(&ecKey.PublicKey, &bccsp.MLDSAGoPublicKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Expected *mldsa.PublicKey")
	_, err = csp.KeyImport((*mldsa.PublicKey)(nil), &bccsp.MLDSAGoPublicKeyImportOpts{Temporary: true})
	require.ErrorContains(t, err, "Expected *mldsa.PublicKey")
}

func TestMLDSAFileKeyStore(t *testing.T) {
	t.Parallel()

	pwds := map[string][]byte{"plain": nil, "encrypted": []byte("password")}
	for name, opts := range mldsaKeyGenOpts {
		for pwdName, pwd := range pwds {
			t.Run(name+"/"+pwdName, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				ks, err := NewFileBasedKeyStore(pwd, dir, false)
				require.NoError(t, err)
				csp := newMLDSATestCSP(t, ks)

				// The CSP stores the generated private key.
				k, err := csp.KeyGen(opts)
				require.NoError(t, err)
				require.NoError(t, ks.StoreKey(k))

				// A fresh keystore on the same directory loads it by SKI.
				reloadKS, err := NewFileBasedKeyStore(pwd, dir, false)
				require.NoError(t, err)
				loaded, err := reloadKS.GetKey(k.SKI())
				require.NoError(t, err)
				require.IsType(t, &mldsaPrivateKey{}, loaded)
				require.True(t, k.(*mldsaPrivateKey).privKey.Equal(loaded.(*mldsaPrivateKey).privKey))

				// The reloaded key signs.
				msg := []byte("msg")
				sig, err := newMLDSATestCSP(t, reloadKS).Sign(loaded, msg, nil)
				require.NoError(t, err)
				valid, err := csp.Verify(k, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)

				// Public keys are stored too.
				pk, err := k.PublicKey()
				require.NoError(t, err)
				pubKS, err := NewFileBasedKeyStore(pwd, t.TempDir(), false)
				require.NoError(t, err)
				require.NoError(t, pubKS.StoreKey(pk))
				loadedPK, err := pubKS.GetKey(pk.SKI())
				require.NoError(t, err)
				require.IsType(t, &mldsaPublicKey{}, loadedPK)
				require.True(t, pk.(*mldsaPublicKey).pubKey.Equal(loadedPK.(*mldsaPublicKey).pubKey))
			})
		}
	}
}

func TestMLDSAKeyStoreSearch(t *testing.T) {
	t.Parallel()

	// Keys written by tools such as cryptogen do not use the <ski>_sk file name.
	dir := t.TempDir()
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	raw, err := privateKeyToPEM(sk, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "priv_sk"), raw, 0o600))

	ks, err := NewFileBasedKeyStore(nil, dir, true)
	require.NoError(t, err)
	k, err := ks.GetKey(mldsaSKI(sk.PublicKey()))
	require.NoError(t, err)
	require.True(t, sk.Equal(k.(*mldsaPrivateKey).privKey))

	_, err = ks.GetKey([]byte(hex.EncodeToString([]byte("missing"))))
	require.ErrorContains(t, err, "not found")
}

func TestMLDSAPEM(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	for _, pwd := range [][]byte{nil, []byte("password")} {
		raw, err := privateKeyToPEM(sk, pwd)
		require.NoError(t, err)
		key, err := pemToPrivateKey(raw, pwd)
		require.NoError(t, err)
		require.True(t, sk.Equal(key))

		raw, err = publicKeyToPEM(sk.PublicKey(), pwd)
		require.NoError(t, err)
		pub, err := pemToPublicKey(raw, pwd)
		require.NoError(t, err)
		require.True(t, sk.PublicKey().Equal(pub))
	}

	der, err := privateKeyToDER(sk)
	require.NoError(t, err)
	key, err := derToPrivateKey(der)
	require.NoError(t, err)
	require.True(t, sk.Equal(key))

	_, err = privateKeyToPEM((*mldsa.PrivateKey)(nil), nil)
	require.Error(t, err)
	_, err = publicKeyToPEM((*mldsa.PublicKey)(nil), nil)
	require.Error(t, err)
}

func TestMLDSACryptoSigner(t *testing.T) {
	t.Parallel()
	csp := newMLDSATestCSP(t, NewDummyKeyStore())

	k, err := csp.KeyGen(&bccsp.MLDSA65KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	s, err := signer.New(csp, k)
	require.NoError(t, err)
	pub, ok := s.Public().(*mldsa.PublicKey)
	require.True(t, ok)

	msg := []byte("hello world")
	sig, err := s.Sign(rand.Reader, msg, nil)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, msg, sig, nil))
}
