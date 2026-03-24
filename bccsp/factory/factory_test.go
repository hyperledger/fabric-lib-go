/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkcs11"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	var yamlBCCSP *FactoryOpts

	yamlCFG := `
BCCSP:
    default: SW
    SW:
        Hash: SHA3
        Security: 256
`

	if pkcs11Enabled {
		lib, pin, label := pkcs11.FindPKCS11Lib()
		yamlCFG = fmt.Sprintf(`
BCCSP:
    default: PKCS11
    SW:
        Hash: SHA3
        Security: 256
    PKCS11:
        Hash: SHA3
        Security: 256

        Library: %s
        Pin:     '%s'
        Label:   %s
        `, lib, pin, label)
	}

	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlCFG))
	if err != nil {
		fmt.Printf("Could not read YAML config [%s]", err)
		os.Exit(-1)
	}

	err = viper.UnmarshalKey("bccsp", &yamlBCCSP)
	if err != nil {
		fmt.Printf("Could not parse YAML config [%s]", err)
		os.Exit(-1)
	}

	cfgVariations := []*FactoryOpts{
		{},
		{Default: "SW"},
		{Default: "SW", SW: &SwOpts{Hash: "SHA2", Security: 256}},
		yamlBCCSP,
	}

	for index, config := range cfgVariations {
		fmt.Printf("Trying configuration [%d]\n", index)
		initErr := InitFactories(config)
		if initErr != nil {
			fmt.Fprintf(os.Stderr, "initFactories failed: %s", initErr)
			os.Exit(1)
		}
		if rc := m.Run(); rc != 0 {
			os.Exit(rc)
		}
	}
	os.Exit(0)
}

func TestGetDefault(t *testing.T) {
	bccspResult := GetDefault()
	require.NotNil(t, bccspResult, "Failed getting default BCCSP. Nil instance.")
}

// TestGetDefaultAfterInitFactories verifies that GetDefault() returns
// the properly initialized BCCSP after InitFactories() is called
func TestGetDefaultAfterInitFactories(t *testing.T) {
	// Reset state.
	defaultBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	factoriesInitError = atomic.Pointer[error]{}
	factoriesInitOnce = sync.Once{}
	bootBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	bootBCCSPInitOnce = sync.Once{}

	config := &FactoryOpts{
		Default: "SW",
		SW:      &SwOpts{Hash: "SHA2", Security: 256},
	}

	err := InitFactories(config)
	require.NoError(t, err, "InitFactories() should succeed")

	instance := GetDefault()
	require.NotNil(t, instance, "GetDefault() should return initialized instance")

	// Call again to ensure idempotency
	instance2 := GetDefault()
	require.Equal(t, instance, instance2, "Multiple calls should return same instance")
}

// TestBootBCCSPConcurrent verifies that the bootBCCSP fallback path
// is thread-safe when GetDefault() is called before InitFactories().
func TestBootBCCSPConcurrent(t *testing.T) {
	// Reset state to simulate uninitialized factory.
	defaultBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	factoriesInitError = atomic.Pointer[error]{}
	factoriesInitOnce = sync.Once{}
	bootBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	bootBCCSPInitOnce = sync.Once{}

	const numGoroutines = 100
	results := make([]bccsp.BCCSP, numGoroutines)

	// Launch multiple goroutines that call GetDefault() before InitFactories()
	// This should trigger the bootBCCSP fallback path.
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := range numGoroutines {
		go func() {
			defer wg.Done()
			instance := GetDefault()
			require.NotNil(t, instance, "GetDefault() should return bootBCCSP instance")
			results[i] = instance
		}()
	}
	wg.Wait()

	// Verify all goroutines got the same bootBCCSP instance.
	for _, r := range results {
		require.Equal(t, results[0], r, "All goroutines should get the same bootBCCSP instance")
	}
}

// TestConcurrentMixedAccess verifies thread safety when mixing
// InitFactories() and GetDefault() calls concurrently.
func TestConcurrentMixedAccess(t *testing.T) {
	// Reset state.
	defaultBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	factoriesInitError = atomic.Pointer[error]{}
	factoriesInitOnce = sync.Once{}
	bootBCCSP = atomic.Pointer[bccsp.BCCSP]{}
	bootBCCSPInitOnce = sync.Once{}

	const numGoroutines = 100
	config := &FactoryOpts{
		Default: "SW",
		SW:      &SwOpts{Hash: "SHA2", Security: 256},
	}

	// Launch goroutines that mix InitFactories() and GetDefault() calls.
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			// Some goroutines call InitFactories
			err := InitFactories(config)
			require.NoError(t, err)
			// All goroutines call GetDefault
			instance := GetDefault()
			require.NotNil(t, instance, "GetDefault() should never return nil")
		}()
		go func() {
			defer wg.Done()
			// All goroutines call GetDefault
			instance := GetDefault()
			require.NotNil(t, instance, "GetDefault() should never return nil")
		}()
	}
	wg.Wait()

	// Final verification
	instance := GetDefault()
	require.NotNil(t, instance, "Final GetDefault() should return valid instance")
}
