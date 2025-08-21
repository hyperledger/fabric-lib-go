/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

// GetDefaultOpts offers a default implementation for Opts
// returns a new instance every time
func GetDefaultOpts() *FactoryOpts {
	fopts := getDefaultImpl()
	fopts.Default = "SW"
	fopts.SW.Hash = "SHA2"
	fopts.SW.Security = 256
	return fopts
}

// FactoryName returns the name of the provider
func (o *FactoryOpts) FactoryName() string {
	return o.Default
}
