#!/bin/bash -eu

#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

time {
    go test -race -cover ./...
    go test -race -cover -tags "pkcs11" github.com/hyperledger/fabric-lib-go/bccsp/factory
    go test -race -cover -tags "pkcs11" github.com/hyperledger/fabric-lib-go/bccsp/pkcs11
}