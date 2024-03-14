#!/bin/bash -eu

#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

time go test -race -cover ./...
cd common
time go test -race -cover ./...
cd ../protoutil
time go test -race -cover ./...