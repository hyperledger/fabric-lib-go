#!/bin/bash -eu
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

scripts_dir=$(cd $(dirname $0) && pwd)
source "${scripts_dir}/common.sh"

time go test -race -cover ./...
