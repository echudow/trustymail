#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail

version=$(./bump_version.sh show)
docker build -t "$IMAGE_NAME":"$version" .
