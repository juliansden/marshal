#!/usr/bin/env bash
# Builds the synthetic_openssl fixture binary for manually exercising `marshal scan`.
set -euo pipefail
cd "$(dirname "$0")"
cc -O0 -o fixture_synthetic_openssl main.c
echo "built $(pwd)/fixture_synthetic_openssl"
