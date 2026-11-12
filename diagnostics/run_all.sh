#!/usr/bin/env bash
# Reproducible forensic pipeline: rebuild every crafted PE, then produce the
# pefile-vs-raw evidence comparison. Standard library + the local pefile only.
set -euo pipefail

cd "$(dirname "$0")"
export PYTHONPATH="$(cd .. && pwd)${PYTHONPATH:+:$PYTHONPATH}"

echo "[1/2] building crafted PE samples"
python3 build_samples.py

echo "[2/2] running pefile vs lossless evidence comparison"
python3 diagnose.py "$@"

echo
echo "reports written to diagnostics/reports/"
