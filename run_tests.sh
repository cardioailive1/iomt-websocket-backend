#!/usr/bin/env bash
# Run the full test suite from the tests/ directory
set -euo pipefail

cd "$(dirname "$0")"

echo "Installing test dependencies..."
pip install -q -r requirements-test.txt

echo ""
echo "Running IoMT CardioAI test suite (200 tests)..."
echo ""
pytest test_iomt_cardioai_handshake.py -v --tb=short "$@"
