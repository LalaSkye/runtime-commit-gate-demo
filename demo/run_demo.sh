#!/bin/bash
# Runtime Commit Gate — Proof Sequence
# Run from project root: bash demo/run_demo.sh

set -e

echo ""
echo "Installing dependencies (if needed)..."
pip install -q fastapi uvicorn 2>/dev/null || true

echo ""
echo "Running proof sequence..."
python demo/run_demo.py

echo ""
echo "Running full test suite..."
python -m pytest tests/ -v --tb=short

echo ""
echo "Done. The gate holds."
