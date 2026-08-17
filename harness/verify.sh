#!/usr/bin/env bash
# The single verification boundary: static checks, then the test suite (unit + API +
# headless-browser) against the running secure application. Local and CI invoke this.
set -euo pipefail

echo "== ruff =="
ruff check src tests

echo "== mypy =="
mypy

echo "== pytest =="
pytest

echo "== verification complete =="
