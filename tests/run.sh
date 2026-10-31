#!/usr/bin/env bash
# Lint the shell, byte-compile the Python, and run the unit tests.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
shellcheck -x hotpatch lib/*.sh scripts/*.sh tests/run.sh
python3 -m py_compile scripts/*.py tests/*.py
python3 -I -m unittest discover -s tests -p 'test_*.py' "$@"
rm -rf scripts/__pycache__ tests/__pycache__
