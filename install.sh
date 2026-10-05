#!/usr/bin/env bash
set -Eeuo pipefail
BASE_URL="https://raw.githubusercontent.com/william-aqn/microtik-awg3-installer/main"
PYTHON_SHA256="ff94b966ddb69fac171e98e72d0d36714a3e7ce69aab5c7ae59c4c37699b1b55"
RUNTIME_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/awg-mikrotik"
VENV="$RUNTIME_ROOT/venv"
SCRIPT="$RUNTIME_ROOT/awg-mikrotik.py"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
trap 'status=$?; printf "Bootstrap failed (exit %s). Check Python >=3.10, curl, HTTPS and pip/venv.\n" "$status" | tee awg-bootstrap-error.txt >&2; exit "$status"' ERR

command -v python3 >/dev/null || { echo "Install Python 3.10+ and retry." | tee awg-bootstrap-error.txt >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
mkdir -p "$RUNTIME_ROOT"
if [[ ! -x "$VENV/bin/python" ]]; then
    python3 -m venv "$VENV"
fi
PYTHON="$VENV/bin/python"
if ! "$PYTHON" -c 'import paramiko' 2>/dev/null; then
    "$PYTHON" -m pip install --disable-pip-version-check 'paramiko==4.0.0'
fi
verify() {
    "$PYTHON" -c 'import hashlib,pathlib,sys; sys.exit(0 if pathlib.Path(sys.argv[1]).exists() and hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()==sys.argv[2] else 1)' "$SCRIPT" "$PYTHON_SHA256"
}
if ! verify; then
    if [[ -f "$SOURCE_DIR/awg-mikrotik.py" ]]; then
        cp "$SOURCE_DIR/awg-mikrotik.py" "$SCRIPT"
    else
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$BASE_URL/awg-mikrotik.py" -o "$SCRIPT"
    fi
    verify
fi
"$PYTHON" "$SCRIPT" "$@"
