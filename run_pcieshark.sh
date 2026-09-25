#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}/gui/python${PYTHONPATH:+:${PYTHONPATH}}"
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"

if [[ -x "${SCRIPT_DIR}/.venv/bin/python" ]]; then
    PYTHON="${SCRIPT_DIR}/.venv/bin/python"
else
    PYTHON="python3"
fi

if ! "$PYTHON" -c "import PySide6" >/dev/null 2>&1; then
    echo "PySide6 is required for the pcieshark GUI." >&2
    echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

exec "$PYTHON" -m pcieshark_gui "$@"
