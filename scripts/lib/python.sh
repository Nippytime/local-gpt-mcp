# Portable interpreter resolver adapted from mlookhere/CI-Pipline.
python_runs() {
  local name="$1"
  [[ -n "$name" ]] && command -v "$name" >/dev/null 2>&1 && \
    "$name" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1
}

resolve_system_python() {
  local name
  for name in "${PYTHON_BIN:-}" python3 python; do
    if python_runs "$name"; then printf '%s\n' "$name"; return 0; fi
  done
  echo 'A working Python 3.12+ interpreter is required.' >&2
  return 1
}

resolve_python() {
  local root="$1" name
  for name in "$root/.venv/bin/python" "$root/.venv/Scripts/python.exe"; do
    if python_runs "$name"; then printf '%s\n' "$name"; return 0; fi
  done
  resolve_system_python
}
