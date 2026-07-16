#!/bin/sh

set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KEY=${1:-}
KPATCH=${KPATCH:-"$DIR/kpatch"}
MODULE=${MODULE:-"$DIR/recompile.kpm"}

if [ -z "$KEY" ]; then
    echo "Usage: $0 <superkey>"
    exit 2
fi

echo "=== recompile_full_test ==="
echo "kpatch=$KPATCH"
echo "module=$MODULE"

"$KPATCH" "$KEY" kpm unload recompile >/dev/null 2>&1 || true

"$KPATCH" "$KEY" kpm load "$MODULE"
"$DIR/recompile_test"
"$DIR/recompile_fork_test"
"$DIR/recompile_export_test"
"$KPATCH" "$KEY" kpm unload recompile

if dmesg | tail -n 200 | grep -Eqi 'WARNING:.*RCU|rcu:.*warning|BUG:.*RCU'; then
    echo "[FAIL] detected possible recent RCU warning in dmesg tail"
    exit 1
fi

echo "[PASS] recompile full suite completed"
