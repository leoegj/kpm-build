#!/system/bin/sh
# recompile_realworld_test.sh — Real-world fork matching verification
#
# Proves: only the target process's forks trigger fork-fix-child.
# System forks (Zygote, etc.) during active mapping → skipped, zero processing.
#
# Usage: adb shell /data/local/tmp/recompile_realworld_test.sh

DIR=/data/local/tmp
KPATCH=$DIR/kpatch
KEY=wwb12345
TEST=$DIR/recompile_fork_test

echo "=== Recompile Real-World Fork Test ==="
echo ""

# Step 1: Clear dmesg
kp -c 'dmesg -c' > /dev/null 2>&1

# Step 2: Reset stats
prctl_stats_reset() {
    # Use the test binary's stats_reset (prctl 0x52430004)
    # We'll read stats via the test binary instead
    true
}

# Step 3: Kill apps to prepare for fresh Zygote forks
echo "[1] Killing apps to prepare fresh forks..."
am force-stop com.android.settings 2>/dev/null
am force-stop com.android.calculator2 2>/dev/null
am force-stop com.android.deskclock 2>/dev/null
sleep 1

# Step 4: Run fork_storm test (holds mapping for ~1 second) in background
# During this window, launch apps to trigger Zygote forks
echo "[2] Starting fork test (background)..."
$TEST -v &
TEST_PID=$!

# Step 5: Wait for test to enter the fork_storm phase (mapping active)
sleep 0.5

# Step 6: Launch 3 apps simultaneously → Zygote forks 3 new processes
echo "[3] Launching 3 apps (Zygote forks while mapping active)..."
am start -n com.android.settings/.Settings > /dev/null 2>&1 &
am start -n com.android.calculator2/.Calculator > /dev/null 2>&1 &
am start -n com.android.deskclock/.DeskClock > /dev/null 2>&1 &

# Step 7: Wait for test to complete
wait $TEST_PID
TEST_EXIT=$?
sleep 1

echo ""
echo "=== dmesg Analysis ==="

# Step 8: Analyze dmesg
echo ""
echo "[fork-fix-child] events by process:"
kp -c 'dmesg' 2>/dev/null | grep "fork-fix-child" | \
    sed 's/.*comm=\([^ ]*\).*/\1/' | sort | uniq -c | sort -rn
echo ""

TOTAL_FIX=$(kp -c 'dmesg' 2>/dev/null | grep -c "fork-fix-child")
NON_TEST_FIX=$(kp -c 'dmesg' 2>/dev/null | grep "fork-fix-child" | grep -cv "recompile_fork_")

echo "Total fork-fix-child events: $TOTAL_FIX"
echo "Non-test-process events:     $NON_TEST_FIX"
echo ""

if [ "$NON_TEST_FIX" -eq 0 ] 2>/dev/null; then
    echo "[PASS] Zero false fork interceptions — only target process was handled"
else
    echo "[FAIL] $NON_TEST_FIX fork events from non-target processes!"
fi

echo ""
echo "Test exit code: $TEST_EXIT"
echo "=== Done ==="
