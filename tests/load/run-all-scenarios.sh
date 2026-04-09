#!/bin/bash
# Lu Yixuan, Deborah, A0277911X
# Runs each load scenario individually and exports an HTML report per scenario.

set -e

REPORT_DIR="tests/load"
SCRIPT="tests/load/load.test.js"

mkdir -p "$REPORT_DIR"

SCENARIOS=(
  "admin_users"
  "orders_user"
  "orders_admin"
  "order_status"
  "profile_update"
  "search"
  "mixed"
)

echo "========================================"
echo " Running all load scenarios one by one"
echo "========================================"
echo ""

for SCENARIO in "${SCENARIOS[@]}"; do
  echo "[ RUNNING ] $SCENARIO..."
  echo "  Output: $REPORT_DIR/report-after-$SCENARIO.html"
  echo ""

  k6 run \
    -e BASE_URL="http://localhost:6060" \
    -e SCENARIO="$SCENARIO" \
    --out "web-dashboard=export=$REPORT_DIR/report-after-$SCENARIO.html" \
    "$SCRIPT" || true

  echo ""
  echo "[ DONE ] $SCENARIO — report saved."
  echo "Waiting 5s before next scenario..."
  sleep 5
done

echo "========================================"
echo " All scenarios complete!"
echo "========================================"
echo "Reports saved in $REPORT_DIR/"