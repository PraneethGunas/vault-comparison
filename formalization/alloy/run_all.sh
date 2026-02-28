#!/usr/bin/env bash
# Run all Alloy 6 models in the current directory.
# Usage: ./run_all.sh
#        ./run_all.sh cross_covenant.als   # run a single file

set -euo pipefail

ALLOY_JAR="${ALLOY_JAR:-$HOME/alloy6.jar}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="$DIR/run_${TIMESTAMP}.log"

# Ordered so dependencies come first (base modules, then concrete vaults, then cross-covenant)
ALL_FILES=(
  btc_base.als
  vault_base.als
  threat_model.als
  ctv_vault.als
  ccv_vault.als
  opvault_vault.als
  cross_covenant.als
)

# If arguments given, run only those files
if [[ $# -gt 0 ]]; then
  FILES=("$@")
else
  FILES=("${ALL_FILES[@]}")
fi

passed=0
failed=0
skipped=0

echo "═══════════════════════════════════════════════════════" | tee "$LOG"
echo " Alloy 6 — Run All Models  ($TIMESTAMP)"                | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════" | tee -a "$LOG"
echo "" | tee -a "$LOG"

for f in "${FILES[@]}"; do
  path="$DIR/$f"
  if [[ ! -f "$path" ]]; then
    echo "⏭  SKIP  $f  (file not found)" | tee -a "$LOG"
    ((skipped++))
    continue
  fi

  echo "───────────────────────────────────────────────────────" | tee -a "$LOG"
  echo "▶  Running  $f" | tee -a "$LOG"
  echo "───────────────────────────────────────────────────────" | tee -a "$LOG"

  start=$(date +%s)
  if java -jar "$ALLOY_JAR" exec -f "$path" 2>&1 | tee -a "$LOG"; then
    end=$(date +%s)
    echo "✅  PASS  $f  ($((end - start))s)" | tee -a "$LOG"
    ((passed++))
  else
    end=$(date +%s)
    echo "❌  FAIL  $f  ($((end - start))s)" | tee -a "$LOG"
    ((failed++))
  fi
  echo "" | tee -a "$LOG"
done

echo "═══════════════════════════════════════════════════════" | tee -a "$LOG"
echo " Summary: $passed passed, $failed failed, $skipped skipped" | tee -a "$LOG"
echo " Log:     $LOG" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════" | tee -a "$LOG"

[[ $failed -eq 0 ]]
