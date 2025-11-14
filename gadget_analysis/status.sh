#!/usr/bin/env bash
set -euo pipefail
LOG_DIR="gadget_analysis/jit_captures"

printf "\n=== Gadget Analysis Status ===\n"

for s in a b c d; do
  name="scenario_${s}"
  pkl="$LOG_DIR/${name}.pkl"
  meta="$LOG_DIR/${name}_meta.json"
  log="$LOG_DIR/${name}.run.log"
  printf "\n[%s]\n" "$name"
  if [[ -f "$pkl" ]]; then
    ls -lh "$pkl" || true
  else
    echo "  - capture: (pending)"
  fi
  if [[ -f "$meta" ]]; then
    jq '.scenario, .function_count?, .region_counts?, .warmup_iterations?, .repeats?' "$meta" 2>/dev/null || true
  else
    echo "  - meta: (pending)"
  fi
  if [[ -f "$log" ]]; then
    echo "  - last log lines:"
    tail -n 5 "$log"
  else
    echo "  - log: (pending)"
  fi
  echo
  pgrep -fa "-m gadget_analysis.jit_code_generator --scenario $s" >/dev/null && echo "  - process: RUNNING" || echo "  - process: idle"
 done

printf "\n[orchestrator]\n"
ls -lh "$LOG_DIR/orchestrator.log" 2>/dev/null || echo "  - orchestrator: (no log yet)"
