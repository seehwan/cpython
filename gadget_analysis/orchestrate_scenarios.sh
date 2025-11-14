#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="gadget_analysis/jit_captures"
PY="./build/python"

# Tunables via env (with sensible defaults)
JIT_ITERS=${JIT_ITERS:-6000}
JIT_REPEAT_A=${JIT_REPEAT_A:-3}
JIT_COUNT_A=${JIT_COUNT_A:-100}
JIT_REGIONS_B=${JIT_REGIONS_B:-"1,8,16,32,64,80"}
JIT_COUNT_C=${JIT_COUNT_C:-50}
JIT_COUNT_D=${JIT_COUNT_D:-50}

mkdir -p "$LOG_DIR"

log() {
  echo "[ORCH] $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_DIR/orchestrator.log"
}

wait_for_scenario_a() {
  log "Waiting for Scenario A to finish..."
  while pgrep -f "-m gadget_analysis.jit_code_generator --scenario a" >/dev/null; do
    sleep 30
  done
  log "Scenario A finished."
}

maybe_run_scenario_a() {
  local name="scenario_a"
  # If A is not running and no capture exists, run it with repeat
  if pgrep -f "-m gadget_analysis.jit_code_generator --scenario a" >/dev/null; then
    log "Scenario A is already running."
    return 0
  fi
  if [[ -f "$LOG_DIR/${name}.pkl" ]]; then
    log "Scenario A capture already exists. Skipping start."
    return 0
  fi
  log "Starting scenario_a (count=$JIT_COUNT_A, iters=$JIT_ITERS, repeat=$JIT_REPEAT_A) ..."
  "$PY" -u -m gadget_analysis.jit_code_generator \
    --scenario a \
    --iters "$JIT_ITERS" \
    --count "$JIT_COUNT_A" \
    --repeat "$JIT_REPEAT_A" \
    2>&1 | tee "$LOG_DIR/${name}.run.log"
}

run_scenario() {
  local letter="$1"; shift || true
  local extra_args=("$@")
  local name="scenario_${letter}"
  log "Starting ${name} (iters=$JIT_ITERS) ..."
  "$PY" -u -m gadget_analysis.jit_code_generator \
    --scenario "$letter" \
    --iters "$JIT_ITERS" \
    "${extra_args[@]}" \
    2>&1 | tee "$LOG_DIR/${name}.run.log"
  log "Completed ${name}."
}

# Orchestrate A (3 repeats) -> B -> C -> D
maybe_run_scenario_a
wait_for_scenario_a
run_scenario b --regions "$JIT_REGIONS_B"
run_scenario c --count "$JIT_COUNT_C"
run_scenario d --count "$JIT_COUNT_D"

log "All scenarios completed."
