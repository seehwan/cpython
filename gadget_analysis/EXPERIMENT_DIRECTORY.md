# Experiment Directory Management

## Overview

실험 디렉토리를 타임스탬프와 이름으로 분리하여 관리합니다. 각 실험은 독립적인 디렉토리 구조를 가지며, 여러 번의 실험 실행을 추적할 수 있습니다.

## Directory Structure

```
gadget_analysis/
├── experiments/
│   ├── experiment_index.json          # 전체 실험 인덱스
│   ├── 20251115_083137_test_exp/      # 실험 디렉토리
│   │   ├── metadata.json              # 실험 메타데이터
│   │   ├── captures/                  # JIT 코드 캡처 데이터
│   │   │   ├── scenario_a.pkl
│   │   │   ├── scenario_a_meta.json
│   │   │   ├── scenario_b.pkl
│   │   │   └── ...
│   │   ├── results/                   # 분석 결과
│   │   │   ├── experiment_1_results/
│   │   │   ├── experiment_2_results/
│   │   │   └── ...
│   │   └── logs/                      # 실행 로그
│   │       ├── orchestrator.log
│   │       ├── scenario_a.run.log
│   │       └── ...
│   └── 20251116_120000_full_run/      # 다른 실험
│       └── ...
```

## Usage

### 1. Creating a New Experiment

```bash
# 기본 생성
./build/python -m gadget_analysis.experiment_manager --create

# 이름 지정
./build/python -m gadget_analysis.experiment_manager --create --name "baseline_test"

# 설명 추가
./build/python -m gadget_analysis.experiment_manager --create \
    --name "high_iteration_test" \
    --description "Testing with 10000 iterations"
```

### 2. Listing Experiments

```bash
./build/python -m gadget_analysis.experiment_manager --list
```

Output:
```
======================================================================
Recent Experiments (showing 10 of 15)
======================================================================

[20251115_120000_high_iteration_test]
  Name: high_iteration_test
  Status: completed
  Created: 2025-11-15T12:00:00.123456
  Path: /home/user/cpython/gadget_analysis/experiments/20251115_120000_high_iteration_test
  Completed: scenario_a, scenario_b, scenario_c, scenario_d
```

### 3. Running Experiments with Experiment ID

#### Manual Mode (specify existing experiment)

```bash
# Scenario A만 실행
./build/python -m gadget_analysis.jit_code_generator \
    --scenario a \
    --count 100 \
    --iters 6000 \
    --repeat 3 \
    --experiment-id 20251115_083137_test_exp

# 전체 시나리오 실행
./build/python -m gadget_analysis.jit_code_generator \
    --scenario all \
    --experiment-id 20251115_083137_test_exp
```

#### Orchestrator Mode (auto-creates experiment)

```bash
# 새 실험 자동 생성
export JIT_ITERS=6000
export JIT_REPEAT_A=3
export JIT_COUNT_A=100
export EXPERIMENT_NAME="baseline_run"
nohup bash gadget_analysis/orchestrate_scenarios.sh >/dev/null 2>&1 &

# 기존 실험에 추가
export EXPERIMENT_ID=20251115_083137_test_exp
nohup bash gadget_analysis/orchestrate_scenarios.sh >/dev/null 2>&1 &
```

### 4. Cleaning Up Old Experiments

```bash
# 최근 5개만 유지하고 나머지 삭제
./build/python -m gadget_analysis.experiment_manager --cleanup 5
```

## Experiment Metadata

Each experiment has a `metadata.json` file:

```json
{
  "experiment_id": "20251115_083137_test_exp",
  "timestamp": "20251115_083137",
  "name": "test_exp",
  "description": "Testing experiment manager",
  "config": {},
  "created_at": "2025-11-15T08:31:37.299665",
  "status": "created",
  "scenarios_completed": []
}
```

Status values:
- `created`: Experiment directory created
- `running`: Scenario generation in progress
- `completed`: All scenarios finished
- `failed`: Error occurred

## Integration with Existing Scripts

### JIT Code Generator

```python
from gadget_analysis.jit_code_generator import JITCodeCapture

# Use experiment manager (creates new experiment)
capturer = JITCodeCapture()

# Use specific experiment ID
capturer = JITCodeCapture(experiment_id="20251115_083137_test_exp")

# Legacy mode (direct output directory)
capturer = JITCodeCapture(output_dir="gadget_analysis/jit_captures")
```

### Experiment Scripts

Experiments can load data from specific experiment directory:

```python
from gadget_analysis.experiment_manager import ExperimentManager
from gadget_analysis.jit_data_loader import JITDataLoader

# Get latest experiment
manager = ExperimentManager()
exp_dir = manager.get_latest_experiment()

# Load data from that experiment
data_path = exp_dir / "captures" / "scenario_a.pkl"
# ... load and analyze
```

## Environment Variables

- `EXPERIMENT_NAME`: Name for the experiment (optional)
- `EXPERIMENT_ID`: Use existing experiment ID (optional)
- `JIT_ITERS`: Warmup iterations (default: 6000)
- `JIT_REPEAT_A`: Repeat count for Scenario A (default: 3)
- `JIT_COUNT_A`: Function count for Scenario A (default: 100)
- `JIT_REGIONS_B`: Region counts for Scenario B (default: "1,8,16,32,64,80")
- `JIT_COUNT_C`: Function count for Scenario C (default: 50)
- `JIT_COUNT_D`: Function count for Scenario D (default: 50)

## Benefits

1. **Organized**: Each experiment run has its own isolated directory
2. **Traceable**: Easy to track multiple experimental runs with timestamps
3. **Reproducible**: Configuration and results stored together
4. **Comparable**: Easy to compare results across different experiments
5. **Clean**: Old experiments can be archived or removed systematically

## Example Workflow

```bash
# 1. Create and run baseline experiment
export EXPERIMENT_NAME="baseline_500_iters"
export JIT_ITERS=500
export JIT_COUNT_A=10
bash gadget_analysis/orchestrate_scenarios.sh

# 2. Create and run high-iteration experiment
export EXPERIMENT_NAME="high_6000_iters"
export JIT_ITERS=6000
export JIT_COUNT_A=100
bash gadget_analysis/orchestrate_scenarios.sh

# 3. List all experiments
./build/python -m gadget_analysis.experiment_manager --list

# 4. Clean up old test runs
./build/python -m gadget_analysis.experiment_manager --cleanup 10
```

## Migration from Old Structure

Old structure:
```
gadget_analysis/jit_captures/
├── scenario_a.pkl
├── scenario_a_meta.json
└── ...
```

New structure (backward compatible):
```
gadget_analysis/
├── jit_captures/           # Legacy support (still works)
│   └── ...
└── experiments/            # New organized structure
    ├── experiment_index.json
    └── 20251115_083137_exp/
        ├── captures/
        ├── results/
        └── logs/
```

Both structures are supported. Use `--output-dir` for legacy mode or `--experiment-id` for new mode.
