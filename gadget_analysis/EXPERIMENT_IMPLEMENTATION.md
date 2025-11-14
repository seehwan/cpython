# Gadget Analysis Experiment Implementation

## Overview

This document describes the implementation of the JIT gadget analysis experimental framework, which generates shared JIT code once and reuses it across multiple experiments to optimize execution time.

## Architecture

### Problem Statement

Initial implementation required ~90 minutes of JIT code generation per experiment × 6 experiments = 540 minutes (9 hours) total execution time. This was inefficient as multiple experiments analyzed the same underlying JIT code.

### Solution: Shared Data Generation

Redesigned architecture to:
1. Generate JIT code once for each unique scenario (A, B, C, D)
2. Save memory captures to disk (pickle format)
3. Load pre-generated captures for analysis experiments
4. Reduce total execution time by ~66% (9 hours → 3-4 hours)

### Scenario Classification

| Scenario | Description | Functions | Iterations | Used By |
|----------|-------------|-----------|------------|---------|
| **A** | Standard JIT functions | 100 | 6000 | Experiments 1, 2, 3 |
| **B** | Memory scaling | Variable (1-80 regions) | 6000 | Experiment 4 |
| **C** | Syscall taxonomy | 50 | 6000 | Experiment 5 |
| **D** | Opcode-sensitive (spray_execve) | 50 | 6000 | Experiment 6 |

## Implementation Details

### 1. JIT Code Generator (`jit_code_generator.py`)

**Purpose**: Generate and capture JIT-compiled memory regions for all scenarios.

**Key Features**:
- **Repeat Runs**: Scenario A supports multiple runs for statistical rigor (default: 3 repeats)
- **GC Protection**: Wraps warmup/scan with `gc.disable()`/`gc.enable()` to prevent premature JIT region deallocation
- **Progress Logging**: Reports progress every 5-10% during warmup (200 iterations per chunk)
- **CLI Options**: Fully parameterizable via `--iters`, `--count`, `--regions`, `--repeat`

**Functions**:
```python
def capture_standard_functions(count=100, iters=6000, repeat=1):
    """Scenario A: Standard JIT functions with repeat capability"""
    # Generates scenario_a.pkl and scenario_a_run{1..N}.pkl
    
def capture_memory_scaling(region_counts=[1,8,16,32,64,80], iters=6000):
    """Scenario B: Memory scaling with intermediate points"""
    # Generates scenario_b.pkl with variable region counts
    
def capture_syscall_taxonomy(count=50, iters=6000):
    """Scenario C: Syscall taxonomy analysis"""
    # Generates scenario_c.pkl
    
def capture_opcode_sensitive(count=50, iters=6000):
    """Scenario D: Opcode-sensitive (spray_execve template)"""
    # Generates scenario_d.pkl
```

**Output Format**:
- Binary captures: `scenario_{a,b,c,d}.pkl`, `scenario_a_run{N}.pkl`
- Metadata: `scenario_{a,b,c,d}_meta.json`
  - Function count, iteration count, timestamp, execution time
  - Pre-patch/post-patch memory region info

**Execution**:
```bash
# Generate Scenario A with 3 repeats
./build/python -m gadget_analysis.jit_code_generator --scenario a --repeat 3 --count 100 --iters 6000

# Generate Scenario B with custom regions
./build/python -m gadget_analysis.jit_code_generator --scenario b --regions 1,8,16,32,64,80 --iters 6000

# Generate all scenarios
./build/python -m gadget_analysis.jit_code_generator --all
```

### 2. JIT Data Loader (`jit_data_loader.py`)

**Purpose**: Load pre-generated JIT captures for analysis experiments.

**API**:
```python
class JITDataLoader:
    @staticmethod
    def load_scenario(scenario_name):
        """Load scenario data from pickle file"""
        # Returns: {
        #   'functions': [...],
        #   'pre_patch_memory': [...],
        #   'post_patch_memory': [...],
        #   'metadata': {...}
        # }
    
    @staticmethod
    def get_pre_patch_memory(scenario_name):
        """Get pre-patch memory regions only"""
    
    @staticmethod
    def get_post_patch_memory(scenario_name):
        """Get post-patch memory regions only"""
```

**Usage Example**:
```python
from gadget_analysis.jit_data_loader import JITDataLoader

# Load Scenario A
data = JITDataLoader.load_scenario('a')
functions = data['functions']
pre_memory = data['pre_patch_memory']
post_memory = data['post_patch_memory']

# Analyze gadgets
scanner = GadgetScanner()
pre_gadgets = scanner.scan_memory_regions(pre_memory)
post_gadgets = scanner.scan_memory_regions(post_memory)
```

### 3. Orchestrator (`orchestrate_scenarios.sh`)

**Purpose**: Sequentially execute all scenarios (A → B → C → D) with parameterization.

**Key Features**:
- **Sequential Execution**: Waits for each scenario to complete before starting next
- **Parameterization**: Environment variables for flexible configuration
- **Background Execution**: Runs with `nohup` and logs to files
- **Idempotency**: Skips scenarios that already have valid output files

**Configuration**:
```bash
# Environment variables (with defaults)
JIT_ITERS=6000              # Warmup iterations per function
JIT_REPEAT_A=3              # Number of repeat runs for Scenario A
JIT_COUNT_A=100             # Function count for Scenario A
JIT_REGIONS_B="1,8,16,32,64,80"  # Region counts for Scenario B
JIT_COUNT_C=50              # Function count for Scenario C
JIT_COUNT_D=50              # Function count for Scenario D
```

**Execution**:
```bash
# Start full pipeline
export JIT_ITERS=6000 JIT_REPEAT_A=3 JIT_COUNT_A=100 \
       JIT_REGIONS_B="1,8,16,32,64,80" JIT_COUNT_C=50 JIT_COUNT_D=50
nohup bash gadget_analysis/orchestrate_scenarios.sh >/dev/null 2>&1 &

# Monitor progress
bash gadget_analysis/status.sh
tail -f gadget_analysis/jit_captures/scenario_a.run.log
```

**Log Files**:
- Main log: `gadget_analysis/jit_captures/orchestrator.log`
- Scenario logs: `gadget_analysis/jit_captures/scenario_{a,b,c,d}.run.log`

### 4. Status Monitor (`status.sh`)

**Purpose**: Display comprehensive status of all scenarios.

**Output Includes**:
- File existence (capture `.pkl`, metadata `.json`)
- Last 5 log lines from each scenario
- Process status (running/idle)
- Orchestrator log info

**Usage**:
```bash
bash gadget_analysis/status.sh
```

## Experiments

### Experiment 1: Stencil Gadget Catalog (`experiment_1_refactored.py`)

**Hypothesis**: JIT stencil templates generate predictable gadget patterns.

**Data Source**: Scenario A

**Analysis**:
1. Load pre-generated JIT functions from Scenario A
2. Scan pre-patch and post-patch memory for gadgets
3. Classify gadgets by type (ret, syscall, indirect branch, stack pivot, pop sequences)
4. Generate catalog JSON with gadget addresses and instructions
5. Create heatmaps showing gadget density changes

**Outputs**:
- `experiment_1_results/catalog.json`: Full gadget catalog
- `experiment_1_results/pre_patch_heatmap.png`: Pre-patch gadget distribution
- `experiment_1_results/post_patch_heatmap.png`: Post-patch gadget distribution
- `experiment_1_results/summary.txt`: Statistical summary

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_1_refactored
```

### Experiment 2: Unaligned Decoding (`experiment_2_unaligned.py`)

**Hypothesis**: Decoding at byte offsets 1-7 reveals hidden gadgets.

**Data Source**: Scenario A (reused)

**Analysis**:
1. Load Scenario A data
2. Decode at offsets 0-7 for each memory region
3. Compare pre-patch vs post-patch gadget counts at each offset
4. Identify offsets with maximum gadget yield

**Outputs**:
- `experiment_2_results/offset_comparison.png`: Bar chart of gadgets by offset
- `experiment_2_results/report.txt`: Detailed offset analysis

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_2_unaligned
```

### Experiment 3: Patch Impact Analysis (`experiment_3_patch_impact.py`)

**Hypothesis**: `patch_*` functions modify stencil code, affecting gadget availability.

**Data Source**: Scenario A (reused)

**Analysis**:
1. Load Scenario A data
2. Compare pre-patch vs post-patch gadgets per function
3. Calculate gadget count delta for each function
4. Identify functions with highest/lowest gadget changes
5. Analyze correlation between function complexity and gadget delta

**Outputs**:
- `experiment_3_results/scatter_plot.png`: Gadget delta scatter plot
- `experiment_3_results/bar_chart.png`: Top functions by gadget change
- `experiment_3_results/summary_table.txt`: Function-level statistics

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_3_patch_impact
```

### Experiment 4: Memory Scaling (`experiment_4_memory_scaling.py`)

**Hypothesis**: Gadget count scales linearly with JIT-compiled memory regions.

**Data Source**: Scenario B

**Analysis**:
1. Load Scenario B data with variable region counts [1, 8, 16, 32, 64, 80]
2. Perform linear regression: `gadgets = α + β × regions`
3. Calculate 95% confidence interval for regression line
4. Generate violin plots showing gadget distribution at each scale
5. Compute per-region gadget density

**Outputs**:
- `experiment_4_results/scaling_plot.png`: Linear regression with 95% CI
- `experiment_4_results/violin_plot.png`: Distribution at each scale point
- `experiment_4_results/regression_stats.txt`: R², p-value, coefficients

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_4_memory_scaling
```

### Experiment 5: Syscall Taxonomy (`experiment_5_syscall_taxonomy.py`)

**Hypothesis**: JIT code contains diverse gadget types suitable for ROP chain construction.

**Data Source**: Scenario C

**Analysis**:
1. Load Scenario C data
2. Classify all gadgets into categories:
   - `ret` gadgets (function epilogues)
   - `syscall` gadgets (kernel invocation)
   - Indirect branches (`jmp/call [reg]`)
   - Stack pivots (`xchg rsp, reg; mov rsp, reg`)
   - Pop sequences (`pop r*; ret`)
3. Generate stacked bar chart showing taxonomy distribution
4. Analyze ret-free chain feasibility

**Outputs**:
- `experiment_5_results/taxonomy_chart.png`: Stacked bar chart by category
- `experiment_5_results/ret_free_analysis.txt`: Alternative chain analysis

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_5_syscall_taxonomy
```

### Experiment 6: Opcode-Sensitive Analysis (`experiment_6_opcode_sensitive.py`)

**Hypothesis**: Specific bytecode patterns (e.g., `spray_execve`) yield higher gadget counts.

**Data Source**: Scenario D (spray_execve) vs Scenario A (baseline)

**Analysis**:
1. Load Scenario D (spray_execve) and Scenario A (baseline)
2. Compare gadget counts between templates
3. Analyze byte distribution differences
4. Calculate gadget count improvement percentage

**Outputs**:
- `experiment_6_results/byte_distribution.png`: Histogram comparison
- `experiment_6_results/gadget_improvement.txt`: % improvement metrics

**Execution**:
```bash
./build/python -m gadget_analysis.experiment_6_opcode_sensitive
```

## Performance Optimization

### Warmup Strategy

**Problem**: CPython JIT (Tier 2) requires 5000+ iterations to trigger compilation.

**Solution**: Chunked warmup with progress logging
```python
def warmup_chunked(functions, total_iters, chunk_size=200):
    """Warm up in chunks for progress visibility"""
    for i in range(0, total_iters, chunk_size):
        for func in functions:
            for _ in range(chunk_size):
                func()
        progress = (i + chunk_size) / total_iters * 100
        if progress % 10 < (chunk_size / total_iters * 100):
            print(f"    - Warmup progress: {int(progress)}% ({i+chunk_size}/{total_iters})")
```

**Benefits**:
- User visibility into long-running operations
- Ability to estimate completion time
- Early detection of hangs or failures

### GC Protection

**Problem**: Python's garbage collector may deallocate JIT executor regions during scan, causing segfaults.

**Solution**: Disable GC during critical sections
```python
import gc

# Before warmup
gc.disable()
try:
    # Warmup and scan operations
    warmup_functions(functions, iters)
    memory = scan_jit_regions()
finally:
    gc.enable()
```

**Impact**: Eliminates intermittent crashes during memory scanning.

### Repeat Runs for Statistical Rigor

**Problem**: Single-run experiments lack statistical confidence.

**Solution**: Scenario A executes 3 times by default
```python
def capture_standard_functions(count=100, iters=6000, repeat=3):
    for run in range(1, repeat + 1):
        print(f"\n--- Run {run}/{repeat} ---\n")
        # Generate, warmup, scan
        save_capture(f"scenario_a_run{run}.pkl", data)
```

**Analysis**: Experiments can compute mean, standard deviation, and 95% confidence intervals.

### Intermediate Data Points

**Problem**: Scenario B initially had only [1, 10, 100] regions, insufficient for regression analysis.

**Solution**: Added intermediate points [1, 8, 16, 32, 64, 80]
- Better captures non-linear trends
- Improves R² for linear regression
- Enables detection of scaling breakpoints

## Execution Timeline

### Current Configuration

| Phase | Duration | Description |
|-------|----------|-------------|
| **Scenario A** | ~17 hours | 100 functions × 6000 iters × 3 repeats |
| **Scenario B** | ~2 hours | 6 regions × 6000 iters |
| **Scenario C** | ~45 minutes | 50 functions × 6000 iters |
| **Scenario D** | ~45 minutes | 50 functions × 6000 iters |
| **Total** | ~21 hours | Sequential execution A→B→C→D |

### Progress Tracking

**Real-time Monitoring**:
```bash
# Overall status
bash gadget_analysis/status.sh

# Scenario A progress
tail -f gadget_analysis/jit_captures/scenario_a.run.log | grep "Warmup progress"

# Orchestrator logs
tail -f gadget_analysis/jit_captures/orchestrator.log
```

**Completion Indicators**:
- Scenario A: 3 `.pkl` files (`scenario_a_run1.pkl`, `scenario_a_run2.pkl`, `scenario_a_run3.pkl`) + metadata
- Scenario B-D: Single `.pkl` file + metadata each
- Orchestrator: "All scenarios completed." in `orchestrator.log`

## File Structure

```
gadget_analysis/
├── jit_code_generator.py       # Generates all 4 scenarios
├── jit_data_loader.py          # Loads pre-generated captures
├── orchestrate_scenarios.sh    # Sequential orchestrator
├── status.sh                   # Status monitoring script
├── experiment_1_refactored.py  # Stencil gadget catalog
├── experiment_2_unaligned.py   # Unaligned decoding
├── experiment_3_patch_impact.py # Patch function impact
├── experiment_4_memory_scaling.py # Linear regression analysis
├── experiment_5_syscall_taxonomy.py # Gadget classification
├── experiment_6_opcode_sensitive.py # Opcode sensitivity
├── generator.py                # Function generation utilities
├── scanner.py                  # Memory scanning utilities
├── classifier.py               # Gadget classification utilities
├── stencil_optimizer.py        # High-gadget-density code generator
└── jit_captures/               # Data output directory
    ├── scenario_a.pkl
    ├── scenario_a_run1.pkl
    ├── scenario_a_run2.pkl
    ├── scenario_a_run3.pkl
    ├── scenario_a_meta.json
    ├── scenario_b.pkl
    ├── scenario_b_meta.json
    ├── scenario_c.pkl
    ├── scenario_c_meta.json
    ├── scenario_d.pkl
    ├── scenario_d_meta.json
    ├── orchestrator.log
    ├── scenario_a.run.log
    ├── scenario_b.run.log
    ├── scenario_c.run.log
    └── scenario_d.run.log
```

## Best Practices

### 1. Always Use Absolute Paths
```bash
# Good
./build/python -m gadget_analysis.jit_code_generator

# Bad (relative imports may fail)
python jit_code_generator.py
```

### 2. Monitor Background Processes
```bash
# Check if orchestrator is running
pgrep -fa orchestrate_scenarios

# View process resource usage
ps -p <PID> -o pid,etime,%cpu,%mem,cmd
```

### 3. Validate Data Before Analysis
```python
# Check if scenario data exists
data_path = Path("gadget_analysis/jit_captures/scenario_a.pkl")
if not data_path.exists():
    raise FileNotFoundError(f"Generate data first: ./build/python -m gadget_analysis.jit_code_generator --scenario a")
```

### 4. Handle Interruptions Gracefully
- Orchestrator checks for existing files before regenerating
- Use `Ctrl+Z` + `bg` + `disown` to safely background manual runs
- Logs preserve progress even if process is killed

### 5. Clean Up Before Rerun
```bash
# Remove old captures to force regeneration
rm gadget_analysis/jit_captures/scenario_*.pkl
rm gadget_analysis/jit_captures/scenario_*_meta.json

# Clean experiment results
rm -rf gadget_analysis/experiment_*_results/
```

## Troubleshooting

### Issue: Segmentation Fault During Scan

**Cause**: GC deallocates JIT executor regions while scanning memory.

**Solution**: Ensure `gc.disable()` wraps warmup and scan operations.

### Issue: ModuleNotFoundError

**Cause**: Incorrect Python executable or module path.

**Solution**: Use `./build/python -m gadget_analysis.module_name` pattern.

### Issue: Slow Warmup Progress

**Cause**: JIT compilation is CPU-intensive (6000 iterations × 100 functions).

**Expected**: ~34 minutes per 200-iteration chunk, ~17 hours for full Scenario A run.

**Mitigation**: Run on dedicated machine, reduce `--iters` for testing.

### Issue: Orchestrator Stuck

**Cause**: Child process hung or waiting for input.

**Diagnosis**:
```bash
# Check active processes
pgrep -fa python | grep jit_code_generator

# Check logs for errors
tail -100 gadget_analysis/jit_captures/scenario_a.run.log | grep -i error
```

**Recovery**: Kill hung process, restart orchestrator.

## Future Enhancements

### 1. Parallel Scenario Execution
Current: Sequential (A → B → C → D)
Proposed: Parallel execution of B, C, D (A must complete first)

### 2. Incremental Progress Checkpoints
Save intermediate captures every N iterations to enable resume on failure.

### 3. Automated Statistical Aggregation
Script to compute mean/CI from repeat runs and update experiment outputs.

### 4. Adaptive Iteration Tuning
Dynamically adjust iteration count based on JIT compilation detection.

### 5. Web Dashboard
Real-time web interface showing progress, resource usage, and preliminary results.

## References

- CPython JIT (Tier 2): PEP 744
- Ropper Framework: https://github.com/sashs/Ropper
- ROP Gadget Analysis: Shacham (2007), "The Geometry of Innocent Flesh on the Bone"
- JIT Spraying: Blazakis (2010), "Interpreter Exploitation"

## Changelog

### 2025-11-14
- Initial implementation with 4-scenario architecture
- Added repeat runs for Scenario A (default: 3)
- Enhanced Scenario B with intermediate points [1,8,16,32,64,80]
- Implemented GC protection for memory scanning
- Added progress logging (5-10% intervals)
- Created orchestrator with full parameterization
- Added status monitoring script

---

**Last Updated**: 2025-11-14  
**Status**: Active development (Scenario A executing, Run 1/3 at 30% progress)
