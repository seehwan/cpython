# Gadget Analysis Framework

A comprehensive toolkit for analyzing ROP gadgets in CPython JIT code.

## Overview

This framework provides modular tools for:
- **Generating** JIT-compiled Python functions
- **Scanning** runtime JIT memory for ROP gadgets
- **Classifying** gadgets by generation mechanism (6 categories)
- **Reporting** statistical analysis and comparisons

## Installation

No installation required. The framework is self-contained.

```bash
cd /home/mobileos2/cpython/case_studies/case4
```

## Quick Start

```bash
# Test with 50 functions, compare normal vs spread allocation
python3 test_gadget_analysis.py -n 50 -t both

# Test with 100 functions, normal allocation only
python3 test_gadget_analysis.py -n 100 -t normal --no-comparison

# Large-scale test with 200 functions, spread allocation
python3 test_gadget_analysis.py -n 200 -t spread
```

## Modules

### 1. `classifier.py`
6-way gadget classification by generation mechanism.

**Categories:**
- **Stencil-Aligned** (27%): Instruction boundary gadgets (high reliability)
- **Instruction-Unaligned** (56%): Mid-instruction decoding (medium reliability)
- **Patch-Induced** (17%): From patch operations (medium reliability)
- **Address-Diversity** (0.1%): Wide address space (variable reliability)
- **Patch-Unaligned** (0.2%): Crossing patch boundaries (low reliability)
- **Syscall-Special** (rare): syscall instruction (high reliability when found)

**Example:**
```python
from gadget_analysis import GadgetClassifier

classifier = GadgetClassifier()
classified = classifier.classify_all_gadgets(base_addr, buffer, gadgets)
classifier.print_classification_report()
```

### 2. `scanner.py`
Runtime JIT memory scanning for ROP gadgets.

**Features:**
- Scans all byte offsets (includes unintended instructions)
- Capstone disassembly for verification
- Address diversity analysis
- Automatic classification integration

**Example:**
```python
from gadget_analysis import RuntimeJITScanner

scanner = RuntimeJITScanner()
gadgets = scanner.scan_functions(functions)
scanner.print_results()
scanner.export_results('results.json')
```

### 3. `generator.py`
JIT function generation with controlled allocation strategies.

**Allocation Strategies:**
- **Normal**: Consecutive memory (baseline)
- **Spread**: Wide distribution across modules (for address diversity)

**Example:**
```python
from gadget_analysis import JITFunctionGenerator

# Normal allocation
generator = JITFunctionGenerator(spread_allocation=False)
functions = generator.generate(count=100)
generator.warmup(iterations=5000)  # Tier 2 JIT

# Spread allocation
generator_spread = JITFunctionGenerator(spread_allocation=True)
functions_spread = generator_spread.generate(count=100)
generator_spread.warmup()
```

### 4. `reporter.py`
Statistical analysis and reporting utilities.

**Features:**
- Summary statistics (timing, gadget counts, etc.)
- Normal vs spread comparison
- Factor analysis
- Classification summaries

**Example:**
```python
from gadget_analysis import GadgetReporter

GadgetReporter.print_summary("Test Label", scanner, generator)
GadgetReporter.compare_allocations(scanner_normal, scanner_spread)
GadgetReporter.analyze_gadget_factors(scanner_normal, scanner_spread)
```

### 5. `config.py`
Shared configuration and constants.

**Constants:**
- `GADGET_PATTERNS`: Byte patterns for gadget detection
- `JIT_WARMUP_ITERATIONS`: 5000 (Tier 2 JIT threshold)
- `MAGIC_VALUES`: Stencil-friendly constants
- `FUNCTION_BASE_ITERATIONS`: Base loop count
- etc.

## Architecture

```
gadget_analysis/
├── __init__.py          # Package initialization
├── classifier.py        # Gadget classification (6 categories)
├── scanner.py           # JIT memory scanning
├── generator.py         # Function generation
├── reporter.py          # Statistical reporting
└── config.py            # Shared configuration

test_gadget_analysis.py  # Main test suite
```

## Usage Examples

### Basic Test
```bash
python3 test_gadget_analysis.py -n 50 -t both
```

**Output:**
```
TEST 1: Normal Allocation
  Total gadgets: 7,252
  Syscall: 1
  Classification:
    - Instruction-Unaligned: 4,889 (55.6%)
    - Stencil-Aligned: 2,362 (26.9%)
    - Patch-Induced: 1,503 (17.1%)

TEST 2: Spread Allocation
  Total gadgets: 7,403
  Syscall: 1
  Improvement: 1.02x
```

### Programmatic Usage
```python
from gadget_analysis import (
    JITFunctionGenerator,
    RuntimeJITScanner,
    GadgetReporter,
)

# Generate functions
gen = JITFunctionGenerator(spread_allocation=False)
functions = gen.generate(100)
gen.warmup()

# Scan for gadgets
scanner = RuntimeJITScanner()
gadgets = scanner.scan_functions(functions)

# Analyze results
scanner.print_results()
GadgetReporter.print_summary("My Test", scanner, gen)

# Export to JSON
scanner.export_results('my_results.json')
```

### Custom Classification Analysis
```python
from gadget_analysis import GadgetClassifier

classifier = GadgetClassifier()

# Classify gadgets from JIT memory
for base_addr, buffer in jit_memory_buffers:
    classifier.classify_all_gadgets(base_addr, buffer, gadgets)

# Get statistics
stats = classifier.get_statistics()
print(f"Stencil-aligned: {stats['by_category']['stencil_aligned']}")
print(f"Unintended: {stats['by_category']['instruction_unaligned']}")

# Export
classification_data = classifier.export_classification()
```

## Key Findings

### 10-Function Experiment
- **Total gadgets**: 7,252 (normal) / 7,403 (spread)
- **Syscall discovered**: 1 per 10 functions
- **Unintended gadgets dominate**: 55-56%
- **Stencil-aligned (most reliable)**: 26-27%
- **Spread allocation effect**: Minimal at small scale (1.02x)

### Classification Distribution
```
Instruction-Unaligned:  55-56%  (dominant, medium reliability)
Stencil-Aligned:        26-27%  (most reliable)
Patch-Induced:          17%     (exploitable via constants)
Patch-Unaligned:        0.2%    (rare, low reliability)
Address-Diversity:      0.1%    (very rare, variable)
Syscall-Special:        0.0%    (1 per 7000+ gadgets)
```

### Recommendations
1. **For reliable gadgets**: Focus on stencil-aligned (27%)
2. **For diversity**: Use unintended instructions (56%)
3. **For syscall discovery**: Generate 200-500 functions
4. **For address diversity**: Requires large-scale tests (>200 functions)
5. **Warmup requirement**: Always use 5000+ iterations for Tier 2 JIT

## Performance

### 10 Functions (Baseline)
- Generation: 0.01s
- Warmup: ~1080s (18 minutes, 5000 iterations)
- Scan: 1.2s
- Classification: <1s
- **Total**: ~18 minutes

### 50 Functions
- Generation: 0.05s
- Warmup: ~5400s (90 minutes)
- Scan: 6s
- **Total**: ~90 minutes

### 200 Functions
- Generation: 0.2s
- Warmup: ~21600s (6 hours)
- Scan: 24s
- **Total**: ~6 hours

**Performance Bottleneck**: Warmup time is exponential due to `{3000 + seed * 500}` iterations per function.

## Future Work

1. **Large-scale validation** (200-500 functions)
   - Measure address diversity effects
   - Analyze syscall discovery rate
   - Observe classification ratio changes

2. **Optimization**
   - Fix exponential warmup time (constant iterations)
   - Parallel function generation
   - Incremental classification

3. **Cross-version analysis**
   - CPython 3.13 vs 3.14
   - JIT option comparison
   - Platform differences (x86-64 vs ARM64)

4. **Defense mechanisms**
   - CFI integration
   - JIT code signing
   - Randomized stencil ordering

## Related Documentation

- `GADGET_CLASSIFICATION.md`: Detailed classification system documentation
- `TEST_RUNTIME_JIT_SCAN.md`: Original test script documentation
- `README.md` (parent): Case study 4 overview

## License

Research and educational use only.

## Authors

Case Study 4 Team - 2024-11-13
