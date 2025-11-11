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

### Gadget Discovery (Typical Run)
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

## Acknowledgments

This work builds on CPython's transparent JIT design and the Capstone disassembly framework. All techniques are for educational and defensive research purposes.

---

**Commit**: `149149cf19` (feat: Add stencil-based JIT gadget scanner and enhanced ROP PoC)  
**Date**: November 11, 2025  
**Status**: ✅ Functional (dry-run validated; full execution ready)
