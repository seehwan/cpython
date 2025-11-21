# Shell Execution Gadget Chaining Overview

This note summarizes the two PoC scripts in `case_studies/case4` that build a ROP chain to spawn a shell from CPython JIT-generated code.

## `gadget_chain_from_multi_jitcode_exec_sh_success.py`
- **Goal:** Find `pop rax/rdi/rsi/rdx; ret` and `syscall` gadgets in JIT output, falling back to tiny shellcode for anything missing, then execute `execve("/bin/sh", 0, 0)` via a trampoline-built ROP stack.
- **JIT generation strategy:** Each run creates a uniquely named Python function with stencil-friendly arithmetic/dict/attribute/comparison activity and iterates it 5,000 times to trigger tier-2 compilation. Constants come from a stencil-aligned `MAGIC_VALUES` list (e.g., `0x00005FC3` for `pop rdi; ret`).【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L10-L116】【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L200-L250】
- **Gadget discovery:** Leaks each function’s JIT address with `jitexecleak.leak_executor_jit`, scans for gadgets with Capstone, and tracks successes globally. Missing gadgets (except `xor edx, edx`) are synthesized with RWX-mapped shellcode; an alternate chain uses `xor edx, edx; ret` if no `pop rdx; ret` is found.【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L130-L198】【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L252-L333】
- **Execution flow:** Builds a stack containing the `execve` chain, writes a small trampoline (`mov rsp, stack+8; mov rax, first_gadget; jmp rax`), and executes it via a ctypes function pointer. An interactive prompt precedes the final jump to the chain.【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L70-L118】【F:case_studies/case4/gadget_chain_from_multi_jitcode_exec_sh_success.py†L216-L250】

## `gadget_chain_parallel.py`
- **Goal:** Broader coverage via **spread allocation**—creating many JIT functions across multiple synthetic modules to reduce executor reuse, gather gadgets, and fall back to libc or shellcode when needed, then trigger the same `execve` chain.
- **Spread strategy:** Generates functions across up to 10 modules, separates them with 1MB dummy buffers, warms all functions to tier-2, keeps references to prevent GC, and records unique JIT addresses. Each function uses the same stencil-oriented loop pattern and `MAGIC_VALUES` constants.【F:case_studies/case4/gadget_chain_parallel.py†L1-L119】【F:case_studies/case4/gadget_chain_parallel.py†L120-L215】
- **Gadget sources:** Scans every JIT blob for target gadgets (`pop rax/rdi/rsi/rdx; ret`, `syscall`, `xor edx, edx`). If any remain missing (except `xor edx, edx`), it attempts to resolve them from runtime libc offsets via `get_runtime_gadget_addresses`, and only then injects shellcode for gaps.【F:case_studies/case4/gadget_chain_parallel.py†L217-L323】【F:case_studies/case4/gadget_chain_parallel.py†L324-L393】
- **Chain execution:** Constructs the `execve` ROP stack and a trampoline identical in layout to the single-function PoC, with a prompt before execution.【F:case_studies/case4/gadget_chain_parallel.py†L326-L362】

## Usage Notes
- Both scripts rely on `jitexecleak.leak_executor_jit` to find JIT memory and Capstone to disassemble it; they allocate RWX pages directly for trampolines, stacks, and fallback shellcode.
- The ROP payload assumes the traditional Linux `execve` syscall number (`59`) and requires user confirmation before jumping to the chain.
- For background, see the scenario description in `case_studies/case4/README.md` (Case Study 4 overview and motivation for stencil-guided gadget hunting).【F:case_studies/case4/README.md†L1-L150】
