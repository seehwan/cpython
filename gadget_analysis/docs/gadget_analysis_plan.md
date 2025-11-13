# Gadget-Oriented Analysis Plan

This document captures the follow-up work for documenting and measuring gadget generation in CPython’s stencil-based JIT without further modifying `noarm.tex`.

## 1. Catalog Stencil Gadgets
- Instrument the emitter to dump `code_body[]` and `data_body[]` before and after every `patch_*` call.
- Label gadgets as:
  - Baseline template prologues/type checks.
  - Data-slot trampolines (e.g., `jmp rax`, `call [rip+imm]`).
  - Patch-induced decodings that appear only after overwrites.
- Visualization: heat map (stencil ID × gadget category) with counts encoded by color.

## 2. Study Unaligned Decoding
- Re-run Capstone with decode offsets 0–7 on identical executor buffers.
- Compare gadget counts before vs. after patching to isolate partial-overwrite effects.
- Visualization: bar chart of offset vs. gadget density, highlighting spikes for bytes like `0xC3`, `0x0F05`, `0xFF`.

## 3. Quantify Patch-Function Impact
- Log each `patch_*` invocation (function name, target offset, pre/post bytes).
- Decode both versions and count new gadgets.
- Visualization: scatter plot (offset vs. new gadgets) colored by patch routine; supplementary table summarizing gadget types per patch.

## 4. Scale Executor Memory
- Allocate varying numbers of JIT regions (e.g., 1, 8, 32, 80 × 128 KB) and record gadget counts.
- Fit linear/near-linear trend until saturation; capture confidence intervals over repeated runs.
- Extend existing base-address CDF (Fig. `x86_jit_cdf`) with violin plots of normalized gadget offsets once the base leak is known.

## 5. Classify Ret-Free Syscall Chains
- Automate gadget taxonomy into `{ret, syscall, indirect branch, stack pivot}`.
- Highlight chains that only rely on `pop` gadgets plus `syscall` (no trailing `ret`).
- Visualization: stacked bar chart per architecture showing gadget-type proportions.

## 6. Opcode-Sensitive Function Generator
- Use the following template to bias emitted bytes toward gadget-friendly opcodes:
  ```python
  def spray_execve(seed, buf):
      helper = lambda v: (v ^ 0xC3C3C3C3) + 0x0F05FF90
      acc = seed
      for i in range(2048 + (seed & 0xFF)):
          acc ^= helper(acc) + (i << (i & 7))
          acc = ((acc << (i & 3)) | (acc >> (32 - (i & 3)))) & 0xFFFFFFFF
          acc += buf[i % len(buf)]
          if i & 1:
              acc ^= buf[(i * 3) % len(buf)]
          else:
              acc += helper(buf[(i * 5) % len(buf)])
      return acc
  ```
- Embed helper lambdas to force extra trampolines and feed attacker-controlled buffers for fine-grained byte patterns.
- Pair with multi-region spraying (up to ~10 MB) to maintain ample gadget diversity for analysis.

## 7. Document Toolkit References
- Leverage the components summarized in `docs/README.md` (generator, scanner, classifier, reporter, config) so every experiment cites the exact module used.
- Reference the framework name (“Gadget Analysis Framework”) when describing automation in the paper to guide readers toward reproducibility.
- When referencing source files in prose or appendices, point to `docs/gadget_analysis/` as the canonical location for scripts supporting the analysis.

## 8. Integration With `noarm.tex`
- All new text, figures, and tables must target `noarm.tex` only (legacy `.tex` files stay untouched).
- Add cross-references from the paper’s Security Analysis and Exploitation sections to the datasets produced by this plan.
- When figures are ready, stage them under `fig/` and update only the corresponding `\includegraphics{}` entries in `noarm.tex`.

## 9. Deliverables
1. Instrumentation scripts (byte dumps, multi-offset disassembly, taxonomy classifier).
2. Visualization suite (heat maps, bar charts, scatter plots, violin plots, stacked bars).
3. Dataset comparing gadget statistics across executor sizes, decode offsets, and patch functions.
4. Narrative summary tying experiments back to the six attack surfaces outlined by the user.
5. Patch-ready snippets (LaTeX paragraphs, figure captions, table text) referencing the new results for `noarm.tex`.
