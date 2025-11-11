#!/usr/bin/env python3

"""
Scan build/jit_stencils.h for instruction byte patterns that correspond to
MAGIC_VALUES-friendly gadgets, using wildcard matching for any displacement,
immediate, or rel32/imm64 fields.

Notes:
- We parse code_body[] byte arrays inside each emit__* stencil function.
- Patterns can include '??' to match any byte (e.g., rel32, imm64).
- We report matches with function name and code-body offset.

Patterns searched (x86-64):
- ret: c3
- pop reg; ret: 58/59/5a/5b/5c/5d/5e/5f c3 (skip pop rsp)
- xor rax, rax: 48 31 c0
- xor edx, edx: 31 d2
- mov eax, 59: b8 3b 00 00 00
- syscall: 0f 05
- call rel32: e8 ?? ?? ?? ?? (for reference)
- jmp rel32: e9 ?? ?? ?? ?? (for reference)
- jne rel32: 0f 85 ?? ?? ?? ?? (for reference)
- je  rel32: 0f 84 ?? ?? ?? ?? (for reference)
"""

from __future__ import annotations

import os
import re
import sys
from typing import List, Optional, Tuple, Dict
import json
import argparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Correct path: jit_stencils.h is directly under cpython/build/ (ROOT/build/jit_stencils.h was missing cpython segment)
STENCILS = os.path.join(ROOT, "cpython", "build", "jit_stencils.h")


def compile_pattern(hexstr: str) -> List[Optional[int]]:
    parts = hexstr.strip().split()
    out: List[Optional[int]] = []
    for p in parts:
        if p == "??":
            out.append(None)
        else:
            out.append(int(p, 16))
    return out


def find_matches(buf: bytes, pat: List[Optional[int]]) -> List[int]:
    m: List[int] = []
    n = len(pat)
    if n == 0:
        return m
    # Simple sliding window
    for i in range(0, len(buf) - n + 1):
        ok = True
        for k, want in enumerate(pat):
            if want is None:
                continue
            if buf[i + k] != want:
                ok = False
                break
        if ok:
            m.append(i)
    return m


def parse_code_segments(text: str) -> List[Tuple[str, bytes]]:
    """Extract (func_name, code_bytes) for each emit* function's code_body.

    We accept names beginning with 'emit' followed by any word chars.
    The earlier implementation was too restrictive and skipped emit_shim.
    """
    segs: List[Tuple[str, bytes]] = []
    func_name: Optional[str] = None
    in_code = False
    bytes_list: List[int] = []
    brace_depth = 0

    re_func = re.compile(r"\b(emit[_A-Za-z0-9]*)\s*\(")
    # code_body can have size like [33]
    re_code_start = re.compile(r"\bcode_body\s*\[.*?\]\s*=\s*\{")
    re_hex = re.compile(r"0x([0-9a-fA-F]{1,2})")

    lines = text.splitlines()
    for line in lines:
        if func_name is None:
            m = re_func.search(line)
            if m:
                func_name = m.group(1)
            continue

        if not in_code:
            if re_code_start.search(line):
                in_code = True
                brace_depth = 1  # opening '{' consumed
                bytes_list = []
            elif line.strip().startswith('}'):  # end of function before code_body
                func_name = None
            continue

        # Collect bytes inside code_body initializer
        brace_depth += line.count('{')
        brace_depth -= line.count('}')
        for hm in re_hex.finditer(line):
            bytes_list.append(int(hm.group(1), 16))
        if brace_depth == 0:
            # Finished array
            segs.append((func_name or '<unknown>', bytes(bytes_list)))
            func_name = None
            in_code = False
            bytes_list = []

    return segs


def _extract_ret_window_gadgets(code: bytes, base_label: str = "retwin") -> Dict[str, List[int]]:
    """Look back up to 8 bytes before each ret for small gadget pairs like:
    - pop rdi; ret
    - pop rsi; ret
    - pop rdx; ret
    - xor edx, edx; ret
    - xor rax, rax; ret
    Return mapping pattern_name -> list of offsets.
    """
    patterns = {
        "pop_rdi_ret": [0x5F, 0xC3],
        "pop_rsi_ret": [0x5E, 0xC3],
        "pop_rdx_ret": [0x5A, 0xC3],
        "pop_rbx_ret": [0x5B, 0xC3],
        "xor_edx_edx_ret": [0x31, 0xD2, 0xC3],
        "xor_rax_rax_ret": [0x48, 0x31, 0xC0, 0xC3],
    }
    hits: Dict[str, List[int]] = {k: [] for k in patterns}
    rets = [i for i, b in enumerate(code) if b == 0xC3]
    for r in rets:
        start = max(0, r - 8)
        window = code[start:r + 1]
        for name, pat in patterns.items():
            if len(window) >= len(pat) and window[-len(pat):] == bytes(pat):
                hits[name].append(start + (len(window) - len(pat)))
    # prune empties
    return {k: v for k, v in hits.items() if v}


def main():
    ap = argparse.ArgumentParser(description="Scan jit_stencils.h for gadget-like byte patterns")
    ap.add_argument("--json", dest="json_out", help="Write results to JSON file path")
    args = ap.parse_args()

    if not os.path.exists(STENCILS):
        print(f"[error] Not found: {STENCILS}")
        sys.exit(1)
    with open(STENCILS, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()

    segs = parse_code_segments(text)
    if not segs:
        print("[warn] No code_body segments parsed. Parser may need adjustment.")

    # Define patterns
    patterns: Dict[str, List[List[Optional[int]]]] = {
        "ret": [compile_pattern("c3")],
        # pop reg; ret (skip rsp=5c)
        "pop_rax_ret": [compile_pattern("58 c3")],
        "pop_rcx_ret": [compile_pattern("59 c3")],
        "pop_rdx_ret": [compile_pattern("5a c3")],
        "pop_rbx_ret": [compile_pattern("5b c3")],
        # 'pop rsp; ret' excluded by default
        "pop_rbp_ret": [compile_pattern("5d c3")],
        "pop_rsi_ret": [compile_pattern("5e c3")],
        "pop_rdi_ret": [compile_pattern("5f c3")],
        "xor_rax_rax": [compile_pattern("48 31 c0")],
        "xor_edx_edx": [compile_pattern("31 d2")],
        "mov_eax_59": [compile_pattern("b8 3b 00 00 00")],
        "syscall": [compile_pattern("0f 05")],
        # control-flow with wildcards
        "call_rel32": [compile_pattern("e8 ?? ?? ?? ??")],
        "jmp_rel32": [compile_pattern("e9 ?? ?? ?? ??")],
        "jne_rel32": [compile_pattern("0f 85 ?? ?? ?? ??")],
        "je_rel32": [compile_pattern("0f 84 ?? ?? ?? ??")],
    }

    total_hits: Dict[str, int] = {k: 0 for k in patterns}
    per_func: Dict[str, Dict[str, List[int]]] = {}
    retwin: Dict[str, Dict[str, List[int]]] = {}

    for fname, code in segs:
        for pname, plist in patterns.items():
            hits_here: List[int] = []
            for pat in plist:
                hits = find_matches(code, pat)
                if hits:
                    hits_here.extend(hits)
            if hits_here:
                hits_here = sorted(set(hits_here))
                total_hits[pname] += len(hits_here)
                per_func.setdefault(fname, {}).setdefault(pname, []).extend(hits_here)
        # ret window combos
        ret_hits = _extract_ret_window_gadgets(code)
        if ret_hits:
            retwin[fname] = ret_hits

    # Report (human)
    print(f"Scanned {len(segs)} stencil code bodies in {os.path.relpath(STENCILS, ROOT)}")
    print("Overall hits:")
    for pname in patterns:
        print(f"  {pname:12s}: {total_hits.get(pname, 0)}")

    if per_func:
        print("\nFunctions with hits:")
        for fname in sorted(per_func.keys()):
            print(f"- {fname}")
            inner = per_func[fname]
            for pname in patterns:
                locs = inner.get(pname)
                if not locs:
                    continue
                sample = ", ".join(hex(x) for x in sorted(locs)[:8])
                print(f"    {pname:12s}: {len(locs)}  at [{sample}{', ...' if len(locs)>8 else ''}]")
            if fname in retwin:
                print(f"    ret-window:")
                for k, locs in retwin[fname].items():
                    sample = ", ".join(hex(x) for x in sorted(locs)[:6])
                    print(f"      {k:16s}: {len(locs)}  at [{sample}{', ...' if len(locs)>6 else ''}]")

    # JSON output
    if args.json_out:
        out = {
            "file": os.path.relpath(STENCILS, ROOT),
            "summary": total_hits,
            "per_func": per_func,
            "ret_window": retwin,
        }
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump(out, jf, indent=2)
        print(f"\n[json] wrote: {args.json_out}")


if __name__ == "__main__":
    main()
