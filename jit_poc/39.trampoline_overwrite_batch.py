#!/usr/bin/env python3
import ctypes
import mmap
import multiprocessing
import json
import time
import os
import struct
import traceback
import fcntl

# Lightweight shellcode: write "OK" then exit(0)
OK_EXIT_CODE = (
    b"\x20\x00\x80\xd2"  # movz x0, #1
    b"\xe1\x00\x00\x10"  # adr x1, #0x20
    b"\x42\x00\x80\xd2"  # movz x2, #2
    b"\x08\x08\x80\xd2"  # movz x8, #8 (write)
    b"\x01\x00\x00\xd4"  # svc #0
    b"\x00\x00\x80\xd2"  # movz x0, #0
    b"\xa8\x0b\x80\xd2"  # movz x8, #93 (exit)
    b"\x01\x00\x00\xd4"  # svc #0
    b"OK"
)

def execute_once(run_id):
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    sc_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)  # PROT_RWX, MAP_PRIVATE|MAP_ANON
    ctypes.memmove(sc_addr, OK_EXIT_CODE, len(OK_EXIT_CODE))

    tramp = (
        b"\x50\x00\x00\x58" +  # ldr x16, #8
        b"\x00\x02\x1f\xd6" +  # br x16
        struct.pack("<Q", sc_addr)
    )
    tramp_buf = ctypes.create_string_buffer(tramp)
    tramp_addr = ctypes.addressof(tramp_buf)

    log = {
        "pid": os.getpid(),
        "run_id": run_id,
        "trampoline_addr": hex(tramp_addr),
        "shellcode_addr": hex(sc_addr),
        "status": "unknown",
        "timestamp": time.time()
    }

    try:
        fn = ctypes.CFUNCTYPE(None)(tramp_addr)
        fn()
        log["status"] = "success"
    except Exception as e:
        log["status"] = "fail"
        log["error"] = str(e)
        log["traceback"] = traceback.format_exc()

    # Safe concurrent file write using fcntl lock
    with open("trampoline_overwrite_results.jsonl", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(log) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn")
    pool = multiprocessing.Pool(processes=8)
    pool.map(execute_once, list(range(100)))
