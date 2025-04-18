#!/usr/bin/env python3
import ctypes
import mmap
import json
import time
import os
import struct
import traceback
import fcntl

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

def execute_once(run_id, offset):
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    mem_size = 0x4000
    mem_addr = libc.mmap(None, mem_size, 7, 0x22, -1, 0)
    sc_addr = mem_addr
    ctypes.memmove(sc_addr, OK_EXIT_CODE, len(OK_EXIT_CODE))

    tramp = (
        b"\x50\x00\x00\x58" +  # ldr x16, #8
        b"\x00\x02\x1f\xd6" +  # br x16
        struct.pack("<Q", sc_addr)
    )
    tramp_addr = sc_addr + offset
    ctypes.memmove(tramp_addr, tramp, len(tramp))

    log = {
        "pid": os.getpid(),
        "run_id": run_id,
        "trampoline_offset": offset,
        "trampoline_addr": hex(tramp_addr),
        "shellcode_addr": hex(sc_addr),
        "status": "unknown",
        "timestamp": time.time()
    }

    try:
        start = time.time()
        fn = ctypes.CFUNCTYPE(None)(tramp_addr)
        fn()
        log["status"] = "success"
        log["exec_time_ms"] = round((time.time() - start) * 1000, 3)
    except Exception as e:
        log["status"] = "fail"
        log["error"] = str(e)
        log["traceback"] = traceback.format_exc()

    with open("trampoline_offset_experiment.jsonl", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(log) + "\n")
        fcntl.flock(f, fcntl.LOCK_UN)

if __name__ == "__main__":
    for i, offset in enumerate(range(0x1000, 0x3000, 0x100)):
        execute_once(run_id=i, offset=offset)
