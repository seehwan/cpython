import ctypes
import struct

# 1. shellcode address (fake for example)
sc_addr = 0xfffff7fef000

# 2. trampoline bytes
tramp = (
    b"\x50\x00\x00\x58" +             # ldr x16, [pc, #8]
    b"\x00\x02\x1f\xd6" +             # br x16
    struct.pack("<Q", sc_addr)       # 8-byte little-endian shellcode addr
)

# 3. allocate full buffer (16 bytes)
tramp_buf = ctypes.create_string_buffer(tramp, len(tramp))  # explicitly pass size!
tramp_addr = ctypes.addressof(tramp_buf)
