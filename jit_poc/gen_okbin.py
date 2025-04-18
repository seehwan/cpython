import base64

# AArch64 shellcode: write "OK\n" to stdout (fd=1), then exit(0)
shellcode = (
    b"\x20\x00\x80\xd2"      # 0x00: movz x0, #1        ; stdout
    b"\xe1\x00\x00\x10"      # 0x04: adr x1, #0x20      ; → 0x28
    b"\x42\x00\x80\xd2"      # 0x08: movz x2, #2        ; length
    b"\x08\x08\x80\xd2"      # 0x0c: movz x8, #8        ; sys_write
    b"\x01\x00\x00\xd4"      # 0x10: svc #0
    b"\x00\x00\x80\xd2"      # 0x14: movz x0, #0
    b"\xa8\x0b\x80\xd2"      # 0x18: movz x8, #93       ; sys_exit
    b"\x01\x00\x00\xd4"      # 0x1c: svc #0
    b"OK"                    # 0x20: message
)

with open("ok.bin", "wb") as f:
    f.write(shellcode)
