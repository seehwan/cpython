#!/usr/bin/env python3
"""
libc Gadget Finder
==================
libc.so에서 ROP 가젯을 찾아주는 도구

사용법:
    python3 libc_gadget_finder.py
"""

import os
import re
import mmap


def find_libc_base():
    """현재 프로세스의 libc 베이스 주소와 경로 찾기"""
    with open(f'/proc/{os.getpid()}/maps', 'r') as f:
        for line in f:
            if 'libc' in line and 'r-xp' in line:
                parts = line.split()
                addr_range = parts[0]
                base_addr = int(addr_range.split('-')[0], 16)
                path = parts[-1]
                return base_addr, path
    return None, None


def find_gadgets_in_binary(binary_path):
    """바이너리 파일에서 가젯 패턴 검색"""
    gadgets = {
        'pop_rsi_ret': [],
        'pop_rdx_ret': [],
        'pop_rdi_ret': [],
        'pop_rax_ret': [],
        'syscall': [],           # syscall alone (preferred for final gadget)
        'syscall_ret': []        # syscall; ret (unnecessary but kept for compatibility)
    }
    
    patterns = {
        'pop_rsi_ret': b'\x5e\xc3',       # pop rsi; ret
        'pop_rdx_ret': b'\x5a\xc3',       # pop rdx; ret
        'pop_rdi_ret': b'\x5f\xc3',       # pop rdi; ret
        'pop_rax_ret': b'\x58\xc3',       # pop rax; ret
        'syscall': b'\x0f\x05',           # syscall (execve doesn't return, so no ret needed!)
        'syscall_ret': b'\x0f\x05\xc3',   # syscall; ret (for completeness)
    }
    
    print(f"[*] Scanning {binary_path}...")
    
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # 각 패턴 검색
    for name, pattern in patterns.items():
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            gadgets[name].append(pos)
            offset = pos + 1
    
    # 통계 출력
    print(f"\n[+] Gadget Statistics:")
    for name, offsets in gadgets.items():
        if offsets:
            print(f"    {name}: {len(offsets)} occurrences")
            # 처음 3개만 오프셋 표시
            for i, off in enumerate(offsets[:3]):
                print(f"      [{i}] offset: 0x{off:x}")
            if len(offsets) > 3:
                print(f"      ... and {len(offsets) - 3} more")
    
    return gadgets


def get_runtime_gadget_addresses():
    """런타임에 실제 사용 가능한 가젯 주소 반환"""
    libc_base, libc_path = find_libc_base()
    
    if not libc_base or not libc_path:
        print("[!] Could not find libc in process memory")
        return None
    
    print(f"[*] Found libc at: {hex(libc_base)}")
    print(f"[*] Path: {libc_path}")
    
    # 가젯 오프셋 찾기
    gadget_offsets = find_gadgets_in_binary(libc_path)
    
    # 베이스 주소를 더해서 실제 주소 계산
    gadget_addresses = {}
    for name, offsets in gadget_offsets.items():
        if offsets:
            # 첫 번째 발견된 가젯 사용
            gadget_addresses[name] = libc_base + offsets[0]
    
    return gadget_addresses, libc_base


def print_gadget_addresses(gadget_addrs, libc_base):
    """가젯 주소를 보기 좋게 출력"""
    print(f"\n[+] Runtime Gadget Addresses (libc_base={hex(libc_base)}):")
    print("=" * 70)
    
    essential = ['pop_rdi_ret', 'pop_rsi_ret', 'pop_rdx_ret', 'pop_rax_ret', 'syscall_ret']
    
    for name in essential:
        if name in gadget_addrs:
            addr = gadget_addrs[name]
            offset = addr - libc_base
            print(f"  {name:20s} = {hex(addr):18s}  (offset: 0x{offset:x})")
        else:
            print(f"  {name:20s} = NOT FOUND")
    
    print("=" * 70)


def verify_gadgets(gadget_addrs):
    """가젯이 실제로 읽을 수 있는 메모리에 있는지 확인"""
    print("\n[*] Verifying gadget accessibility...")
    
    for name, addr in gadget_addrs.items():
        try:
            # ctypes로 메모리 읽기 시도
            import ctypes
            ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ubyte * 4))
            bytes_at_addr = bytes(ptr.contents)
            print(f"  {name}: {bytes_at_addr.hex()} at {hex(addr)} ✓")
        except Exception as e:
            print(f"  {name}: INACCESSIBLE at {hex(addr)} ✗ ({e})")


def main():
    print("=" * 70)
    print("  libc ROP Gadget Finder")
    print("=" * 70)
    
    result = get_runtime_gadget_addresses()
    if not result:
        return 1
    
    gadget_addrs, libc_base = result
    
    if not gadget_addrs:
        print("[!] No gadgets found!")
        return 1
    
    print_gadget_addresses(gadget_addrs, libc_base)
    
    # 가젯 접근 가능성 검증
    verify_gadgets(gadget_addrs)
    
    # 사용 예제 코드 생성
    print("\n[+] Example usage in your exploit:")
    print("-" * 70)
    print("from libc_gadget_finder import get_runtime_gadget_addresses")
    print()
    print("gadgets, libc_base = get_runtime_gadget_addresses()")
    print("pop_rdi = gadgets['pop_rdi_ret']")
    print("pop_rsi = gadgets['pop_rsi_ret']")
    print("pop_rdx = gadgets['pop_rdx_ret']")
    print("pop_rax = gadgets['pop_rax_ret']")
    print("syscall = gadgets['syscall_ret']")
    print()
    print("# Build ROP chain")
    print("rop_chain = struct.pack('<Q', pop_rax) + struct.pack('<Q', 59)  # execve")
    print("rop_chain += struct.pack('<Q', pop_rdi) + struct.pack('<Q', binsh_addr)")
    print("rop_chain += struct.pack('<Q', pop_rsi) + struct.pack('<Q', 0)")
    print("rop_chain += struct.pack('<Q', pop_rdx) + struct.pack('<Q', 0)")
    print("rop_chain += struct.pack('<Q', syscall)")
    print("-" * 70)
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
