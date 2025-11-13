#!/usr/bin/env python3
"""
Configuration Module
====================

Shared configuration and constants for gadget analysis framework.
"""

# Gadget patterns (x86-64)
GADGET_PATTERNS = {
    'pop_rax': b'\x58',
    'pop_rdi': b'\x5f',
    'pop_rsi': b'\x5e',
    'pop_rdx': b'\x5a',
    'pop_rbx': b'\x5b',
    'pop_rcx': b'\x59',
    'syscall': b'\x0f\x05',
    'ret': b'\xc3',
}

# JIT compilation settings
JIT_WARMUP_ITERATIONS = 5000  # Tier 2 JIT requires ~5000 iterations
JIT_MODULE_COUNT = 10          # Number of modules for spread allocation

# Memory settings
SPREAD_DUMMY_SIZE = 1024 * 1024  # 1MB dummy allocation between modules

# Magic values for function generation (stencil-friendly patterns)
MAGIC_VALUES = [
    0x000000C3,  # ret
    0x00005FC3,  # pop rdi; ret
    0x00005EC3,  # pop rsi; ret
    0x00005AC3,  # pop rdx; ret
    0x00005BC3,  # pop rbx; ret
    0x000031D2,  # xor edx, edx
    0x004831C0,  # xor rax, rax
]

# Function generation settings
FUNCTION_BASE_ITERATIONS = 3000
FUNCTION_ITER_INCREMENT = 500

# Analysis settings
PROGRESS_REPORT_INTERVAL = 100  # Report progress every N functions
