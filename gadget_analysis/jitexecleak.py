#!/usr/bin/env python3
"""
JIT Executor Leak Module
Extracts JIT code address and size from Python function executors
"""
import _opcode
import ctypes


def leak_executor_jit(func):
    """
    Extract REAL JIT code address and size from a function's executor
    
    This function directly reads the jit_code pointer from the _PyExecutorObject
    structure, giving us the actual executable memory address (not a copy).
    
    Args:
        func: Python function object that has been JIT compiled
        
    Returns:
        tuple: (jit_code_address, jit_code_size) - REAL executable memory address
        
    Raises:
        RuntimeError: If no JIT executor found or JIT code unavailable
    """
    code = func.__code__
    
    # Scan all bytecode offsets to find an executor
    executor = None
    found_offset = None
    
    for offset in range(0, len(code.co_code), 2):
        try:
            ex = _opcode.get_executor(code, offset)
            if ex is not None:
                executor = ex
                found_offset = offset
                break
        except (ValueError, RuntimeError):
            continue
    
    if executor is None:
        raise RuntimeError(f"No executor found for function {func.__name__}")
    
    # Check if executor is valid
    if not executor.is_valid():
        raise RuntimeError(f"Executor at offset {found_offset} is invalid")
    
    # Get executor object's memory address
    executor_addr = id(executor)
    
    # Calculate offset to jit_code field
    # Empirically determined offsets (from CPython 3.14 JIT build):
    # - jit_size is at offset 104
    # - jit_code is at offset 112
    # These were found by scanning the executor object structure
    
    JIT_SIZE_OFFSET = 104
    JIT_CODE_OFFSET = 112
    
    # Read jit_size (size_t = 8 bytes on x86-64)
    jit_size = ctypes.c_size_t.from_address(executor_addr + JIT_SIZE_OFFSET).value
    
    # Read jit_code pointer (void* = 8 bytes on x86-64)
    jit_addr = ctypes.c_void_p.from_address(executor_addr + JIT_CODE_OFFSET).value
    
    if jit_addr is None or jit_addr == 0:
        raise RuntimeError(f"JIT code pointer is NULL for executor at offset {found_offset}")
    
    if jit_size == 0:
        raise RuntimeError(f"JIT code size is 0 for executor at offset {found_offset}")
    
    return jit_addr, jit_size


def find_all_executors(func):
    """
    Find all executors for a given function
    
    Args:
        func: Python function object
        
    Returns:
        list: List of (offset, executor, jit_addr, jit_size) tuples
    """
    code = func.__code__
    results = []
    
    for offset in range(0, len(code.co_code), 2):
        try:
            ex = _opcode.get_executor(code, offset)
            if ex is not None and ex.is_valid():
                executor_addr = id(ex)
                JIT_SIZE_OFFSET = 104
                JIT_CODE_OFFSET = 112
                
                jit_size = ctypes.c_size_t.from_address(executor_addr + JIT_SIZE_OFFSET).value
                jit_addr = ctypes.c_void_p.from_address(executor_addr + JIT_CODE_OFFSET).value
                
                if jit_addr and jit_size > 0:
                    results.append((offset, ex, jit_addr, jit_size))
        except (ValueError, RuntimeError):
            continue
    
    return results


if __name__ == "__main__":
    # Quick test
    def test_func(x):
        s = 0
        for i in range(x):
            s += i
        return s
    
    # Warmup to trigger JIT
    print("[*] Warming up test function...")
    for _ in range(50000):
        test_func(100)
    
    try:
        addr, size = leak_executor_jit(test_func)
        print(f"[+] JIT code @ {hex(addr)}, size: {size} bytes")
    except RuntimeError as e:
        print(f"[!] Failed: {e}")
