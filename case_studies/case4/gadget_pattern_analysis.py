#!/usr/bin/env python3
"""
JIT Gadget Pattern Analysis
가젯 생성을 극대화하기 위한 코드 패턴 분석
"""
import ctypes
import jitexecleak
from capstone import *

def find_all_gadgets(blob, jit_addr):
    """JIT 코드에서 모든 pop/syscall 가젯 찾기"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    gadgets = {
        'pop_rax': [], 'pop_rbx': [], 'pop_rcx': [], 'pop_rdx': [],
        'pop_rsi': [], 'pop_rdi': [], 'pop_rbp': [], 'pop_rsp': [],
        'pop_r8': [], 'pop_r9': [], 'pop_r10': [], 'pop_r11': [],
        'pop_r12': [], 'pop_r13': [], 'pop_r14': [], 'pop_r15': [],
        'syscall': []
    }
    
    for i in range(len(blob) - 3):
        insns = list(md.disasm(blob[i:i+5], jit_addr + i))
        if len(insns) >= 2:
            # pop reg; ret
            if insns[0].mnemonic == 'pop' and insns[1].mnemonic == 'ret':
                reg = insns[0].op_str.strip()
                key = f'pop_{reg}'
                if key in gadgets:
                    gadgets[key].append(hex(insns[0].address))
        
        if len(insns) >= 1:
            # syscall
            if insns[0].mnemonic == 'syscall':
                gadgets['syscall'].append(hex(insns[0].address))
    
    return gadgets

def test_code_pattern(name, code_generator, iterations=3000):
    """특정 코드 패턴의 가젯 생성 효과 테스트"""
    f = code_generator()
    
    # Warm up
    for i in range(iterations):
        f(i)
    
    try:
        jit_addr, size = jitexecleak.leak_executor_jit(f)
        blob = (ctypes.c_ubyte * size).from_address(jit_addr)
        gadgets = find_all_gadgets(bytes(blob), jit_addr)
        
        # 발견된 가젯 통계
        found = {k: len(v) for k, v in gadgets.items() if v}
        total = sum(found.values())
        
        print(f"\n{'='*70}")
        print(f"Pattern: {name}")
        print(f"{'='*70}")
        print(f"Total gadgets: {total}")
        print(f"Found registers: {list(found.keys())}")
        for k, v in sorted(found.items(), key=lambda x: x[1], reverse=True):
            print(f"  {k}: {v}")
        
        return found
    except Exception as e:
        print(f"\nPattern: {name} - Failed: {e}")
        return {}

# ============================================================================
# 패턴 1: 기본 루프 (현재 방식)
# ============================================================================
def pattern_basic():
    code = """
def f(x):
    acc = x
    for i in range(5000):
        acc ^= (0xC3 + i)
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 2: 다중 인자 함수 호출 (rdi, rsi, rdx, rcx, r8, r9 사용)
# ============================================================================
def pattern_multiarg_calls():
    code = """
def helper(a, b, c, d, e, f):
    return (a + b + c + d + e + f) & 0xFFFFFFFF

def f(x):
    acc = x
    for i in range(5000):
        acc = helper(i, i+1, i+2, i+3, i+4, i+5)
        acc ^= i
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 3: 중첩 함수 + 클로저 (스택 프레임 조작)
# ============================================================================
def pattern_nested_closure():
    code = """
def f(x):
    outer_var = x
    
    def inner1(a):
        return (a + outer_var) & 0xFFFFFFFF
    
    def inner2(b):
        return (b ^ outer_var) & 0xFFFFFFFF
    
    acc = x
    for i in range(5000):
        acc = inner1(i)
        acc = inner2(acc)
        outer_var += 1
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 4: 예외 처리 (try/except)
# ============================================================================
def pattern_exception_handling():
    code = """
def f(x):
    acc = x
    for i in range(5000):
        try:
            acc ^= (0xC3 + i)
            if i % 1000 == 0:
                acc = acc // (i % 3 + 1)
        except:
            acc = i
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 5: 리스트/딕셔너리 연산 (많은 메모리 접근)
# ============================================================================
def pattern_container_ops():
    code = """
def f(x):
    data = [0] * 100
    d = {}
    acc = x
    for i in range(5000):
        idx = i % 100
        data[idx] = (acc + i) & 0xFF
        acc ^= data[idx]
        
        if i % 50 == 0:
            d[i] = acc
            acc += d.get(i, 0)
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 6: 객체 속성 접근 (LOAD_ATTR, STORE_ATTR)
# ============================================================================
def pattern_object_attrs():
    code = """
def f(x):
    class State:
        val1 = 0
        val2 = 0
        val3 = 0
    
    state = State()
    acc = x
    for i in range(5000):
        state.val1 = (acc + i) & 0xFF
        state.val2 = (acc ^ i) & 0xFF
        state.val3 = (acc - i) & 0xFF
        acc = state.val1 + state.val2 + state.val3
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 7: 제너레이터 (yield)
# ============================================================================
def pattern_generator():
    code = """
def gen(n):
    for i in range(n):
        yield i * 2

def f(x):
    acc = x
    for val in gen(5000):
        acc ^= val
        acc = (acc + 1) & 0xFFFFFFFF
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 8: 언패킹 연산 (*args, **kwargs)
# ============================================================================
def pattern_unpacking():
    code = """
def helper(*args):
    return sum(args) & 0xFFFFFFFF

def f(x):
    acc = x
    for i in range(5000):
        args = (i, i+1, i+2, i+3)
        acc = helper(*args)
        acc ^= i
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 9: 재귀 호출
# ============================================================================
def pattern_recursion():
    code = """
def recursive(n, acc):
    if n <= 0:
        return acc
    return recursive(n-1, (acc + n) & 0xFFFFFFFF)

def f(x):
    acc = x
    for i in range(500):  # 재귀는 비용이 크므로 적게
        acc = recursive(min(i % 20, 10), acc)
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 패턴 10: 복합 패턴 (여러 기법 조합)
# ============================================================================
def pattern_combined():
    code = """
def helper(a, b, c, d):
    return (a + b * c - d) & 0xFFFFFFFF

def f(x):
    class State:
        val = 0
    
    state = State()
    data = {}
    
    def nested(n):
        return (n ^ state.val) & 0xFFFFFFFF
    
    acc = x
    for i in range(5000):
        # 다중 인자 함수
        acc = helper(i, i+1, i+2, i+3)
        
        # 중첩 함수
        acc = nested(acc)
        
        # 객체 속성
        state.val = acc & 0xFF
        
        # 딕셔너리
        if i % 100 == 0:
            data[i] = acc
            acc ^= data.get(i, 0)
        
        # 예외 처리
        try:
            acc = acc // (i % 5 + 1)
        except:
            pass
    
    return acc
"""
    scope = {}
    exec(code, scope)
    return scope['f']

# ============================================================================
# 메인 분석
# ============================================================================
def main():
    print("\n" + "="*70)
    print("JIT Gadget Generation Pattern Analysis")
    print("="*70)
    
    patterns = [
        ("1. Basic Loop (baseline)", pattern_basic),
        ("2. Multi-arg Function Calls", pattern_multiarg_calls),
        ("3. Nested Functions + Closures", pattern_nested_closure),
        ("4. Exception Handling", pattern_exception_handling),
        ("5. Container Operations", pattern_container_ops),
        ("6. Object Attributes", pattern_object_attrs),
        ("7. Generator", pattern_generator),
        ("8. Unpacking (*args)", pattern_unpacking),
        ("9. Recursion", pattern_recursion),
        ("10. Combined Pattern", pattern_combined),
    ]
    
    results = {}
    for name, gen in patterns:
        try:
            result = test_code_pattern(name, gen)
            results[name] = result
        except Exception as e:
            print(f"\n{name} - Error: {e}")
            results[name] = {}
    
    # 최종 비교
    print("\n\n" + "="*70)
    print("COMPARISON SUMMARY")
    print("="*70)
    print(f"{'Pattern':<40} {'Total':>8} {'Unique Regs':>15}")
    print("-"*70)
    
    for name, gadgets in results.items():
        total = sum(gadgets.values())
        unique = len(gadgets)
        print(f"{name:<40} {total:>8} {unique:>15}")
    
    # 가장 효과적인 패턴
    best_pattern = max(results.items(), key=lambda x: sum(x[1].values()))
    print("\n" + "="*70)
    print(f"🏆 Best Pattern: {best_pattern[0]}")
    print(f"   Total gadgets: {sum(best_pattern[1].values())}")
    print(f"   Registers: {list(best_pattern[1].keys())}")
    print("="*70)

if __name__ == '__main__':
    main()
