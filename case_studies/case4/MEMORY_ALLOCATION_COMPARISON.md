# JIT 메모리 할당 전략 비교

## 🔍 핵심 차이점

### test_runtime_jit_scan.py
```python
# 1. Normal Allocation (연속 할당)
def _generate_normal(self, count):
    for i in range(count):
        func = self._create_jit_function(i)
        self.functions.append(func)
        # → 모든 함수가 같은 프로세스 내에서 순차적으로 생성
        # → JIT 메모리도 비교적 가까운 주소에 할당될 가능성 높음

# 2. Spread Allocation (분산 할당)
def _generate_spread(self, count):
    num_modules = 10
    for mod_idx in range(num_modules):
        module = types.ModuleType(f"jit_spread_module_{mod_idx}")
        
        for i in range(funcs_per_module):
            func = self._create_jit_function(global_idx)
            setattr(module, f"func_{i}", func)
            self.functions.append(func)
        
        # 핵심: 메모리 할당 경계 강제
        dummy = bytearray(1024 * 1024)  # 1MB 더미!
        # → 다음 모듈이 다른 메모리 영역에 할당되도록 강제
```

### gadget_chain_parallel.py
```python
# Multiprocessing Pool 사용
num_workers = min(len(MAGIC_VALUES), os.cpu_count() or 4)
with Pool(processes=num_workers) as pool:
    results = pool.map(worker_task, tasks)

# 각 worker_task는 독립된 프로세스에서 실행:
def worker_task(args):
    jit_func = generate_jit_func_named(seed, magic_value)
    for i in range(5000):
        jit_func(i)
    jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
    # → 각 프로세스가 독립된 메모리 공간 가짐!
    # → 완전히 다른 주소 공간에서 JIT 컴파일
```

## 📊 메모리 분포 예측

### test_runtime_jit_scan.py - Normal
```
단일 프로세스 메모리 공간:
[Python Heap]
  ├─ Function 0  JIT @ 0x7f1234560000
  ├─ Function 1  JIT @ 0x7f1234561000  (가까움)
  ├─ Function 2  JIT @ 0x7f1234562000  (가까움)
  └─ ...
  
→ JIT 메모리 범위: 좁음 (~수 MB)
→ patch_64 주소 중복 가능성: 높음
```

### test_runtime_jit_scan.py - Spread
```
단일 프로세스 메모리 공간:
[Python Heap]
  ├─ Module 0
  │   ├─ Function 0  JIT @ 0x7f1234560000
  │   └─ Function 1  JIT @ 0x7f1234561000
  ├─ [1MB Dummy]      ← 메모리 경계 강제!
  ├─ Module 1
  │   ├─ Function 2  JIT @ 0x7f1235600000  (멀어짐!)
  │   └─ Function 3  JIT @ 0x7f1235601000
  ├─ [1MB Dummy]
  └─ ...

→ JIT 메모리 범위: 중간 (~수십 MB)
→ patch_64 주소 다양성: 증가
```

### gadget_chain_parallel.py - Multiprocessing
```
프로세스 0:
  └─ Function 0  JIT @ 0x7f1234560000

프로세스 1:
  └─ Function 1  JIT @ 0x7f9876540000  (완전히 다른 주소!)

프로세스 2:
  └─ Function 2  JIT @ 0x7fab12340000  (완전히 다른 주소!)

→ JIT 메모리 범위: 매우 넓음 (수 GB 차이)
→ patch_64 주소 다양성: 최대!
```

## 🎯 핵심 차이점 요약

| 항목 | test_runtime_jit_scan.py<br>Normal | test_runtime_jit_scan.py<br>Spread | gadget_chain_parallel.py<br>Multiprocessing |
|-----|-------------------------------------|-------------------------------------|----------------------------------------------|
| **프로세스 개수** | 1 | 1 | 7개 (병렬) |
| **메모리 공간** | 공유 | 공유 | 완전히 독립 |
| **JIT 주소 범위** | 좁음 (~MB) | 중간 (~10MB) | 매우 넓음 (~GB) |
| **할당 강제 방법** | 없음 | 1MB dummy | 프로세스 분리 |
| **patch_64 다양성** | 낮음 | 중간 | 높음 |
| **Gadget 중복도** | 높을 가능성 | 중간 | 낮을 가능성 |

## 💡 왜 이것이 중요한가?

### PATCH_GADGET_ANALYSIS.md의 가설:
```
"넓은 주소 공간에 JIT 코드를 분산시키면
 patch_64로 패치되는 libc 주소가 다양해진다
 → 더 많은 unintended instruction 생성
 → gadget 종류 2-3배 증가"
```

### 각 방식의 효과:

**1. test_runtime_jit_scan.py - Normal**
- ❌ 주소 분산 없음
- JIT 메모리가 연속적
- patch_64 주소가 비슷한 범위
- Gadget 다양성: 낮음

**2. test_runtime_jit_scan.py - Spread**
- ⚠️ 부분적 주소 분산
- 1MB dummy로 메모리 경계 강제
- 같은 프로세스 내에서 제한적
- patch_64 주소 어느 정도 다양해질 수 있음
- Gadget 다양성: 중간

**3. gadget_chain_parallel.py - Multiprocessing**
- ✅ 완전한 주소 분산!
- 각 프로세스가 독립된 메모리 공간
- patch_64 주소가 완전히 다른 범위
- Gadget 다양성: 최대!

## 🔬 실제 검증 필요

### 예상 결과:

```python
# Normal: 단일 함수에서 7,320개
gadgets_normal = 7320

# Spread: 10개 모듈로 분산
# 예상: 각 모듈마다 약간씩 다른 gadget
# → 총 8,000-10,000개? (1.2-1.4배)
gadgets_spread = 8500  # 예상

# Multiprocessing: 7개 프로세스
# 예상: 각 프로세스마다 완전히 다른 주소
# → 총 15,000-20,000개? (2-3배)
gadgets_multiproc = 18000  # 예상
```

## 🚨 하지만 문제가 있다!

### gadget_chain_parallel.py의 치명적 한계:

```python
# 각 프로세스는 독립된 메모리 공간
with Pool(processes=num_workers) as pool:
    results = pool.map(worker_task, tasks)

# 문제:
# 1. 프로세스 간 메모리 공유 안됨!
# 2. Worker 0에서 발견한 JIT 메모리는 Worker 1에서 접근 불가
# 3. 각 worker가 자기 JIT만 스캔
# 4. ROP chain 실행 시 다른 프로세스의 gadget 주소 사용 불가!
```

### 실제로 무슨 일이 일어나나?

```
Main Process:
  └─ execute_rop_chain() 실행
  └─ gadgets["pop rax"] = 0x7f9876540000  ← Worker 1에서 발견
  
  ⚠️ 문제: 이 주소는 Worker 1 프로세스의 메모리!
  ⚠️ Main Process에서는 이 주소가 유효하지 않음!
  ⚠️ Segmentation Fault 가능성!
```

## ✅ 올바른 접근 방법

### 시나리오 1: 단일 프로세스 공격 (현실적)
```python
# test_runtime_jit_scan.py 방식
# - 단일 프로세스에서 여러 함수 생성
# - 모든 JIT 메모리가 같은 주소 공간
# - Spread allocation으로 주소 분산
# - 발견한 모든 gadget이 유효함!
```

### 시나리오 2: 멀티프로세스 공격 (이론적)
```python
# gadget_chain_parallel.py가 작동하려면:
# 1. 모든 worker를 자식 프로세스로 유지 (fork)
# 2. 자식에서 gadget 발견 후 주소 전달
# 3. 자식 프로세스 중 하나에서 ROP chain 실행
# 4. 그 자식에서만 JIT 주소가 유효

# 하지만 문제:
# - Worker 0의 gadget을 Worker 1에서 사용 불가
# - 결국 단일 worker의 gadget만 사용 가능
# - Multiprocessing의 이점 상실!
```

## 🎯 결론

### gadget_chain_parallel.py는 왜 작동하는가?

실제 코드 확인 필요:
```python
# 가설 1: 부족한 gadget을 libc에서 보충
if missing_gadgets:
    libc_gadgets, libc_base = get_runtime_gadget_addresses()
    # → libc 주소는 모든 프로세스에서 동일 (ASLR은 프로세스 시작 시 결정)
    # → Main process에서도 유효!

# 가설 2: Shellcode로 대체
if key not in found_gadgets_global:
    found_gadgets_global[key] = provide_gadget_shellcode(mnemonic, operand)
    # → Main process에서 새로 할당한 메모리
    # → 당연히 유효!
```

### 진짜 이점은?

**Multiprocessing의 실제 목적**:
- ✅ 병렬로 여러 함수 JIT 컴파일 (시간 절약)
- ✅ 각 worker가 독립적으로 gadget 탐색
- ⚠️ 하지만 최종 사용 gadget은 libc나 shellcode일 가능성 높음!

**test_runtime_jit_scan.py Spread의 진짜 이점**:
- ✅ 같은 프로세스 내에서 주소 분산
- ✅ 모든 발견된 gadget이 유효함
- ✅ JIT gadget만으로 ROP chain 구성 가능!

## 📋 검증 필요 사항

1. **gadget_chain_parallel.py 실행 로그 분석**
   - JIT에서 몇 개 gadget 발견?
   - libc에서 몇 개 보충?
   - 최종 ROP chain은 어떤 주소 사용?

2. **test_runtime_jit_scan.py Spread 효과 측정**
   - Normal vs Spread gadget 개수 차이
   - patch_64 주소 다양성 실제 측정
   - 주소 엔트로피 계산

3. **메모리 맵 확인**
   - /proc/self/maps로 JIT 메모리 분포 확인
   - Normal vs Spread 주소 범위 비교
