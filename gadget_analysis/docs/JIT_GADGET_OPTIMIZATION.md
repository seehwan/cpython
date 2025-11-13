# JIT 가젯 생성 최적화 전략

## 주요 발견사항

### 1. MAGIC_VALUES의 영향: **거의 없음**
```
모든 MAGIC_VALUES (0xC3, 0x5FC3, 0x5EC3, 등)가 거의 동일한 가젯 생성:
- 31~32개의 pop 가젯
- 동일한 레지스터: r15, rbx, rdi, rcx, rbp
```

**결론**: MAGIC_VALUES는 가젯 생성에 **직접적인 영향이 없음**. 
JIT 컴파일러는 상수 값이 아닌 **코드 구조**에 따라 가젯을 생성합니다.

---

## 2. 코드 패턴의 영향: **매우 큼!**

### 📊 가젯 생성 효과 순위

| 순위 | 패턴                        | 가젯 수 | 설명 |
|------|----------------------------|---------|------|
| 🥇 1 | **Combined Pattern**       | **70**  | 여러 기법 조합 |
| 🥈 2 | Multi-arg Function Calls   | 51      | 다중 인자 함수 (rdi, rsi, rdx 사용) |
| 🥉 3 | Recursion                  | 43      | 재귀 호출 (스택 프레임 많음) |
| 4    | Nested Functions + Closures| 42      | 중첩 함수 + 클로저 |
| 5    | Container Operations       | 35      | 리스트/딕셔너리 연산 |
| 6    | Basic Loop (baseline)      | 33      | 기본 루프 |
| 7    | Exception Handling         | 23      | try/except |
| 8    | Unpacking (*args)          | 23      | 언패킹 |
| 9    | Object Attributes          | 6       | 객체 속성 접근 |
| 10   | Generator                  | 0       | JIT 미지원 |

### 🎯 핵심 인사이트

1. **복합 패턴이 최고**: 여러 기법을 조합하면 가젯 수가 **2배 이상** 증가 (33 → 70)

2. **다중 인자 함수 호출 효과적**: 
   - 6개 인자 함수 → rdi, rsi, rdx, rcx, r8, r9 레지스터 사용
   - 가젯 수 55% 증가

3. **재귀와 중첩 함수**:
   - 스택 프레임 조작이 많아 pop 가젯 증가
   - 재귀: 43개 가젯

4. **제너레이터는 JIT 미지원**:
   - yield 사용 시 JIT 컴파일 안 됨
   - 피해야 함

---

## 3. 생성되는 레지스터 분석

### ✅ 자주 생성되는 레지스터
```
pop rcx  : 11-47개  (가장 많음!)
pop rbp  : 5-16개
pop rbx  : 2-11개
pop rdi  : 1-2개
pop r15  : 1개
```

### ❌ 생성되지 않는 레지스터
```
pop rax  : 0개  ← 필요함! (execve syscall number)
pop rsi  : 0개  ← 필요함! (argv)
pop rdx  : 0-1개  ← 필요함! (envp)
pop r8-r14 : 0개
syscall  : 0개  ← 필요함!
```

**중요**: JIT만으로는 **ROP 체인에 필요한 핵심 가젯을 얻을 수 없음**
→ **libc 백업이 필수**

---

## 4. 최적 코드 생성 전략

### 🚀 권장 패턴: Combined Pattern
```python
def generate_optimal_jit_func():
    code = """
def helper(a, b, c, d):  # 다중 인자 함수
    return (a + b * c - d) & 0xFFFFFFFF

def f(x):
    class State:  # 객체 속성
        val = 0
    
    state = State()
    data = {}  # 딕셔너리
    
    def nested(n):  # 중첩 함수
        return (n ^ state.val) & 0xFFFFFFFF
    
    acc = x
    for i in range(5000):
        # 다중 인자 함수 호출
        acc = helper(i, i+1, i+2, i+3)
        
        # 중첩 함수 호출
        acc = nested(acc)
        
        # 객체 속성 접근
        state.val = acc & 0xFF
        
        # 딕셔너리 연산
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
    return code
```

### 🎯 핵심 요소

1. **다중 인자 함수 (4-6개 인자)**
   - 함수 인자 레지스터 사용 증가
   - pop 가젯 생성 증가

2. **중첩 함수 + 클로저**
   - 스택 프레임 복잡도 증가
   - 레지스터 save/restore 증가

3. **딕셔너리 연산**
   - 메모리 접근 패턴 다양화
   - 추가 레지스터 사용

4. **예외 처리 (선택적)**
   - 스택 언와인딩 코드 생성
   - 약간의 가젯 증가

5. **객체 속성 접근**
   - LOAD_ATTR/STORE_ATTR 바이트코드
   - 속성 딕셔너리 접근

### ⚠️ 피해야 할 패턴
```python
# 1. 제너레이터 (JIT 미지원)
def gen():
    yield 1  # ❌

# 2. 너무 단순한 루프
for i in range(n):
    acc += i  # ❌ 가젯 적음

# 3. 순수 계산만
acc = (acc + 1) * 2  # ❌ 메모리 접근 없음
```

---

## 5. 실전 적용 예제

### 현재 코드 개선
```python
# Before (33 gadgets)
def generate_jit_func_named(seed, magic_value):
    code = f"""
def f(x):
    acc = x
    for i in range(3000):
        acc ^= ({magic_value} + i)
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
    return acc
"""

# After (70+ gadgets)
def generate_jit_func_optimized(seed, magic_value):
    code = f"""
def helper(a, b, c, d, e, f):  # 6개 인자
    return (a + b + c - d * e + f) & 0xFFFFFFFF

def f(x):
    class State:
        val1 = 0
        val2 = 0
    
    state = State()
    cache = {{}}
    
    def nested(n, m):  # 중첩 함수
        return (n ^ m ^ state.val1) & 0xFFFFFFFF
    
    acc = x
    for i in range({3000 + seed * 500}):
        # 복잡한 연산
        acc = helper(i, i+1, i+2, i+3, i+4, acc)
        acc = nested(acc, i)
        
        # 메모리 접근
        state.val1 = acc & 0xFF
        state.val2 = (acc >> 8) & 0xFF
        acc += state.val1 + state.val2
        
        # 딕셔너리
        if i % 100 == 0:
            cache[i] = acc
            acc ^= cache.get(i-100, 0)
        
        # 예외 처리
        try:
            acc = acc // (i % 5 + 1)
        except:
            acc ^= i
    
    return acc
"""
```

---

## 6. 결론 및 권장사항

### ✅ 해야 할 것
1. **복합 패턴 사용**: 여러 기법 조합 (70개 가젯)
2. **다중 인자 함수**: 4-6개 인자로 레지스터 사용 극대화
3. **중첩 함수 + 클로저**: 스택 프레임 조작 증가
4. **딕셔너리/객체 연산**: 메모리 접근 패턴 다양화
5. **libc 백업 전략 유지**: JIT만으로는 rax, rsi, rdx, syscall 얻기 어려움

### ❌ 하지 말아야 할 것
1. **제너레이터 사용**: JIT 컴파일 안 됨
2. **단순 계산**: 가젯 생성 최소화
3. **MAGIC_VALUES 조정**: 효과 없음

### 🎯 최종 전략
```
JIT 최적화 (70개 가젯) + libc 백업 (rax, rsi, rdx, syscall)
= 완벽한 ROP 체인 구성
```

**현실적 목표**:
- JIT에서: pop rdi, pop rbx, pop rcx, pop rbp 등 보조 가젯
- libc에서: pop rax, pop rsi, pop rdx, syscall (핵심 가젯)
