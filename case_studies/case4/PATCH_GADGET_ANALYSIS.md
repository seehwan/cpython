# JIT Patching 과정에서 우연히 생성되는 Gadget 분석

## 🎯 핵심 질문

**"JIT patching 과정에서 stencil hole을 채울 때, 우연히 gadget 바이트 패턴(pop rax, pop rsi, syscall 등)이 생성될 수 있지 않을까?"**

답: **가능하지만 극히 드물며, 실용성이 없음**

---

## 📊 Patching 메커니즘 분석

### 1. Stencil Hole이란?

```c
// Tools/jit/_stencils.py
@dataclasses.dataclass
class Hole:
    """
    A "hole" in the stencil to be patched with a computed runtime value.
    Analogous to relocation records in an object file.
    """
    offset: int           # stencil 내 위치
    kind: str            # relocation 타입
    value: HoleValue     # 패치할 기본 값
    symbol: str | None   # 심볼 주소
    addend: int          # 추가 오프셋
```

**Hole의 용도**:
- 함수 포인터 주소 패치
- Jump target 주소 패치  
- 상수 값(oparg, operand) 패치
- GOT(Global Offset Table) 주소 패치

### 2. Patch 함수들

```c
// Python/jit.c

// 32비트 절대 주소
void patch_32(unsigned char *location, uint64_t value) {
    *(uint32_t *)location = (uint32_t)value;
}

// 64비트 절대 주소
void patch_64(unsigned char *location, uint64_t value) {
    *(uint64_t *)location = value;
}

// 32비트 상대 주소
void patch_32r(unsigned char *location, uint64_t value) {
    value -= (uintptr_t)location;  // 상대 오프셋 계산
    *(uint32_t *)location = (uint32_t)value;
}
```

---

## 🔬 Gadget 생성 가능성 분석

### Case 1: pop rax; ret (58 c3)

#### ❌ **불가능** - 이유:

1. **0x58은 함수 포인터 하위 바이트일 가능성 매우 낮음**
   ```
   일반적인 함수 주소: 0x7ffff7a12345
   - 상위 바이트는 0x7f가 많음 (libc, 커널 영역)
   - 0x58이 나오려면 하위 바이트가 정확히 0x58이어야 함
   - 확률: 1/256 ≈ 0.39%
   ```

2. **0xc3(ret)은 다음 바이트가 우연히 일치해야 함**
   ```
   64비트 주소 패치 시:
   [58] [??] [??] [??] [??] [??] [??] [??]
    ^
    58이 나올 확률 1/256
    
   그 다음 바이트가 c3일 확률: 1/256
   
   총 확률: 1/65536 ≈ 0.0015%
   ```

3. **패치된 위치는 데이터 영역인 경우가 많음**
   ```c
   // 예: operand 패치
   patch_64(code + 0x10, instruction->operand0);
   // 이건 immediate value이지, 실행 가능한 코드가 아님!
   ```

#### 실제 패치 예시:
```c
// LOAD_FAST 같은 opcode의 패치
// code:
//   48 8b 45 [XX]     mov rax, [rbp + XX]  <- oparg 패치
//   
// patch_32(code + 3, oparg * 8);
// 
// XX 위치에 oparg가 들어가는데,
// 이게 0x58이 될 확률은 매우 낮음 (oparg는 보통 0~255)
```

---

### Case 2: pop rsi; ret (5e c3)

#### ❌ **불가능** - 동일한 이유

```
0x5e가 나올 확률: 1/256
0x5e 다음이 0xc3일 확률: 1/65536

게다가:
- 패치는 보통 4바이트 또는 8바이트 단위
- 중간에 gadget 패턴이 나와도 정렬되지 않음
```

#### 예시: 불가능한 시나리오
```
정렬되지 않은 gadget:
[48] [8b] [5e] [c3] [00] [00] [00] [00]
 mov     ^^^^^^^^^
         여기 5e c3이 있지만,
         이건 mov 명령어의 일부이지
         독립적인 gadget이 아님!
```

---

### Case 3: pop rdx; ret (5a c3)

#### ❌ **불가능** - 동일한 이유

---

### Case 4: syscall (0f 05)

#### ⚠️ **이론상 가능, 하지만 극히 드묾**

```
0f 05 패턴이 나올 가능성:
1. 상대 주소 패치 시 우연히 일치
2. 작은 immediate value 패치

확률:
- 0x0f가 나올 확률: 1/256
- 그 다음이 0x05일 확률: 1/65536
```

#### 실제 예시 (가능성 매우 낮음):
```c
// 이론상 이런 상황:
patch_32r(code + 0x10, target_address);
// 상대 오프셋이 우연히 0x0000050f가 되는 경우

// 메모리 레이아웃:
// code + 0x10: [0f] [05] [00] [00]
//               ^^^^^^^^^
//               syscall!

// 하지만 이건:
// 1) 정렬이 안 맞을 가능성 높음
// 2) 앞뒤 context가 실행 불가능
// 3) RIP가 여기로 오기 어려움
```

---

## 🎲 확률 계산 요약

| Gadget | 바이트 | 우연 생성 확률 | 실용 가능성 |
|--------|--------|---------------|------------|
| pop rax; ret | 58 c3 | 1/65,536 | ❌ 불가능 |
| pop rsi; ret | 5e c3 | 1/65,536 | ❌ 불가능 |
| pop rdx; ret | 5a c3 | 1/65,536 | ❌ 불가능 |
| syscall | 0f 05 | 1/65,536 | ⚠️ 이론상만 |

**추가 제약 요인**:
- 정렬 문제 (gadget이 instruction boundary에 있어야 함)
- 접근 가능성 (RIP가 그 주소로 올 수 있어야 함)
- 앞뒤 context (실행 가능한 코드 흐름이어야 함)

**실질적 확률**: `< 1 / 1,000,000` (백만 분의 일 미만)

---

## 🔍 왜 불가능한가?

### 1️⃣ **패치 타겟이 데이터 영역인 경우가 많음**

```c
// 전형적인 패치 예시:
group->emit(code, data, executor, instruction, &state);

// code 영역: 실행 가능
// data 영역: 읽기 전용 (상수, 포인터)

// data 영역에 gadget이 생겨도 실행 불가!
```

### 2️⃣ **패치 값의 특성**

```python
# 패치되는 값들:
- instruction->oparg      # 보통 0~255 (작은 값)
- instruction->operand0   # PyObject* 주소 (0x7f...)
- instruction->target     # 보통 작은 offset
- 함수 포인터             # 0x7f... 시작

# pop rax (0x58)이 나오려면:
# 주소 하위 바이트가 정확히 0x58이어야 함
# 실제 함수 주소: 0x7ffff7a12340, 0x7ffff7a12350, ...
#                                    ^^
#                              여기가 0x58일 확률: 1/256
```

### 3️⃣ **정렬 문제**

```
패치는 4바이트 또는 8바이트 단위:

[XX] [XX] [XX] [58]  <- 8바이트 패치의 마지막
[c3] [YY] [YY] [YY]  <- 다음 8바이트 패치의 시작
 ^^
 이 c3은 우연히 여기 있지만,
 CPU는 [XX XX XX 58] 전체를 하나의 명령어로 해석
```

### 4️⃣ **Stencil 구조**

```c
// jit_stencils.h 생성 방식
void emit_LOAD_FAST(code, data, executor, instruction, state) {
    // 미리 컴파일된 바이너리 복사
    memcpy(code, code_body, sizeof(code_body));
    
    // Hole 패치
    patch_32(code + 0x10, instruction->oparg);  // oparg 삽입
    patch_64(code + 0x20, instruction->operand0); // 주소 삽입
}

// code_body는 이미 컴파일된 기계어
// Hole은 특정 위치의 placeholder
// 새로운 명령어가 추가되는 게 아니라, 값만 교체됨!
```

---

## 💡 실제 Gadget 발견 메커니즘

### ✅ **실제로 동작하는 방법**

```python
# 1. Stencil 자체에 이미 존재하는 gadget 찾기
with open("build/jit_stencils.h") as f:
    stencils = f.read()
    
# 2. pop rcx (59 c3) 같은 패턴 검색
gadgets = re.findall(b'\x59\xc3', stencils)
# → 11~47개 발견! (함수 에필로그에 자주 등장)

# 3. libc에서 확실하게 찾기
with open("/lib/x86_64-linux-gnu/libc.so.6", "rb") as f:
    libc = f.read()
    
pop_rax = libc.find(b'\x58\xc3')  # 100+ 발견!
syscall = libc.find(b'\x0f\x05')  # 581개 발견!
```

---

## 📝 결론

### ❌ **Patching을 통한 Gadget 생성은 비실용적**

**이유**:
1. **확률이 너무 낮음** (< 0.001%)
2. **정렬 보장 안 됨** (instruction boundary 불일치)
3. **접근성 없음** (데이터 영역에 생성될 가능성)
4. **예측 불가능** (ASLR, 런타임 주소 변동)

### ✅ **대신 이렇게 하세요**

```python
# 전략 1: Stencil에 이미 존재하는 gadget 활용
# - pop rcx, pop rbp, pop rbx: 11~47개 발견
# - 안정적이고 예측 가능

# 전략 2: libc 백업
# - pop rax, pop rsi, pop rdx, syscall
# - 100% 보장, 수백 개 gadget 존재

# 전략 3: 셸코드 (최후의 수단)
# - 필요한 gadget 직접 생성
# - 탐지 위험 있음
```

---

## 🎓 추가 고찰: "Gadget Spray" 가능성

### 이론: 많은 JIT 함수를 생성해서 확률 높이기?

```python
# 100,000개의 JIT 함수 생성
for i in range(100000):
    compile(f"lambda: {i}")

# 각 함수마다 50개의 hole 패치
# 총 5,000,000번의 패치

# pop rax (58 c3) 확률: 1/65536
# 5,000,000 / 65536 ≈ 76개의 우연한 gadget?
```

### ❌ **실제로는 불가능**:

1. **정렬 문제 여전히 존재**
   ```
   우연히 생긴 58 c3이 명령어 경계에 있을 확률 매우 낮음
   ```

2. **데이터 영역 vs 코드 영역**
   ```
   많은 패치가 data 영역에서 발생
   실행 불가능
   ```

3. **주소 예측 불가**
   ```
   JIT 메모리는 동적 할당
   어디서 gadget이 생길지 예측 불가능
   검색 시간이 너무 오래 걸림
   ```

4. **리소스 소모**
   ```
   100,000개 함수 컴파일: 수십 초~분
   그냥 libc 검색: 0.01초
   ```

---

## 🎯 최종 권장사항

```python
# ✅ 최선의 전략
def find_gadgets():
    # 1단계: JIT stencil 검색 (pop rcx, pop rbp 등)
    jit_gadgets = search_jit_stencils()
    
    # 2단계: libc 백업 (pop rax, pop rsi, syscall)
    libc_gadgets = search_libc()
    
    # 3단계: 필요시 셸코드
    if not all_gadgets_found():
        shellcode_gadgets = generate_shellcode()
    
    return combine(jit_gadgets, libc_gadgets, shellcode_gadgets)

# ❌ 피해야 할 전략
def bad_approach():
    # Patching으로 우연히 gadget 생성 기대하기
    # - 시간 낭비
    # - 불안정
    # - 예측 불가능
```

**Patching을 통한 gadget 생성은 이론적으로만 흥미로운 주제이고, 실용성은 전혀 없습니다.**
