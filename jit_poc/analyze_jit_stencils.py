import re

GADGET_PATTERNS = {
    "ret": r"d65f03c0",
    "br x16": r"d61f0200",
    "blr": r"d63f01",
    "ldr/str": r"\bf8|\bf9",
    "mov": r"\baa.*03",
}

def scan_jit_stencils(filename):
    results = []
    current_func = None
    with open(filename) as f:
        for line in f:
            # emit__FOO 함수 시작 감지
            if match := re.match(r"void\s+(emit__[A-Z0-9_]+)", line):
                current_func = match.group(1)
            # 주석 내 gadget 후보 바이트 시퀀스 탐색
            if "//" in line:
                for gadget_name, pattern in GADGET_PATTERNS.items():
                    if re.search(pattern, line.lower()):
                        results.append((current_func, gadget_name, line.strip()))
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze_jit_stencils.py jit_stencils.h")
        sys.exit(1)

    file = sys.argv[1]
    matches = scan_jit_stencils(file)
    print(f"[+] Found {len(matches)} gadget-related patterns in emit functions.\n")
    for func, gadget, line in matches:
        print(f"[{func or 'UNKNOWN':<40}] {gadget:<10} -> {line}")
