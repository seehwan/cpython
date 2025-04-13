import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# Capstone disassembler
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def parse_stencil_code_blocks(filepath):
    with open(filepath, 'r') as f:
        src = f.read()

    blocks = re.findall(
        r"void\s+(emit__\w+).*?const\s+unsigned char code_body\[\d+\] = \{(.*?)\};",
        src,
        re.DOTALL,
    )

    result = {}
    for func_name, raw in blocks:
        byte_matches = re.findall(r"0x[0-9a-fA-F]{2}", raw)
        
        if not byte_matches:
            continue  # ✅ 비어있는 code_body는 무시
        bytecode = bytes(int(b, 16) for b in byte_matches)  # ✅ 여기를 꼭 bytes(...) 로!
        result[func_name] = bytecode

    return result

def disassemble_code(bytecode):
    return list(md.disasm(bytecode, 0x0))

def analyze_gadget_chains(stencil_map, disasm_map):
    for name_a, instrs_a in disasm_map.items():
        if not instrs_a:
            continue
        tail = instrs_a[-1]
        if tail.mnemonic in {"ldr", "mov", "str", "add", "eor"}:
            for name_b, instrs_b in disasm_map.items():
                if instrs_b and instrs_b[0].mnemonic in {"br", "ret", "blr"}:
                    print(f"[ROP] {name_a} ➜ {name_b}  --  {tail.mnemonic:<5} ➜ {instrs_b[0].mnemonic}")

def preview_stencil_disassembly(disasm_map, max_preview=3):
    print("\n[+] Preview of disassembled stencils:\n")
    for name, instrs in sorted(disasm_map.items()):
        if not instrs:
            continue
        print(f"{name}:")
        for i in instrs[:max_preview]:
            print(f"  {i.address:04x}: {i.mnemonic:<6} {i.op_str}")
        print()

def main():
    path = "../build/jit_stencils.h"  # adjust if needed
    stencils = parse_stencil_code_blocks(path)
    print(f"[+] Parsed {len(stencils)} stencil code blocks (with non-empty code_body)")

    disasm_map = {
        name: disassemble_code(code) for name, code in stencils.items()
    }

    analyze_gadget_chains(stencils, disasm_map)
    preview_stencil_disassembly(disasm_map)  # ← 이 줄은 이제 OK

if __name__ == "__main__":
    main()
