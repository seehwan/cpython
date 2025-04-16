import json
from pathlib import Path
from capstone import *
from collections import defaultdict

# 설정
LOG_DIR = Path("./jit_random_logs")  # JSONL 로그 경로
ARCH = CS_ARCH_ARM64
MODE = CS_MODE_ARM
TARGET_REGS = {"x16", "x8", "x0"}
GADGET_TYPES = ["ldr_x16", "br_x16", "ret"]  # 분석할 gadget 유형
OUTPUT_JSON = "register_control_gadgets.json"

# 디스어셈블러 초기화
md = Cs(ARCH, MODE)
md.detail = True

# 결과 저장
results = defaultdict(list)

# 분석 루프
for log_file in LOG_DIR.glob("*.jsonl"):
    with log_file.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                run_id = entry.get("run_id")
                jit_base = int(entry.get("jit_addr", "0"), 16)
                magic = entry.get("magic")
                gadgets = entry.get("gadgets", {})

                for gtype in GADGET_TYPES:
                    for addr_str in gadgets.get(gtype, []):
                        addr = int(addr_str, 16)
                        offset = addr - jit_base
                        # 4-byte 패턴만 분석 (실제 코드는 별도 memory dump 필요)
                        code = (addr & 0xFFFFFFFF).to_bytes(4, 'little')
                        try:
                            for insn in md.disasm(code, addr):
                                # 결과 필터링: destination이 x16, x8, x0인지
                                if insn.operands and insn.operands[0].type == CS_OP_REG:
                                    reg_name = insn.reg_name(insn.operands[0].reg)
                                    if reg_name in TARGET_REGS:
                                        results[reg_name].append({
                                            "run_id": run_id,
                                            "magic": magic,
                                            "type": gtype,
                                            "offset": offset,
                                            "address": addr_str,
                                            "mnemonic": insn.mnemonic,
                                            "op_str": insn.op_str
                                        })
                        except CsError:
                            continue
            except Exception:
                continue

# 출력
import json
with open(OUTPUT_JSON, "w") as f:
    json.dump(results, f, indent=2)

print(f"[+] Analysis complete. Saved to {OUTPUT_JSON}")
