import jitaccess
import dis

def get_value(index):
    if index < 10000:
        return index
    else:
        return -1


def test_function():
    result = 0
    result2 = 0
    for i in range(20):
        value = get_value(i)
        result = value + result
        result2 = result2 - value
        print(f"i: {i} res: {result} res2: {result2}")
    return result


raw_bytecode = test_function.__code__.co_code
print("\nBytecode with Disassembled Instructions:")
print("Offset | Raw Bytecode | Instruction")
instructions = dis.get_instructions(test_function)
for instr in instructions:
    raw = raw_bytecode[instr.offset:instr.offset+2]  # Get bytecode slice
    raw_hex = " ".join(f"{byte:02x}" for byte in raw)
    print(f"{instr.offset:6} | {raw_hex:<12} | {instr.opname} {instr.argrepr}")

test_function()

jitaccess.attack_alias(test_function, 116)

test_function()
