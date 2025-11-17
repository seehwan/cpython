#!/usr/bin/env python3.12
"""
Calculate patch function statistics based on Scenario A uop usage

Combines:
1. Actual uops used in Scenario A (from extract_scenario_uops.py)
2. Patch function usage per uop (from jit_stencils.h)

Result: Estimated patch function distribution for Scenario A workload
"""

import pickle
import re
from collections import Counter, defaultdict

print("=== Scenario A Patch Function Analysis ===\n")

# Load Scenario A uop analysis results
with open('scenario_a_uop_analysis.pkl', 'rb') as f:
    uop_data = pickle.load(f)

estimated_uops = uop_data['estimated_uops']
print(f"Loaded Scenario A uop usage: {len(estimated_uops)} unique uops\n")

# Parse jit_stencils.h to get patch function usage per uop
with open('../build/jit_stencils.h', 'r') as f:
    content = f.read()

# Extract emit functions and their patch calls
function_pattern = r'void\s+emit_([^\(]+)\s*\([^{]+\{(.*?)(?=void\s+emit_|$)'
functions = re.findall(function_pattern, content, re.DOTALL)

print(f"Analyzing {len(functions)} stencils from jit_stencils.h...")

# Build uop -> patch function mapping
uop_to_patches = {}

for opcode, body in functions:
    patch_64 = len(re.findall(r'patch_64\(', body))
    patch_x86 = len(re.findall(r'patch_x86_64_32rx\(', body))
    patch_32r = len(re.findall(r'patch_32r\(', body))
    
    uop_to_patches[opcode] = {
        'patch_64': patch_64,
        'patch_x86_64_32rx': patch_x86,
        'patch_32r': patch_32r,
        'total': patch_64 + patch_x86 + patch_32r
    }

print(f"✓ Mapped patch usage for {len(uop_to_patches)} stencils\n")

# Calculate weighted patch function usage for Scenario A
scenario_a_patches = Counter()
uop_contribution = defaultdict(lambda: defaultdict(int))

for uop, count in estimated_uops.items():
    if uop in uop_to_patches:
        patches = uop_to_patches[uop]
        
        # Weight by actual usage count
        scenario_a_patches['patch_64'] += patches['patch_64'] * count
        scenario_a_patches['patch_x86_64_32rx'] += patches['patch_x86_64_32rx'] * count
        scenario_a_patches['patch_32r'] += patches['patch_32r'] * count
        
        # Record contribution details
        uop_contribution[uop]['patch_64'] = patches['patch_64'] * count
        uop_contribution[uop]['patch_x86_64_32rx'] = patches['patch_x86_64_32rx'] * count
        uop_contribution[uop]['patch_32r'] = patches['patch_32r'] * count
        uop_contribution[uop]['total'] = patches['total'] * count
        uop_contribution[uop]['uop_count'] = count

print("="*80)
print("SCENARIO A PATCH FUNCTION STATISTICS")
print("="*80)
print()

total_patches = sum(scenario_a_patches.values())

print(f"{'Patch Function':25} | {'Est. Calls':15} | {'Percentage':12}")
print("-" * 65)

for patch_func in ['patch_64', 'patch_x86_64_32rx', 'patch_32r']:
    count = scenario_a_patches[patch_func]
    percentage = 100 * count / total_patches if total_patches > 0 else 0
    print(f"{patch_func:25} | {count:15,} | {percentage:11.2f}%")

print(f"{'─'*25}─┼─{'─'*15}─┼─{'─'*12}")
print(f"{'Total':25} | {total_patches:15,} | {'100.00%':>12}")

print(f"\n\n{'='*80}")
print("TOP 10 UOPS BY PATCH FUNCTION CONTRIBUTION")
print("="*80)
print()

# Sort uops by total patch contribution
sorted_uops = sorted(uop_contribution.items(), 
                     key=lambda x: x[1]['total'], 
                     reverse=True)

print(f"{'uop':30} | {'uop Count':10} | p64 | px86 | p32r | {'Total Patches':15}")
print("-" * 100)

for uop, stats in sorted_uops[:20]:
    print(f"{uop:30} | {stats['uop_count']:10,} | "
          f"{stats['patch_64']:6,} | {stats['patch_x86_64_32rx']:6,} | "
          f"{stats['patch_32r']:6,} | {stats['total']:15,}")

if len(sorted_uops) > 20:
    print(f"\n... ({len(sorted_uops) - 20} more uops)")

# Save detailed results
results = {
    'scenario_a_patches': dict(scenario_a_patches),
    'total_estimated_patches': total_patches,
    'uop_contribution': {k: dict(v) for k, v in uop_contribution.items()},
    'estimated_uops': estimated_uops,
    'uop_to_patches_map': uop_to_patches,
}

output_file = 'scenario_a_patch_analysis.pkl'
with open(output_file, 'wb') as f:
    pickle.dump(results, f)

print(f"\n✓ Detailed results saved to {output_file}")

# Summary for README
print(f"\n\n{'='*80}")
print("SUMMARY FOR DOCUMENTATION")
print("="*80)
print()
print(f"Based on {uop_data['function_count']} functions × {uop_data['warmup_iterations']} iterations:")
print(f"  - Total bytecode instructions: {uop_data['total_bytecode_instructions']:,}")
print(f"  - Unique Tier-2 uops: {uop_data['unique_uops']}")
print(f"  - Estimated total uop executions: {uop_data['total_estimated_uops']:,}")
print()
print(f"Estimated patch function calls during Scenario A execution:")
patch_64_pct = 100 * scenario_a_patches['patch_64'] / total_patches
patch_x86_pct = 100 * scenario_a_patches['patch_x86_64_32rx'] / total_patches
patch_32r_pct = 100 * scenario_a_patches['patch_32r'] / total_patches

print(f"  - patch_64:          {scenario_a_patches['patch_64']:,} calls ({patch_64_pct:.1f}%)")
print(f"  - patch_x86_64_32rx: {scenario_a_patches['patch_x86_64_32rx']:,} calls ({patch_x86_pct:.1f}%)")
print(f"  - patch_32r:         {scenario_a_patches['patch_32r']:,} calls ({patch_32r_pct:.1f}%)")
print(f"  - Total:             {total_patches:,} calls")
print()

# Top contributors
top_3_uops = sorted_uops[:3]
print(f"Top 3 uops contributing to patch calls:")
for i, (uop, stats) in enumerate(top_3_uops, 1):
    contribution_pct = 100 * stats['total'] / total_patches
    print(f"  {i}. {uop}: {stats['total']:,} patches ({contribution_pct:.1f}%) "
          f"from {stats['uop_count']:,} executions")

print(f"\n{'='*80}\n")
