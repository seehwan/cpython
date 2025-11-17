#!/usr/bin/env python3
"""
Stencil Optimizer Module
=========================

Analyzes and prioritizes Python bytecode operations based on their
gadget-generation potential in JIT stencils.

Strategy:
---------
1. Parse stencil_gadgets.json to identify high-gadget-density stencils
2. Map stencils to Python bytecode operations
3. Provide code generation templates that trigger high-yield stencils
4. Score functions based on expected gadget yield

Key Insights:
-------------
- COMPARE_OP stencils: High pop/ret density
- CALL operations: Many register saves/restores
- BINARY_OP: Diverse instruction sequences
- FOR_ITER: Loop overhead with stack operations
- STORE/LOAD operations: Memory access patterns
"""

import json
import os
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


class StencilOptimizer:
    """Optimizes Python code generation for maximum gadget yield"""
    
    # Bytecode -> Expected gadget density (gadgets per 100 bytes)
    OPCODE_GADGET_DENSITY = {
        # High-yield operations (>5 gadgets/100 bytes)
        'COMPARE_OP': 8.5,
        'COMPARE_OP_INT': 9.2,
        'CALL': 7.8,
        'CALL_PY_EXACT_ARGS': 8.1,
        'STORE_SUBSCR_DICT': 6.5,
        'BINARY_OP_ADD_INT': 6.2,
        'BINARY_OP_MULTIPLY_INT': 6.0,
        'FOR_ITER': 5.8,
        
        # Medium-yield operations (3-5 gadgets/100 bytes)
        'LOAD_ATTR': 4.5,
        'STORE_ATTR': 4.3,
        'BINARY_SUBSCR': 4.0,
        'LOAD_FAST': 3.8,
        'STORE_FAST': 3.7,
        'POP_TOP': 3.5,
        
        # Low-yield operations (<3 gadgets/100 bytes)
        'LOAD_CONST': 2.5,
        'RETURN_VALUE': 2.0,
        'NOP': 1.0,
    }
    
    # Common gadget patterns in stencils (byte sequences)
    GADGET_SIGNATURES = {
        'pop_rdi': b'\x5f\xc3',      # pop rdi; ret
        'pop_rsi': b'\x5e\xc3',      # pop rsi; ret
        'pop_rdx': b'\x5a\xc3',      # pop rdx; ret
        'pop_rax': b'\x58\xc3',      # pop rax; ret
        'pop_rbx': b'\x5b\xc3',      # pop rbx; ret
        'pop_rcx': b'\x59\xc3',      # pop rcx; ret
        'ret': b'\xc3',              # ret
        'xor_edx_edx': b'\x31\xd2',  # xor edx, edx
    }
    
    def __init__(self, stencil_json_path: Optional[str] = None):
        """
        Initialize optimizer
        
        Args:
            stencil_json_path: Path to stencil_gadgets.json (optional)
        """
        self.stencil_data = {}
        self.opcode_scores = {}
        
        if stencil_json_path and os.path.exists(stencil_json_path):
            self._load_stencil_data(stencil_json_path)
            self._calculate_opcode_scores()
    
    def _load_stencil_data(self, path: str):
        """Load stencil analysis data from JSON"""
        with open(path, 'r') as f:
            self.stencil_data = json.load(f)
    
    def _calculate_opcode_scores(self):
        """Calculate gadget scores for each stencil based on analysis"""
        if not self.stencil_data:
            return
        
        for stencil_name, data in self.stencil_data.items():
            # Count gadget types
            gadget_count = sum(
                len(offsets) for gadgets in data.get('gadgets', {}).values()
                for offsets in gadgets.values()
            )
            
            # Estimate code size (approximate)
            code_size = data.get('code_size', 100)
            
            # Calculate density (gadgets per 100 bytes)
            density = (gadget_count / code_size * 100) if code_size > 0 else 0
            
            self.opcode_scores[stencil_name] = {
                'gadget_count': gadget_count,
                'code_size': code_size,
                'density': density,
            }
    
    def get_high_yield_operations(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """
        Get top N operations by gadget density
        
        Args:
            top_n: Number of operations to return
        
        Returns:
            List of (operation_name, density) tuples
        """
        scored = sorted(
            self.OPCODE_GADGET_DENSITY.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return scored[:top_n]
    
    def generate_optimized_function(self, seed: int, iterations: int = 5000) -> str:
        """
        Generate Python code optimized for gadget yield
        
        Strategy:
        - Maximize COMPARE_OP usage (highest density)
        - Include CALL operations (register pressure)
        - Use dict operations (STORE_SUBSCR_DICT)
        - Add attribute access (LOAD/STORE_ATTR)
        - Include arithmetic ops (BINARY_OP variants)
        
        Args:
            seed: Function variation seed
            iterations: Loop iteration count
        
        Returns:
            Python code string
        """
        from .config import MAGIC_VALUES
        
        magic_value = MAGIC_VALUES[seed % len(MAGIC_VALUES)]
        
        code = f"""
def optimized_jit_func_{seed}(x):
    '''
    High-gadget-density function:
    - Heavy COMPARE_OP usage (8.5 gadgets/100 bytes)
    - Nested calls (7.8 gadgets/100 bytes)
    - Dict operations (6.5 gadgets/100 bytes)
    - Arithmetic ops (6+ gadgets/100 bytes)
    '''
    
    # Nested helper: triggers CALL stencils
    def helper(a, b, c):
        # Multiple comparisons: COMPARE_OP_INT stencils
        if a > b:
            result = a ^ c
        elif a < b:
            result = b ^ c
        else:
            result = a + b + c
        
        # More comparisons
        if result > {magic_value}:
            result -= 1
        if result < 0:
            result += 1
        
        return result & 0xFFFFFFFF
    
    # Dict for STORE_SUBSCR_DICT stencils
    data = {{}}
    
    # Object for LOAD/STORE_ATTR stencils
    class Container:
        val1 = 0
        val2 = 0
        val3 = 0
    
    obj = Container()
    acc = x
    
    # Main loop: high iteration for JIT compilation
    for i in range({iterations}):
        # COMPARE_OP: Multiple conditions
        if i % 10 == 0:
            acc = helper(acc, i, {magic_value})
        
        if i % 20 == 0:
            acc = helper(acc ^ {magic_value}, i & 0xFF, acc >> 3)
        
        # BINARY_OP: Arithmetic operations
        acc = (acc + {magic_value}) & 0xFFFFFFFF
        acc = (acc * 3) & 0xFFFFFFFF
        acc ^= i << (i % 8)
        acc = ((acc << 5) | (acc >> 27)) & 0xFFFFFFFF
        
        # STORE_SUBSCR_DICT: Dictionary operations
        if i % 50 == 0:
            data[i] = acc & 0xFF
            acc ^= data.get(i - 50, 0)
        
        # LOAD/STORE_ATTR: Object operations
        if i % 100 == 0:
            obj.val1 = acc & 0xFFFF
            obj.val2 = (acc >> 16) & 0xFFFF
            acc += obj.val1 ^ obj.val2
        
        # More COMPARE_OP: Range checks
        if acc > 0x7FFFFFFF:
            acc &= 0x7FFFFFFF
        
        if acc < {magic_value}:
            acc += i
        elif acc > ({magic_value} << 10):
            acc -= i
        
        # COMPARE_OP: Multiple elif chain (generates many stencils)
        mod = i % 7
        if mod == 0:
            acc ^= 0x12345678
        elif mod == 1:
            acc += 0x87654321
        elif mod == 2:
            acc *= 5
        elif mod == 3:
            acc >>= 3
        elif mod == 4:
            acc <<= 2
        elif mod == 5:
            acc |= {magic_value}
        else:
            acc &= 0xFFFFFFFF
        
        # Final comparison cascade
        if acc > {magic_value} * 2:
            if acc > {magic_value} * 4:
                acc -= {magic_value}
            else:
                acc += i
        
    return acc
"""
        return code
    
    def estimate_gadget_yield(self, code: str) -> Dict[str, int]:
        """
        Estimate expected gadget yield from code
        
        Analyzes code for operation frequency and estimates total gadgets
        
        Args:
            code: Python code string
        
        Returns:
            Dictionary with yield estimates
        """
        # Count operation occurrences (simple heuristic)
        estimates = {
            'compare_ops': code.count('if ') + code.count('elif '),
            'calls': code.count('helper('),
            'dict_ops': code.count('data[') + code.count('.get('),
            'attr_ops': code.count('obj.'),
            'arithmetic_ops': code.count('^=') + code.count('+=') + code.count('*='),
        }
        
        # Estimate gadgets using density scores
        expected_gadgets = (
            estimates['compare_ops'] * 8.5 +
            estimates['calls'] * 7.8 +
            estimates['dict_ops'] * 6.5 +
            estimates['attr_ops'] * 4.5 +
            estimates['arithmetic_ops'] * 6.0
        ) / 10  # Normalize
        
        return {
            'operation_counts': estimates,
            'expected_gadgets': int(expected_gadgets),
        }
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get list of optimization recommendations"""
        return [
            "1. Maximize COMPARE_OP usage: Use if/elif chains extensively",
            "2. Add nested function calls: Triggers register save/restore",
            "3. Include dictionary operations: STORE_SUBSCR_DICT high yield",
            "4. Use object attribute access: LOAD/STORE_ATTR medium yield",
            "5. Vary arithmetic operations: Different BINARY_OP stencils",
            "6. Loop unrolling: Repeat patterns within loops",
            "7. Multiple comparison chains: Cascaded if/elif statements",
            "8. Mix data types: Integer, dict, object operations together",
        ]
    
    def print_stencil_ranking(self, top_n: int = 20):
        """Print ranking of stencils by gadget density"""
        if not self.opcode_scores:
            print("[!] No stencil data loaded. Using default heuristics.")
            print("\nTop Operations (by heuristic density):")
            for i, (op, density) in enumerate(self.get_high_yield_operations(top_n), 1):
                print(f"  {i:2d}. {op:<30} {density:.1f} gadgets/100 bytes")
            return
        
        print("\nStencil Ranking (by actual analysis):")
        ranked = sorted(
            self.opcode_scores.items(),
            key=lambda x: x[1]['density'],
            reverse=True
        )
        
        for i, (name, score) in enumerate(ranked[:top_n], 1):
            print(f"  {i:2d}. {name:<40} "
                  f"{score['gadget_count']:3d} gadgets, "
                  f"{score['code_size']:4d} bytes, "
                  f"{score['density']:.2f} density")


def create_optimized_function_set(count: int, optimizer: StencilOptimizer) -> List[str]:
    """
    Create a set of optimized functions with varying patterns
    
    Args:
        count: Number of functions to create
        optimizer: StencilOptimizer instance
    
    Returns:
        List of Python code strings
    """
    functions = []
    
    for i in range(count):
        # Vary iterations to create different JIT code sizes
        iterations = 5000 + (i % 10) * 500
        code = optimizer.generate_optimized_function(i, iterations)
        functions.append(code)
    
    return functions


if __name__ == '__main__':
    print(__doc__)
    
    # Try to load stencil data
    stencil_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'case_studies',
        'case4',
        'stencil_gadgets.json'
    )
    
    optimizer = StencilOptimizer(stencil_path if os.path.exists(stencil_path) else None)
    
    print("\n" + "="*70)
    print("STENCIL OPTIMIZATION RECOMMENDATIONS")
    print("="*70)
    
    # Print recommendations
    for rec in optimizer.get_optimization_recommendations():
        print(f"  {rec}")
    
    # Print stencil ranking
    print("\n" + "="*70)
    optimizer.print_stencil_ranking()
    
    # Show sample optimized function
    print("\n" + "="*70)
    print("SAMPLE OPTIMIZED FUNCTION")
    print("="*70)
    sample_code = optimizer.generate_optimized_function(0, 5000)
    print(sample_code)
    
    # Estimate yield
    yield_est = optimizer.estimate_gadget_yield(sample_code)
    print("\n" + "="*70)
    print("ESTIMATED GADGET YIELD")
    print("="*70)
    print(f"  Expected gadgets: ~{yield_est['expected_gadgets']}")
    print(f"  Operation counts: {yield_est['operation_counts']}")
