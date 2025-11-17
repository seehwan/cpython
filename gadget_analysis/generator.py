#!/usr/bin/env python3
"""
JIT Function Generator Module
==============================

Generates JIT-compiled Python functions for gadget analysis.

Supports two allocation strategies:
- Normal: Consecutive memory allocation
- Spread: Wide memory distribution across multiple modules

Generation modes:
- Standard: Basic function template
- Optimized: High-gadget-density code using StencilOptimizer
"""

import time
import types
from .config import (
    MAGIC_VALUES,
    JIT_WARMUP_ITERATIONS,
    JIT_MODULE_COUNT,
    SPREAD_DUMMY_SIZE,
    FUNCTION_BASE_ITERATIONS,
    FUNCTION_ITER_INCREMENT,
    PROGRESS_REPORT_INTERVAL,
)
from .stencil_optimizer import StencilOptimizer


class JITFunctionGenerator:
    """Generates JIT-compiled Python functions"""
    
    def __init__(self, spread_allocation=False, use_optimizer=False, stencil_json_path=None):
        """
        Initialize generator
        
        Args:
            spread_allocation: Use spread allocation strategy if True
            use_optimizer: Use StencilOptimizer for high-yield code generation
            stencil_json_path: Path to stencil_gadgets.json (for optimizer)
        """
        self.spread_allocation = spread_allocation
        self.use_optimizer = use_optimizer
        self.functions = []
        self.modules = []
        self.stats = {
            'total_functions': 0,
            'jit_compiled': 0,
            'jit_failed': 0,
            'generation_time': 0,
            'warmup_time': 0,
        }
        
        # Initialize optimizer if requested
        if use_optimizer:
            self.optimizer = StencilOptimizer(stencil_json_path)
            print("[+] Using StencilOptimizer for high-gadget-density code generation")
        else:
            self.optimizer = None
    
    def generate(self, count=1000):
        """
        Generate JIT functions
        
        Args:
            count: Number of functions to generate
        
        Returns:
            list: Generated function objects
        """
        start_time = time.time()
        
        if self.spread_allocation:
            print(f"[*] Generating {count} functions with SPREAD allocation...")
            self._generate_spread(count)
        else:
            print(f"[*] Generating {count} functions with NORMAL allocation...")
            self._generate_normal(count)
        
        self.stats['generation_time'] = time.time() - start_time
        self.stats['total_functions'] = len(self.functions)
        
        print(f"[+] Generated {len(self.functions)} functions in "
              f"{self.stats['generation_time']:.2f}s")
        return self.functions
    
    def _generate_normal(self, count):
        """Normal generation: consecutive memory region"""
        for i in range(count):
            func = self._create_jit_function(i)
            self.functions.append(func)
            
            if (i + 1) % PROGRESS_REPORT_INTERVAL == 0:
                print(f"  Progress: {i+1}/{count} functions generated")
    
    def _generate_spread(self, count):
        """
        Spread generation: distribute across wide address space
        
        Strategy:
        1. Create multiple modules
        2. Distribute functions across modules
        3. Force memory allocation separation
        """
        funcs_per_module = count // JIT_MODULE_COUNT
        
        for mod_idx in range(JIT_MODULE_COUNT):
            # Create new module
            module = types.ModuleType(f"jit_spread_module_{mod_idx}")
            self.modules.append(module)
            
            print(f"  Module {mod_idx}: generating {funcs_per_module} functions...")
            
            # Generate functions in module
            for i in range(funcs_per_module):
                global_idx = mod_idx * funcs_per_module + i
                func = self._create_jit_function(global_idx)
                
                # Register in module namespace
                setattr(module, f"func_{i}", func)
                self.functions.append(func)
            
            # Force memory allocation boundary (dummy allocation)
            dummy = bytearray(SPREAD_DUMMY_SIZE)
        
        print(f"[+] Functions spread across {len(self.modules)} modules")
    
    def _create_jit_function(self, seed):
        """
        Create single JIT function
        
        Uses diverse stencils:
        - CALL (nested function)
        - STORE_SUBSCR_DICT, LOAD_ATTR
        - COMPARE_OP
        - FOR_ITER
        - BINARY_OP (add, mul, xor, shift)
        
        If optimizer is enabled, generates high-gadget-density code
        
        Args:
            seed: Function seed for variation
        
        Returns:
            function: Compiled function object
        """
        # Use optimizer if available
        if self.optimizer:
            iterations = FUNCTION_BASE_ITERATIONS + seed * FUNCTION_ITER_INCREMENT
            code = self.optimizer.generate_optimized_function(seed, iterations)
        else:
            # Standard function template
            magic_value = MAGIC_VALUES[seed % len(MAGIC_VALUES)]
            iterations = FUNCTION_BASE_ITERATIONS + seed * FUNCTION_ITER_INCREMENT
            
            code = f"""
def jit_func_{seed}(x):
    # Nested helper to trigger CALL-related stencils
    def h(a, b):
        return (a ^ b) & 0xFFFFFFFF

    # Dictionary and object operations
    d = {{}}
    class Obj:
        val = 0

    obj = Obj()
    acc = x
    for i in range({iterations}):
        acc ^= ({magic_value} + (i << (i % 8)))
        acc = ((acc << (i % 5)) | (acc >> (32 - (i % 5)))) & 0xFFFFFFFF
        acc += ({magic_value} >> (i % 16))
        acc *= 3 + (i % 4)
        acc ^= (acc >> ((i+3) % 8))
        acc ^= ({magic_value} + i) * ((acc >> 3) & 0xff)
        acc += (i ^ {magic_value})
        
        # Trigger various stencils
        acc = h(acc, i & 0xff)
        
        if i % 100 == 0:
            d[i] = acc & 0xff
            acc ^= d.get(i, 0)
        
        if i % 200 == 0:
            obj.val = acc & 0xffff
            acc += obj.val
        
        if acc > {magic_value}:
            acc -= 1
        elif acc < (i & 0xff):
            acc += 1
    
    return acc
"""
        
        scope = {}
        exec(code, scope)
        func_name = f'jit_func_{seed}' if not self.optimizer else f'optimized_jit_func_{seed}'
        return scope[func_name]
    
    def warmup(self, iterations=None):
        """
        Warm up functions to trigger JIT compilation
        
        Args:
            iterations: Number of iterations per function (default: from config)
        """
        if iterations is None:
            iterations = JIT_WARMUP_ITERATIONS
        
        start_time = time.time()
        print(f"[*] Warming up {len(self.functions)} functions "
              f"({iterations} iterations each)...")
        
        for i, func in enumerate(self.functions):
            try:
                for _ in range(iterations):
                    func(42)
                self.stats['jit_compiled'] += 1
            except Exception as e:
                self.stats['jit_failed'] += 1
                print(f"[!] Function {i} warmup failed: {e}")
            
            if (i + 1) % PROGRESS_REPORT_INTERVAL == 0:
                print(f"  Progress: {i+1}/{len(self.functions)} functions warmed up")
        
        self.stats['warmup_time'] = time.time() - start_time
        print(f"[+] Warm-up completed in {self.stats['warmup_time']:.2f}s")
        print(f"    JIT compiled: {self.stats['jit_compiled']}")
        print(f"    Failed: {self.stats['jit_failed']}")
    
    def get_stats(self):
        """Get generation statistics"""
        return self.stats.copy()
