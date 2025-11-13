#!/usr/bin/env python3
"""
JIT Memory Scanner Module
==========================

Scans runtime JIT memory for ROP gadgets.
"""

import ctypes
import time
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Import jitexecleak from parent directory
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jitexecleak

from .config import GADGET_PATTERNS, PROGRESS_REPORT_INTERVAL
from .classifier import GadgetClassifier


class RuntimeJITScanner:
    """Runtime JIT memory scanner"""
    
    def __init__(self):
        """Initialize scanner with Capstone disassembler"""
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.gadgets = defaultdict(list)
        self.stats = {
            'functions_scanned': 0,
            'jit_memory_accessible': 0,
            'jit_memory_failed': 0,
            'total_bytes_scanned': 0,
            'scan_time': 0,
            'gadgets_found': 0,
        }
        self.address_diversity = defaultdict(set)
        
        # Gadget classifier
        self.classifier = GadgetClassifier()
        self.classified_results = None
        
        # JIT memory cache for classification
        self.jit_memory_cache = []  # [(base_addr, buffer)]
    
    def scan_functions(self, functions):
        """
        Scan all JIT functions for gadgets
        
        Args:
            functions: List of function objects to scan
        
        Returns:
            dict: Discovered gadgets by type
        """
        start_time = time.time()
        print(f"\n[*] Scanning {len(functions)} JIT functions...")
        
        for i, func in enumerate(functions):
            self._scan_single_function(func, i)
            
            if (i + 1) % PROGRESS_REPORT_INTERVAL == 0:
                print(f"  Progress: {i+1}/{len(functions)} functions scanned")
        
        self.stats['scan_time'] = time.time() - start_time
        self.stats['gadgets_found'] = sum(len(v) for v in self.gadgets.values())
        
        print(f"[+] Scan completed in {self.stats['scan_time']:.2f}s")
        print(f"    Memory accessible: {self.stats['jit_memory_accessible']}")
        print(f"    Memory failed: {self.stats['jit_memory_failed']}")
        print(f"    Total bytes scanned: {self.stats['total_bytes_scanned']:,}")
        print(f"    Gadgets found: {self.stats['gadgets_found']}")
        
        # Classify gadgets
        print(f"\n[*] Classifying gadgets by generation mechanism...")
        self._classify_gadgets()
        
        return self.gadgets
    
    def _scan_single_function(self, func, func_idx):
        """Scan single JIT function memory"""
        try:
            # Get JIT code address
            jit_addr, jit_size = jitexecleak.leak_executor_jit(func)
            
            # Read memory
            buffer = ctypes.string_at(jit_addr, jit_size)
            self.stats['jit_memory_accessible'] += 1
            self.stats['total_bytes_scanned'] += jit_size
            
            # Cache JIT memory for classification
            self.jit_memory_cache.append((jit_addr, buffer))
            
            # Scan for gadgets (all byte offsets including unintended)
            self._scan_buffer_for_gadgets(jit_addr, buffer)
            
        except Exception as e:
            self.stats['jit_memory_failed'] += 1
        
        self.stats['functions_scanned'] += 1
    
    def _scan_buffer_for_gadgets(self, base_addr, buffer):
        """Scan buffer for all gadget patterns"""
        # Scan every byte offset (includes unintended instructions)
        for offset in range(len(buffer)):
            for gadget_name, pattern in GADGET_PATTERNS.items():
                if buffer[offset:offset+len(pattern)] == pattern:
                    # Found gadget
                    addr = base_addr + offset
                    
                    # Disassemble to get instruction text
                    try:
                        insns = list(self.md.disasm(
                            buffer[offset:offset+16], addr
                        ))
                        if insns:
                            instruction = '; '.join(
                                f"{insn.mnemonic} {insn.op_str}" 
                                for insn in insns[:2]
                            )
                        else:
                            instruction = f"<raw: {pattern.hex()}>"
                    except:
                        instruction = f"<raw: {pattern.hex()}>"
                    
                    self.gadgets[gadget_name].append({
                        'address': addr,
                        'offset': offset,
                        'bytes': buffer[offset:offset+len(pattern)].hex(),
                        'instruction': instruction,
                    })
                    
                    # Track address diversity for patch_64 analysis
                    if gadget_name == 'pop_rax' and offset % 8 == 0:
                        for byte_pos in range(8):
                            if offset + byte_pos < len(buffer):
                                self.address_diversity[byte_pos].add(
                                    buffer[offset + byte_pos]
                                )
    
    def _classify_gadgets(self):
        """Classify discovered gadgets by generation mechanism"""
        if not self.jit_memory_cache:
            print("[!] No JIT memory cached for classification")
            return
        
        print(f"[*] Classifying {len(self.jit_memory_cache)} JIT memory regions...")
        
        # Classify each JIT memory buffer
        for idx, (base_addr, buffer) in enumerate(self.jit_memory_cache):
            if idx % 10 == 0 and idx > 0:
                print(f"    Progress: {idx}/{len(self.jit_memory_cache)} "
                      f"regions classified")
            
            self.classifier.classify_all_gadgets(base_addr, buffer, self.gadgets)
        
        # Mark classification complete
        self.classified_results = {
            'total_regions': len(self.jit_memory_cache),
            'classified': True
        }
        print(f"[+] Classification complete!")
    
    def print_results(self):
        """Print scan results"""
        print("\n" + "="*70)
        print("SCAN RESULTS")
        print("="*70)
        
        # Gadgets found
        print("\n[Gadgets Found]")
        for gadget_name, gadget_list in sorted(self.gadgets.items()):
            print(f"  {gadget_name:<12}: {len(gadget_list):>5} gadgets")
        
        # Sample gadgets
        print("\n[Sample Gadgets]")
        for gadget_name, gadget_list in sorted(self.gadgets.items()):
            if gadget_list:
                print(f"\n  {gadget_name}:")
                for gadget in gadget_list[:3]:
                    print(f"    0x{gadget['address']:016x}: {gadget['instruction']}")
        
        # Address diversity analysis
        print("\n[Address Diversity Analysis]")
        print("  (patch_64 주소의 바이트별 엔트로피)")
        for byte_pos in range(8):
            unique_vals = len(self.address_diversity[byte_pos])
            entropy = 0
            if unique_vals > 0:
                import math
                entropy = math.log2(unique_vals) if unique_vals > 1 else 0
            print(f"    Byte {byte_pos}: {unique_vals:>3} unique values "
                  f"({entropy:.2f} bits entropy)")
        
        print("\n" + "="*70)
        
        # Classification report
        if self.classified_results:
            print("\n[Gadget Classification Report]")
            self.classifier.print_classification_report()
    
    def export_results(self, filename):
        """
        Export results to JSON
        
        Args:
            filename: Output JSON file path
        """
        import json
        
        data = {
            'stats': self.stats,
            'gadgets': {
                name: [
                    {
                        'address': f"0x{g['address']:016x}",
                        'offset': g['offset'],
                        'bytes': g['bytes'],
                        'instruction': g['instruction'],
                    }
                    for g in gadgets
                ]
                for name, gadgets in self.gadgets.items()
            },
            'address_diversity': {
                f'byte_{i}': len(vals)
                for i, vals in self.address_diversity.items()
            }
        }
        
        # Add classification data
        if self.classified_results:
            classification_data = self.classifier.export_classification()
            data['classification'] = classification_data
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Results exported to {filename}")
    
    def get_stats(self):
        """Get scan statistics"""
        return self.stats.copy()
