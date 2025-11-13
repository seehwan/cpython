#!/usr/bin/env python3
"""
Gadget Classifier Module
=========================

6-way classification of ROP gadgets by generation mechanism.

Categories:
-----------
1. Stencil-Aligned: Gadgets at instruction boundaries in JIT stencils
2. Instruction-Unaligned: Gadgets from mid-instruction decoding (unintended)
3. Patch-Induced: Gadgets created during patch operations (patch_64/32/x86_64_32rx)
4. Address-Diversity: Gadgets from diverse address space usage
5. Patch-Unaligned: Gadgets spanning patch field boundaries
6. Syscall-Special: syscall instruction (no ret needed)

Each gadget can belong to multiple categories simultaneously.
"""

import struct
from collections import defaultdict
from enum import Enum
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class GadgetCategory(Enum):
    """Gadget generation mechanism categories"""
    STENCIL_ALIGNED = "stencil_aligned"
    INSTRUCTION_UNALIGNED = "instruction_unaligned"
    PATCH_INDUCED = "patch_induced"
    ADDRESS_DIVERSITY = "address_diversity"
    PATCH_UNALIGNED = "patch_unaligned"
    SYSCALL_SPECIAL = "syscall_special"


class GadgetClassifier:
    """Classifies gadgets by generation mechanism"""
    
    # Patch function signatures (byte patterns)
    PATCH_SIGNATURES = {
        'patch_64': b'\x48\x8b',      # movabs family (8-byte address)
        'patch_32': b'\x89',          # mov r/m32 family
        'patch_x86_64_32rx': b'\x8d', # lea family
    }
    
    # Reliability levels
    RELIABILITY = {
        GadgetCategory.STENCIL_ALIGNED: 'high',
        GadgetCategory.INSTRUCTION_UNALIGNED: 'medium',
        GadgetCategory.PATCH_INDUCED: 'medium',
        GadgetCategory.ADDRESS_DIVERSITY: 'variable',
        GadgetCategory.PATCH_UNALIGNED: 'low',
        GadgetCategory.SYSCALL_SPECIAL: 'high',
    }
    
    def __init__(self):
        """Initialize classifier with Capstone disassembler"""
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.classified_gadgets = defaultdict(lambda: defaultdict(list))
        self.classification_results = {}
        self.instruction_boundaries = set()
    
    def classify_all_gadgets(self, base_addr, buffer, gadgets_dict):
        """
        Classify all discovered gadgets
        
        Args:
            base_addr: JIT code start address
            buffer: JIT code memory (bytes)
            gadgets_dict: Discovered gadgets {gadget_name: [gadget_info]}
        
        Returns:
            dict: Classified gadgets by category
        """
        # Step 1: Identify instruction boundaries
        self._identify_instruction_boundaries(base_addr, buffer)
        
        # Step 2: Classify each gadget
        for gadget_name, gadget_list in gadgets_dict.items():
            for gadget_info in gadget_list:
                addr = gadget_info['address']
                offset = gadget_info['offset']
                
                # Special case: syscall
                if gadget_name == 'syscall':
                    self._add_classified_gadget(
                        GadgetCategory.SYSCALL_SPECIAL,
                        gadget_name,
                        gadget_info,
                        {
                            'reason': 'syscall requires no ret, special ROP handling',
                            'reliability': 'high'
                        }
                    )
                    continue
                
                # General gadget classification (multi-category)
                categories = self._classify_single_gadget(
                    addr, offset, buffer, gadget_name, gadget_info
                )
                
                for category, metadata in categories:
                    self._add_classified_gadget(category, gadget_name, gadget_info, metadata)
        
        return self.classified_gadgets
    
    def _identify_instruction_boundaries(self, base_addr, buffer):
        """Identify instruction boundaries via sequential disassembly"""
        self.instruction_boundaries.clear()
        
        try:
            offset = 0
            while offset < len(buffer):
                insns = list(self.md.disasm(buffer[offset:offset+16], base_addr + offset))
                if insns:
                    self.instruction_boundaries.add(base_addr + offset)
                    offset += insns[0].size
                else:
                    offset += 1
        except:
            pass
    
    def _classify_single_gadget(self, addr, offset, buffer, gadget_name, gadget_info):
        """Classify single gadget (can belong to multiple categories)"""
        categories = []
        
        # 1. Aligned vs Unaligned
        if addr in self.instruction_boundaries:
            categories.append((
                GadgetCategory.STENCIL_ALIGNED,
                {
                    'reason': 'Found at instruction boundary',
                    'reliability': 'high',
                    'offset_alignment': 'aligned'
                }
            ))
        else:
            categories.append((
                GadgetCategory.INSTRUCTION_UNALIGNED,
                {
                    'reason': 'Found mid-instruction (unintended decoding)',
                    'reliability': 'medium',
                    'offset_alignment': 'unaligned'
                }
            ))
        
        # 2. Patch-Induced check
        patch_context = self._analyze_patch_context(offset, buffer)
        if patch_context:
            categories.append((
                GadgetCategory.PATCH_INDUCED,
                {
                    'reason': f"Found near {patch_context['type']} operation",
                    'reliability': 'medium',
                    'patch_type': patch_context['type'],
                    'patch_offset': patch_context['offset']
                }
            ))
            
            # 3. Patch-Unaligned sub-classification
            if not self._is_aligned_to_patch_field(offset, patch_context):
                categories.append((
                    GadgetCategory.PATCH_UNALIGNED,
                    {
                        'reason': 'Gadget spans across patch field boundary',
                        'reliability': 'low',
                        'patch_field_offset': patch_context['field_offset']
                    }
                ))
        
        # 4. Address-Diversity check
        if self._is_address_diversity_candidate(offset, buffer):
            categories.append((
                GadgetCategory.ADDRESS_DIVERSITY,
                {
                    'reason': 'Gadget bytes contain high-diversity address values',
                    'reliability': 'variable',
                    'address_bytes': self._extract_address_bytes(offset, buffer)
                }
            ))
        
        return categories
    
    def _analyze_patch_context(self, offset, buffer):
        """Analyze patch function context around gadget"""
        search_start = max(0, offset - 16)
        search_end = min(len(buffer), offset + 16)
        context = buffer[search_start:search_end]
        
        for patch_type, signature in self.PATCH_SIGNATURES.items():
            pos = context.find(signature)
            if pos != -1:
                return {
                    'type': patch_type,
                    'offset': search_start + pos,
                    'field_offset': self._estimate_patch_field_offset(
                        offset, search_start + pos, patch_type
                    )
                }
        
        return None
    
    def _estimate_patch_field_offset(self, gadget_offset, patch_offset, patch_type):
        """Estimate gadget offset within patch field"""
        field_layouts = {
            'patch_64': (2, 8),        # opcode(2) + imm64(8)
            'patch_32': (2, 4),        # opcode(2) + imm32(4)
            'patch_x86_64_32rx': (2, 4), # opcode(2) + disp32(4)
        }
        
        if patch_type not in field_layouts:
            return None
        
        prefix_size, field_size = field_layouts[patch_type]
        field_start = patch_offset + prefix_size
        field_end = field_start + field_size
        
        if field_start <= gadget_offset < field_end:
            return gadget_offset - field_start
        
        return None
    
    def _is_aligned_to_patch_field(self, offset, patch_context):
        """Check if gadget is aligned to patch field boundary"""
        return patch_context.get('field_offset') is None
    
    def _is_address_diversity_candidate(self, offset, buffer):
        """Check if gadget is from address diversity"""
        if offset % 8 == 0 and offset + 8 <= len(buffer):
            ptr_value = struct.unpack('<Q', buffer[offset:offset+8])[0]
            # libc address range
            return 0x7f0000000000 <= ptr_value < 0x800000000000
        return False
    
    def _extract_address_bytes(self, offset, buffer):
        """Extract address bytes for analysis"""
        if offset + 8 <= len(buffer):
            return buffer[offset:offset+8].hex()
        return None
    
    def _add_classified_gadget(self, category, gadget_name, gadget_info, metadata):
        """Add classified gadget to results"""
        classified_info = {
            **gadget_info,
            'category': category.value,
            'metadata': metadata
        }
        self.classified_gadgets[category][gadget_name].append(classified_info)
    
    def print_classification_report(self):
        """Print classification results report"""
        print("\n" + "="*70)
        print("GADGET CLASSIFICATION REPORT")
        print("="*70)
        
        descriptions = {
            GadgetCategory.STENCIL_ALIGNED: "1. JIT Stencil Aligned (Instruction Boundary)",
            GadgetCategory.INSTRUCTION_UNALIGNED: "2. Instruction-Unaligned (Unintended)",
            GadgetCategory.PATCH_INDUCED: "3. Patch-Induced (During Patching)",
            GadgetCategory.ADDRESS_DIVERSITY: "4. Address-Diversity (Wide Address Space)",
            GadgetCategory.PATCH_UNALIGNED: "5. Patch-Unaligned (Crossing Field Boundary)",
            GadgetCategory.SYSCALL_SPECIAL: "6. Syscall (No ret needed)",
        }
        
        total_by_category = {}
        
        for category in GadgetCategory:
            desc = descriptions[category]
            gadgets = self.classified_gadgets[category]
            total = sum(len(v) for v in gadgets.values())
            total_by_category[category] = total
            
            print(f"\n{desc}")
            print(f"  Total: {total} gadgets")
            
            if gadgets:
                for gadget_name, gadget_list in sorted(gadgets.items()):
                    print(f"    {gadget_name:<12}: {len(gadget_list):>4} gadgets")
        
        # Summary statistics
        print("\n" + "-"*70)
        print("SUMMARY")
        print("-"*70)
        
        grand_total = sum(total_by_category.values())
        print(f"  Total classified gadgets: {grand_total}")
        print("\n  Distribution:")
        
        for category, count in sorted(total_by_category.items(), 
                                      key=lambda x: x[1], reverse=True):
            if count > 0:
                pct = (count / grand_total * 100) if grand_total > 0 else 0
                print(f"    {category.value:<25}: {count:>5} ({pct:>5.1f}%)")
    
    def export_classification(self):
        """Export classification results as dictionary (for JSON)"""
        data = {}
        
        for category, gadgets in self.classified_gadgets.items():
            data[category.value] = {
                name: [
                    {
                        'address': f"0x{g['address']:016x}",
                        'offset': g['offset'],
                        'bytes': g['bytes'],
                        'instruction': g['instruction'],
                        'metadata': g['metadata']
                    }
                    for g in gadget_list
                ]
                for name, gadget_list in gadgets.items()
            }
        
        # Add statistics
        total_by_category = {
            category.value: sum(len(v) for v in gadgets.values())
            for category, gadgets in self.classified_gadgets.items()
        }
        
        data['_summary'] = {
            'total_gadgets': sum(total_by_category.values()),
            'by_category': total_by_category
        }
        
        return data
    
    def get_statistics(self):
        """Get classification statistics"""
        stats = {
            'by_category': {},
            'by_gadget_type': defaultdict(lambda: defaultdict(int))
        }
        
        for category, gadgets in self.classified_gadgets.items():
            total = sum(len(v) for v in gadgets.values())
            stats['by_category'][category.value] = total
            
            for gadget_name, gadget_list in gadgets.items():
                stats['by_gadget_type'][gadget_name][category.value] = len(gadget_list)
        
        return stats


if __name__ == "__main__":
    print(__doc__)
    print("\nUsage:")
    print("  from gadget_analysis import GadgetClassifier")
    print("  classifier = GadgetClassifier()")
    print("  classified = classifier.classify_all_gadgets(base_addr, buffer, gadgets)")
    print("  classifier.print_classification_report()")
