"""
Gadget Analysis Framework
==========================

A comprehensive toolkit for analyzing ROP gadgets in CPython JIT code.

Modules:
--------
- classifier: 6-way gadget classification by generation mechanism
- scanner: Runtime JIT memory scanning and gadget detection
- generator: JIT function generation with controlled allocation
- reporter: Statistical analysis and reporting utilities
- config: Shared configuration and constants

Usage:
------
    from gadget_analysis import GadgetClassifier, RuntimeJITScanner
    
    scanner = RuntimeJITScanner()
    gadgets = scanner.scan_functions(functions)
    
    classifier = GadgetClassifier()
    classifier.classify_all_gadgets(base_addr, buffer, gadgets)
    classifier.print_classification_report()
"""

__version__ = "1.0.0"
__author__ = "Case Study 4 Team"
__all__ = [
    "GadgetClassifier",
    "GadgetCategory",
    "RuntimeJITScanner",
    "JITFunctionGenerator",
    "GadgetReporter",
]

from .classifier import GadgetClassifier, GadgetCategory
from .scanner import RuntimeJITScanner
from .generator import JITFunctionGenerator
from .reporter import GadgetReporter
