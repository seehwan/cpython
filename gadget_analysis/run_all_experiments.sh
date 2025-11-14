#!/bin/bash
# 전체 실험 자동 실행 스크립트

echo "=========================================="
echo "Gadget Analysis Experiments - Full Suite"
echo "=========================================="
echo ""

# Step 1: JIT 코드 생성 (시간 소요)
echo "[Step 1] Generating JIT code for all scenarios..."
echo "  (This will take a long time - estimated 3-4 hours total)"
echo ""

read -p "Generate all scenarios? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "  Generating Scenario A (for Experiments 1, 2, 3)..."
    python3 gadget_analysis/jit_code_generator.py --scenario a
    
    echo "  Generating Scenario B (for Experiment 4)..."
    python3 gadget_analysis/jit_code_generator.py --scenario b
    
    echo "  Generating Scenario C (for Experiment 5)..."
    python3 gadget_analysis/jit_code_generator.py --scenario c
    
    echo "  Generating Scenario D (for Experiment 6)..."
    python3 gadget_analysis/jit_code_generator.py --scenario d
else
    echo "Skipping generation. Make sure data exists before running experiments."
fi

echo ""
echo "[Step 2] Running all experiments (fast - using pre-generated data)..."
echo ""

# Experiment 1
echo "Running Experiment 1: Stencil Gadget Cataloging..."
python3 gadget_analysis/experiment_1_refactored.py
echo ""

# Experiment 2
echo "Running Experiment 2: Unaligned Decoding Analysis..."
python3 gadget_analysis/experiment_2_unaligned.py
echo ""

# Experiment 3
echo "Running Experiment 3: Patch Function Impact..."
python3 gadget_analysis/experiment_3_patch_impact.py
echo ""

# Experiment 4
echo "Running Experiment 4: Memory Scaling..."
python3 gadget_analysis/experiment_4_memory_scaling.py
echo ""

# Experiment 5
echo "Running Experiment 5: Syscall Taxonomy..."
python3 gadget_analysis/experiment_5_syscall_taxonomy.py
echo ""

# Experiment 6
echo "Running Experiment 6: Opcode-Sensitive Generator..."
python3 gadget_analysis/experiment_6_opcode_sensitive.py
echo ""

echo "=========================================="
echo "✓ All experiments completed!"
echo "=========================================="
echo ""
echo "Results saved in:"
echo "  - gadget_analysis/experiment_1_results/"
echo "  - gadget_analysis/experiment_2_results/"
echo "  - gadget_analysis/experiment_3_results/"
echo "  - gadget_analysis/experiment_4_results/"
echo "  - gadget_analysis/experiment_5_results/"
echo "  - gadget_analysis/experiment_6_results/"
