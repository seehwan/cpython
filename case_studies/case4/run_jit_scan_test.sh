#!/bin/bash
# Runtime JIT Gadget Scanner - Quick Start Guide

echo "=========================================="
echo "Runtime JIT Gadget Scanner Test Suite"
echo "=========================================="
echo ""

# Check if running from correct directory
if [ ! -f "test_runtime_jit_scan.py" ]; then
    echo "Error: test_runtime_jit_scan.py not found"
    echo "Please run this script from case_studies/case4 directory"
    exit 1
fi

# Check dependencies
echo "[*] Checking dependencies..."
python3 -c "import capstone" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: capstone not installed"
    echo "Install with: pip install capstone"
    exit 1
fi

if [ ! -f "jitexecleak.py" ]; then
    echo "Warning: jitexecleak.py not found"
    echo "Some functionality may be limited"
fi

echo "[+] Dependencies OK"
echo ""

# Show menu
echo "Select test scenario:"
echo "  1) Quick test (100 functions, normal allocation)"
echo "  2) Quick test (100 functions, spread allocation)"
echo "  3) Standard test (1000 functions, both allocations + comparison)"
echo "  4) Large test (5000 functions, both allocations + comparison)"
echo "  5) Custom test"
echo ""
read -p "Choice [1-5]: " choice

case $choice in
    1)
        echo ""
        echo "[*] Running quick test (normal allocation)..."
        python3 test_runtime_jit_scan.py -n 100 -t normal
        ;;
    2)
        echo ""
        echo "[*] Running quick test (spread allocation)..."
        python3 test_runtime_jit_scan.py -n 100 -t spread
        ;;
    3)
        echo ""
        echo "[*] Running standard test (1000 functions)..."
        echo "    This will take approximately 1-2 minutes..."
        python3 test_runtime_jit_scan.py -n 1000 -t both
        ;;
    4)
        echo ""
        echo "[*] Running large test (5000 functions)..."
        echo "    This will take approximately 5-10 minutes..."
        python3 test_runtime_jit_scan.py -n 5000 -t both
        ;;
    5)
        echo ""
        read -p "Number of functions: " num
        read -p "Test type (normal/spread/both): " test_type
        echo ""
        echo "[*] Running custom test..."
        python3 test_runtime_jit_scan.py -n $num -t $test_type
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Test completed!"
echo "=========================================="
echo ""
echo "Results saved to:"
echo "  - runtime_scan_normal.json (if normal test was run)"
echo "  - runtime_scan_spread.json (if spread test was run)"
echo ""
echo "To analyze results:"
echo "  python3 -m json.tool runtime_scan_normal.json | less"
echo "  python3 -m json.tool runtime_scan_spread.json | less"
