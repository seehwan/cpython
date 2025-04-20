[ ! -e run_dir ] && ln -s ../run_dir run_dir
[ -e trampoline_jit_log ] && rm -rf trampoline_jit_log
cp case1.py ./run_dir
cd run_dir
python3.14 case1.py
mv trampoline_jit_log ../case1
cd ..
