[ ! -e run_dir ] && ln -s ../run_dir run_dir
cp case1.trampoline_overwrite_single.py ./run_dir/run_shell.py
cd run_dir
python3.14 run_shell.py
cd ..
