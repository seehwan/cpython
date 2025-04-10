cat /proc/$(pgrep -f jit_exec_experiment.py)/smaps | grep -A 15 -i jit

grep -A 20 -i jit /proc/$(pgrep -f jit_exec_experiment.py)/smaps

