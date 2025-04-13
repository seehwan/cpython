# 37.jit_randomization_launcher.py
import subprocess
import multiprocessing

# 실험에 사용할 magic 값 목록
MAGIC_VALUES = [
    "0x0000ffff", "0xffff0000", "0xf0f0f0f0", "0x0f0f0f0f",
    "0xdeadbeef", "0xaaaaaaaa", "0x55555555", "0xffffffff"
]

# 각 magic 값마다 실행할 반복 횟수
REPEAT_COUNT = 100

# 동시에 실행할 최대 프로세스 수
MAX_PARALLEL = 8

def run_worker(args):
    magic, run_id = args
    print(f"[Launcher] Run {run_id + 1}/{REPEAT_COUNT} for {magic}")
    subprocess.run(["python3.14", "37.jit_randomization_worker.py", magic, str(run_id)])

if __name__ == "__main__":
    # 전체 실험 태스크 생성
    task_list = [(magic, i) for magic in MAGIC_VALUES for i in range(REPEAT_COUNT)]

    # 병렬로 태스크 실행
    with multiprocessing.Pool(processes=MAX_PARALLEL) as pool:
        pool.map(run_worker, task_list)
