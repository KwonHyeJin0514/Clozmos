import multiprocessing
import time
import sys
import os

def burn_cpu():
    start = time.time()
    while time.time() - start < 8:
        pass

def main():
    processes = []
    for _ in range(10):
        p = multiprocessing.Process(target=burn_cpu)
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


if __name__ == "__main__":
    multiprocessing.freeze_support() 
    main()
