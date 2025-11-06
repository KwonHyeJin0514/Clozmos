import threading

def burn_cpu():
    while True:
        pass  # 무한 루프

threads = []
for _ in range(20):  # CPU 코어 수에 맞게 조절
    t = threading.Thread(target=burn_cpu)
    t.start()
    threads.append(t)