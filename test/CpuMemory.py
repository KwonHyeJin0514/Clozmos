import threading
import time

# CPU 부하용 함수
def burn_cpu():
    while True:
        pass  # 무한 루프

# 메모리 부하용 함수
def burn_memory():
    big_list = []
    try:
        while True:
            # 약 1MB짜리 문자열을 계속 리스트에 추가
            big_list.append("A" * 1024 * 1024)
    except:
        pass

# 스레드 생성 (CPU 코어 수에 맞게 조절)
for _ in range(16):  # CPU 코어 수 또는 그 이상
    threading.Thread(target=burn_cpu).start()

# 메모리 부하 시작 (한 스레드로도 충분함)
threading.Thread(target=burn_memory).start()
