import threading
import time

# 실행 여부를 제어할 플래그
running = True

# 메모리 부하용 함수
def burn_memory():
    big_list = []
    while running:
        big_list.append("A" * 1024 * 10 ) # 10KB 문자열 추가


# 스레드 시작
t = threading.Thread(target=burn_memory)
t.start()

# 4초 동안 실행
time.sleep(7)

# 종료 신호 보내기
running = False

# 스레드가 종료될 때까지 기다리기
t.join()

# 메모리 부하 시작 (한 스레드로도 충분함)
threading.Thread(target=burn_memory).start()
