# report_generator.py (수정된 최종 코드)

from fpdf import FPDF
from datetime import datetime
import os
import time
# ⚠️ matplotlib, io, pytz, get_historical_data import 추가
import matplotlib.pyplot as plt
import io
import pytz 
from zabbix_api import get_user_info, get_alert_logs, get_user_host, get_historical_data 
# get_item_id, get_latest_data는 이제 사용하지 않으므로 제거하거나 주석 처리합니다.

# PDF 보고서 생성 함수
def generate_pdf_report(token, username, start, end, selected_resources=None):
    # 1. 날짜 문자열을 KST 기반 Unix Timestamp로 변환
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S' # app.py에서 YYYY-MM-DD HH:MM:SS 형식으로 변환하여 보냄
    try:
        kst = pytz.timezone('Asia/Seoul')
        
        # 시작/종료 시간을 KST로 로컬라이즈하고 Timestamp로 변환
        start_dt_kst = kst.localize(datetime.strptime(start, DATE_FORMAT))
        end_dt_kst = kst.localize(datetime.strptime(end, DATE_FORMAT))
        
        time_from = int(start_dt_kst.timestamp())
        time_till = int(end_dt_kst.timestamp())

    except ValueError:
        raise Exception("날짜 형식을 확인해주세요. (예: 2024-01-01 13:00:00)")

    pdf = FPDF()
    pdf.add_page()
    
    # 한글 특수문자 출력이 가능하도록 나눔고딕 폰트 등록
    pdf.add_font("NanumBold", "", "fonts/NanumGothic-Bold.ttf", uni=True)
    pdf.set_font("NanumBold", size=12)

    # ... (사용자 정보 및 기간 설정 셀 출력 로직 유지) ...
    user = get_user_info(token)
    pdf.cell(200, 10, txt=f"사용자: {username} ({user['name']})", ln=True)
    # ... (이메일 및 언어 출력 로직 유지) ...
    pdf.ln(5)
    pdf.cell(200, 10, txt=f"리소스 보고서 기간: {start_dt_kst.strftime('%Y-%m-%d %H:%M')} ~ {end_dt_kst.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(5)


    # 2. 리소스 키 설정 (Linux/Windows 호환성 개선 키 포함)
    resource_items = {
        "CPU 평균 부하": [
            'system.cpu.load[all,avg1]', # Linux 표준
            'perf_counter_en["\\Processor Information(_total)\\% User Time"]' # Windows
        ],
        "CPU 사용률": ["system.cpu.util"],
        "전체대비 메모리 사용률": ["vm.memory.util"],
        "디스크 사용률": [
            'vfs.fs.size[/,pused]', # Linux 표준
            'perf_counter_en["\Paging file(_Total)\\% Usage"]' # Windows
        ],
        "네트워크 송수신 바이트수": [ 
            'net.if.in[eth0]', # Linux/Windows - 수신
            'net.if.out[eth0]' # Linux/Windows - 송신
        ],
        "패킷 손실율": [
            'icmppingloss["172.29.109.194"]'
        ]
    }

    host_id = get_user_host(token, username, return_id=True)

    for res_name, key_list in resource_items.items():
        if selected_resources and res_name not in selected_resources:
            continue
        
        for key in key_list:
            try:
                # 3. 기간별 이력 데이터 조회 (get_historical_data 사용)
                data = get_historical_data(token, username, key, time_from, time_till)
                
                if not data:
                    continue
                
                # 4. 데이터 추출 및 분석
                values = [float(d['value']) for d in data]
                timestamps = [datetime.fromtimestamp(int(d['clock'])) for d in data]
                
                max_val = max(values) if values else 0
                avg_val = sum(values) / len(values) if values else 0
                warn_cnt = len([v for v in values if v > 80])
                crit_cnt = len([v for v in values if v > 95])

                # 5. Matplotlib 그래프 생성 (BytesIO를 사용하여 임시 파일 사용 최소화)
                plt.figure(figsize=(7, 3.5)) # PDF 크기에 맞게 조정
                plt.plot(timestamps, values, label=res_name, linewidth=1.5)
                plt.title(f"{res_name} 사용률", fontsize=10)
                plt.xlabel("시간", fontsize=8)
                plt.ylabel("값 (%)", fontsize=8)
                plt.grid(True, linestyle='--', alpha=0.6)
                plt.xticks(rotation=20, fontsize=7)
                plt.yticks(fontsize=7)
                plt.tight_layout()
                
                # BytesIO를 사용하여 메모리 내 이미지 저장
                img_stream = io.BytesIO()
                plt.savefig(img_stream, format='png')
                plt.close() # 메모리 해제
                img_stream.seek(0)

                # 6. PDF에 정보 및 이미지 삽입
                pdf.set_font("NanumBold", size=11)
                pdf.cell(200, 10, txt=f"▶ {res_name}", ln=True)
                pdf.set_font("NanumBold", size=10)
                pdf.cell(200, 8, txt=f"  최대값: {max_val:.2f}, 평균값: {avg_val:.2f}", ln=True)
                pdf.cell(200, 8, txt=f"  경고 수: {warn_cnt}회, 위험 수: {crit_cnt}회 (임계치 80%/95%)", ln=True)
                
                # fpdf에 BytesIO에서 읽은 PNG 이미지 삽입
                pdf.image(img_stream, x=10, w=180, type='PNG') 
                pdf.ln(3)
                
                break # 유효한 데이터를 찾았으므로 다음 리소스로 이동

            except Exception as e:
                # print(f"Error generating report for {res_name} with key {key}: {e}")
                continue # 다음 후보 키 시도

    # 7. 최근 알림 로그 섹션 유지
    pdf.ln(5)
    pdf.set_font("NanumBold", size=12)
    pdf.cell(200, 10, txt="최근 알림 로그:", ln=True)
    pdf.set_font("NanumBold", size=10)
    # 알림 로그는 현재 시간 기준 최근 로그를 가져오므로, 기간 정보는 사용하지 않습니다.
    logs = get_alert_logs(token, username) 
    for log in logs:
        # log['message']에 개행 문자 포함 시 multi_cell 사용
        pdf.multi_cell(200, 8, f"- [{log['time']}] {log['message']}")

    # 8. 최종 PDF 저장 및 경로 반환
    output_path = f"report_{username}_{int(time.time())}.pdf"
    pdf.output(output_path)
    return output_path