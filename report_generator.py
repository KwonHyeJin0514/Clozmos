from fpdf import FPDF
from datetime import datetime
import os
import time

def generate_pdf_report(token, username, start, end):
    # 날짜 문자열을 datetime 객체로 변환
    try:
        start_dt = datetime.strptime(start, '%Y-%m-%d %H:%M')
        end_dt = datetime.strptime(end, '%Y-%m-%d %H:%M')
    except ValueError:
        raise Exception("날짜 형식을 확인해주세요. (예: 2024-01-01 13:00)")

    # PDF 생성
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt=f"{username}님의 리소스 보고서", ln=True, align='C')
    pdf.cell(200, 10, txt=f"기간: {start_dt.strftime('%Y-%m-%d %H:%M')} ~ {end_dt.strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
    pdf.ln(10)

    # 샘플 데이터 (실제 Zabbix 데이터가 연동되면 바꿀 수 있음)
    pdf.cell(200, 10, txt="리소스별 평균 및 최대 사용률:", ln=True)
    pdf.cell(200, 10, txt="- CPU 평균: 25%, 최대: 70%", ln=True)
    pdf.cell(200, 10, txt="- 메모리 평균: 58%, 최대: 90%", ln=True)
    pdf.ln(10)

    # 그래프 이미지 삽입
    if os.path.exists("static/CPU.png"):
        pdf.image("static/CPU.png", x=10, w=180)
    if os.path.exists("static/Memory.png"):
        pdf.image("static/Memory.png", x=10, w=180)

    # 알림 로그 예시
    pdf.ln(10)
    pdf.cell(200, 10, txt="최근 알림 로그:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(200, 8,
        "- [2025-05-01 15:00:00] CPU 임계치 초과\n"
        "- [2025-05-01 15:05:00] 메모리 사용량 90% 초과"
    )

    output_path = f"report_{username}_{int(time.time())}.pdf"
    pdf.output(output_path)
    return output_path
