from fpdf import FPDF
from datetime import datetime
import os
import time
from zabbix_api import get_user_info, get_alert_logs, get_item_id, get_latest_data, get_user_host

# PDF 보고서 생성 함수
def generate_pdf_report(token, username, start, end, selected_resources=None):
    try:
        start_dt = datetime.strptime(start, '%Y-%m-%d %H:%M')
        end_dt = datetime.strptime(end, '%Y-%m-%d %H:%M')
    except ValueError:
        raise Exception("날짜 형식을 확인해주세요. (예: 2024-01-01 13:00)")

    pdf = FPDF()
    pdf.add_page()
    
    #한글 특수문자 출력이 가능하도록 나눔고딕 폰트 등록
    pdf.add_font("NanumBold", "", "fonts/NanumGothic-Bold.ttf",uni=True)
    pdf.set_font("NanumBold",size=12)

    # 사용자 정보
    user = get_user_info(token)
    pdf.cell(200, 10, txt=f"사용자: {username} ({user['name']})", ln=True)
    email = None
    medias = user.get('medias') or user.get('user_medias')
    if medias and isinstance(medias, list) and len(medias) > 0:
        raw = medias[0].get('sendto')
        email = raw[0] if isinstance(raw, list) else raw

    pdf.cell(200, 10, txt=f"이메일: {email or '등록되지 않음'}", ln=True)
    pdf.cell(200, 10, txt=f"언어: {user.get('lang', 'ko')}", ln=True)
    pdf.ln(5)

    pdf.cell(200, 10, txt=f"리소스 보고서 기간: {start_dt.strftime('%Y-%m-%d %H:%M')} ~ {end_dt.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(5)

    # 리소스 키 설정 (manage.html 기준)
    resource_items = {
        "CPU 평균 부하":
            ['perf_counter_en["\\Processor Information(_total)\\% User Time"]',
            'perf_counter_en["\\Processor Information(_total)\\% Privileged Time"]'],  # Linux only
        "CPU 사용률": ["system.cpu.util"],
        "전체대비 메모리 사용률": ["vm.memory.util"],
        "디스크 사용률": [
            'perf_counter_en["\Paging file(_Total)\% Usage"]'        # Windows
        ],
        "네트워크 송수신 바이트수": [            # Linux
            'net.if.total["이더넷]'
        ],
        "패킷 손실율": [
            'icmppingloss["172.29.109.194"]'
        ]
    }

    host_id = get_user_host(token, username, return_id=True)

    for res_name, key_list in resource_items.items():
        if selected_resources and res_name not in selected_resources:
            continue
        data_points = []
        for key in key_list:
            try:
                item_id = get_item_id(token, host_id, key)
                data = get_latest_data(token, item_id, limit=20)
                values = [float(d['value']) for d in data]
                if not values:
                    continue
                max_val = max(values)
                warn_cnt = len([v for v in values if v > 80])
                crit_cnt = len([v for v in values if v > 95])

                pdf.set_font("NanumBold", size=11)
                pdf.cell(200, 10, txt=f"▶ {res_name}", ln=True)
                pdf.set_font("NanumBold", size=10)
                pdf.cell(200, 8, txt=f"  최대값: {max_val}", ln=True)
                pdf.cell(200, 8, txt=f"  경고 수: {warn_cnt}회, 위험 수: {crit_cnt}회", ln=True)
                img_path = f"static/{res_name.split()[0]}.png"
                if os.path.exists(img_path):
                    pdf.image(img_path, x=10, w=180)
                pdf.ln(3)
                break
            except:
                continue

    pdf.ln(5)
    pdf.set_font("NanumBold", size=12)
    pdf.cell(200, 10, txt="최근 알림 로그:", ln=True)
    pdf.set_font("NanumBold", size=10)
    logs = get_alert_logs(token, username)
    for log in logs:
        pdf.multi_cell(200, 8, f"- [{log['time']}] {log['message']}")

    output_path = f"report_{username}_{int(time.time())}.pdf"
    pdf.output(output_path)
    return output_path
