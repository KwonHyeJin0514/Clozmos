from flask import jsonify, Flask, render_template, request, redirect, url_for, session, flash, send_file
from zabbix_api import (
    get_auth_token, get_all_hosts, get_user_host, get_item_id, get_latest_data,
    get_user_info, update_user_field, validate_user_password, delete_user_account,
    get_alert_logs, create_zabbix_user, get_historical_data, get_item_info
)
#자빅스와 연동하기 위해 만든 api 함수들
from report_generator import generate_pdf_report
from email_sender import send_email_with_attachment

#다국어 처리리
from translations import translations  # 추가
import time
import os
from flask import g
from datetime import datetime, timedelta
import traceback
import pytz


app = Flask(__name__)

#session 보안을 위하여 비밀키 설정
app.secret_key = 'secret_key'

ZABBIX_SERVER_IP = "172.29.109.42"
ZABBIX_ADMIN_ID = "Admin"
ZABBIX_ADMIN_PW = "zabbix"


#다국어 지원 코드
#번역키를 호출함
@app.context_processor
def inject_translations():
    #현재 언어를 가져오기 (없으면 한국어 기본)
    lang = getattr(g, 'lang', 'ko')
    def _(key):         #번역 함수 정의
        return translations.get(lang, {}).get(key, key)
    return dict(_=_)        #_이라는 함수를 등록 => {'_': _}

#언어 설정값을 g.lang에 저장
@app.before_request
def set_lang():
    token = session.get('auth_token')
    
    if token:
        info = get_user_info(token)
        
        lang = info.get('lang', 'ko')
        g.lang = lang.split('_')[0]
    else:
        g.lang = 'ko'

#로그인 화면
@app.route('/')
def index():
    lang = session.get('lang','ko')
    return render_template('login.html',lang=lang)

#로그인 시도가 발생하면 자빅스 api 로그인. 호스트명으로 비교하여 검증하면 session 저장
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'] #사용자의 아이디
    password = request.form['password'] #사용자의 비밀번호
    try:
        #사용자가 입력한 정보로 zabbix api에 로그인 요청 -> token을 받음
        token = get_auth_token(username, password)  # Zabbix 인증 토큰 획득
        print("로그인성공 토큰:",token)
        user = get_user_info(token)         #사용자 정보 가져오기
        session['lang'] = user.get('lang', 'ko')  #계정에 저장된 언어를 lang에 저장
        host_names = [h['host'] for h in get_all_hosts(token)] #호스트 목록 확인
        if not (username.lower()=='admin') and username not in host_names: #예외처리
            raise Exception("입력된 이름에 해당하는 호스트가 존재하지 않습니다.")

        session['username'] = username  #로그인 이름
        session['auth_token'] = token   #zabbix api 인증 토큰
        session['is_admin'] = (username.lower() == 'admin')     #관리자 확인
        
        info = get_user_info(token)
        if not info.get('name'):
            update_user_field(token, 'name', username)
        return redirect(url_for('dashboard'))
    except Exception as e:
        #로그인이 실패하면 다시 시도하게 함.
        print("로그인 실패",str(e))
        flash("로그인 실패. 호스트명 또는 비밀번호를 확인하세요.")
        return redirect(url_for('index'))

#로그아웃 하기
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#대시보드 띄우기
@app.route('/dashboard')
def dashboard():
    #받아온 auth_token의 세션이 만료되거나 없다면 로그인으로 다시 돌아감
    if 'auth_token' not in session:
        return redirect(url_for('index'))

    #기본 정보 불러오기
    token = session['auth_token']   #api 호출에 사용할 인증 토큰
    is_admin = session.get('is_admin', False) #관리자의 여부

    #로그인한게 관리자라면 호스트 선택 가능
    if is_admin:
        hosts = get_all_hosts(token) #zabbix에 있는 모든 호스트를 가져옴.
        #드롭다운에서 선택한 사용자가 보이도록 함.
        selected_host = request.args.get('host') or hosts[0]['host']
    #로그인한게 일반 사용자라면
    else:
        try:
            selected_host = get_user_host(token, session['username'])
        except Exception:
            flash("호스트를 찾을 수 없습니다")
            return redirect(url_for('logout'))
            
        
    #name 필드 가져오기 (없으면 username 사용)
    info = get_user_info(token)
    display_name = info.get('name') or session['username']
    
    
    
    #대시보드의 템플릿을 브라우저에 보여줌. 
    return render_template('dashboard.html',
                           username=display_name,
                           is_admin=is_admin,
                           selected_host=selected_host,
                           hosts=get_all_hosts(token) if is_admin else [],
                           alerts=get_alert_logs(token, selected_host),
                           lang=session.get('lang', 'ko'))
    #템플릿에서 사용할 수 있도록 변수로 넘겨주기기

#api가져와서 실시간 리소스 데이터 시각화. 데이터 수집후 JSON 형태로 반환
@app.route('/api/data')  #/api/data 경로로 http 요청이 들어왔을때 실행
def api_data():
    try: #예외 발생 대비
        token = session['auth_token'] #현재 로그인 된 사용자의 인증 토큰을 세션에서 가져옴
        host = request.args.get('host') or session['username'] 
        #요청 파라미터에 host 값이 있으면 그걸 사용하고, 없으면 로그인한 사용자 이름을 호스트 이름으로 사용.
        
        #해당 호스트 id를 zabbix api로부터 가져옴
        host_id = get_user_host(token, host, return_id=True)

        #사용자가 /manage 페이지에서 리소스 목록을 세션에서 가져옴. 없으면 빈 리스트
        session_resources = session.get('selected_resources') or []
        print("[선택된 리소스]", session_resources)

        # 시각화 키 이름 매핑
        metric_key_map = {
            "CPU 평균 부하": "cpu_load",
            "CPU 사용률": "cpu_util",
            "전체대비 메모리 사용률": "mem_util",
            "디스크 사용률": "disk",
            "네트워크 송수신 바이트수": "network",
            "패킷 손실율": "loss"
        }

        # 운영체제별 item key 후보들
        item_candidates = {
            "CPU 평균 부하": [
                'perf_counter_en["\\Processor Information(_total)\\% User Time"]',
                'perf_counter_en["\\Processor Information(_total)\\% Privileged Time"]'
            ],
            "CPU 사용률": [
                "system.cpu.util"
            ],
            "전체대비 메모리 사용률": [
                "vm.memory.util"
            ],
            "디스크 사용률": [
                'perf_counter_en["\Paging file(_Total)\% Usage"]'        # Windows
            ],
            "네트워크 송수신 바이트수": [
                'net.if.total["이더넷"]'      # Windows
            ],
            "패킷 손실율": [
                'icmppingloss["172.29.109.194"]'
            ]
        }
        

        result = {}

        for metric, keys in item_candidates.items():
            if session_resources and metric not in session_resources:
                print(f"[건너뜀] {metric}")
                continue

            for key in keys:
                try:
                    item_id = get_item_id(token, host_id, key)
                    data = get_latest_data(token, item_id)
                    
                    key_name = metric_key_map.get(metric)
                    if not key_name:
                        continue

                    result[key_name] = {
                        "timestamps": [
                                    datetime.fromtimestamp(int(d['clock']), tz=pytz.utc) # UTC 타임스탬프 로드
                                    .astimezone(pytz.timezone('Asia/Seoul'))              # KST (한국 시간)로 변환
                                    .strftime('%H:%M:%S')                                # 원하는 형식으로 포맷
                                    for d in data
                                ],                        
                        "values": [float(d['value']) for d in data]
                    }
                    break
                except Exception as e:
                    print(f"[수집 실패] {metric} - {key}: {e}")
                    continue

        return jsonify(result)

    except Exception as e:
        print("[API ERROR]", str(e))
        return jsonify({"error": str(e)}), 500

# app.py (기존 /api/data 라우트 이후에 추가)

@app.route('/api/report_data', methods=['GET'])
def api_report_data():
    try:
        token = session['auth_token']
        username = session['username']
        
        # ⚠️ report.html에서 GET 파라미터로 받은 YYYY-MM-DDTHH:MM 형식의 시간
        start_date_raw = request.args.get('start_date') 
        end_date_raw = request.args.get('end_date')

        # KST 시간대 정의
        kst = pytz.timezone('Asia/Seoul')
        DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
        
        # 날짜 문자열을 KST 기반 Unix Timestamp로 변환
        start_dt_kst = kst.localize(datetime.strptime(start_date_raw, DATE_FORMAT))
        end_dt_kst = kst.localize(datetime.strptime(end_date_raw, DATE_FORMAT))
        time_from = int(start_dt_kst.timestamp())
        time_till = int(end_dt_kst.timestamp())
        
        # report_generator.py와 동일한 Item Key 맵 사용 (멀티 플랫폼 호환성 확보)
        resource_items = {
            "CPU 평균 부하": [ 'system.cpu.load[all,avg1]', 'perf_counter_en["\\Processor Information(_total)\\% User Time"]' ],
            "CPU 사용률": ["system.cpu.util"],
            "전체대비 메모리 사용률": ["vm.memory.util"],
            "디스크 사용률": [ 'vfs.fs.size[/,pused]', 'perf_counter_en["\Paging file(_Total)\\% Usage"]' ],
            "네트워크 송수신 바이트수": [ 'net.if.in[eth0]', 'net.if.out[eth0]' ],
            "패킷 손실율": ['icmppingloss["172.29.109.194"]']
        }

        result_data = {}

        # ⚠️ 세션에 저장된 선택 리소스 사용
        selected_resources = session.get('selected_resources') or resource_items.keys() 
        
        for res_name, key_list in resource_items.items():
            if res_name not in selected_resources:
                continue

            for key in key_list:
                data = get_historical_data(token, username, key, time_from, time_till)
                
                if data:
                    # 데이터 포인트가 많을 경우, JSON 직렬화에 시간이 오래 걸리거나 너무 커질 수 있음
                    # 여기서는 모든 데이터를 반환하는 것으로 가정합니다.
                    timestamps = [
                        datetime.fromtimestamp(int(d['clock'])).astimezone(kst).strftime('%Y-%m-%d %H:%M:%S') 
                        for d in data
                    ]
                    values = [float(d['value']) for d in data]

                    result_data[res_name] = {
                        "timestamps": timestamps,
                        "values": values
                    }
                    break # 유효한 데이터를 찾으면 다음 리소스로 이동

        return jsonify(result_data)

    except Exception as e:
        print("[API REPORT DATA ERROR]", str(e))
        traceback.print_exc()
        return jsonify({"error": f"데이터 로드 실패: {str(e)}", "detail": traceback.format_exc()}), 500

#리소스 선택 저장
@app.route('/manage', methods=['GET', 'POST'])
def manage():
    lang = session.get('lang','ko')
    if request.method == 'POST':
        session['selected_resources'] = request.form.getlist('resources')
        
        # threshold 값 저장 (입력 없으면 기본값 적용)
        default_thresholds = {
            "CPU 평균 부하": {"warn": 2.0, "crit": 5.0},
            "CPU 사용률": {"warn": 60, "crit": 75},
            "전체대비 메모리 사용률": {"warn": 85, "crit": 95},
            "디스크 사용률": {"warn": 80, "crit": 95},
            "네트워크 송수신 바이트수": {"warn": 10000, "crit": 20000},
            "패킷 손실율": {"warn": 10, "crit": 30}
        }

        thresholds = {}
        for i, resource in enumerate(default_thresholds.keys()):
        
            warn_key = f'warning_{i}'
            crit_key = f'critical_{i}'
            
            warn_input= request.form.get(warn_key)
            crit_input= request.form.get(crit_key)
                
            default_warn = default_thresholds[resource]['warn']
            default_crit = default_thresholds[resource]['crit']

            thresholds[resource] = {
                'warn': float(warn_input) if warn_input else default_warn,
                'crit': float(crit_input) if crit_input else default_crit

            }

        session['thresholds'] = thresholds
        
        
        flash("설정이 저장되었습니다.")
        return redirect(url_for('dashboard'))
    return render_template('manage.html',lang=lang)


#사용자 정보 페이지
@app.route('/user_info')
def user_info():
    token = session['auth_token']
    info = get_user_info(token)
    lang = session.get('lang','ko')
    
    email = "등록되지 않음"
    medias = info.get('medias') or info.get('user_medias')
    if medias and isinstance(medias, list) and len(medias) > 0:
        email = medias[0].get('sendto', '등록되지 않음')
    
    return render_template('user_info.html'
                           , email = email
                           , username=info.get('name') or info.get('username')
                           , lang=lang)

#사용자 닉네임 수정
@app.route('/user_info_name', methods=['GET', 'POST'])
def user_info_name():
    token = session['auth_token']
    if request.method == 'POST': #폼 제출 시 post 요청이 들어오면 실행행
        update_user_field(token, 'name', request.form['username'])  #from = 새 닉네임,  field 함수는 실제 zabbix 서버에 반영하는 역할할
        return redirect(url_for('user_info'))  #변경이 완료되면 사용자 정보 페이지로 리다이렉트함.
    lang = session.get('lang','ko')
    return render_template('user_info_name.html',lang=lang)

#사용자 이메일 수정
@app.route('/user_info_email', methods=['GET', 'POST'])
def user_info_email():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'email', request.form['email'])
        return redirect(url_for('user_info'))
    lang = session.get('lang','ko')
    return render_template('user_info_email.html',lang=lang)

#사용자 언어 수정
@app.route('/user_info_language', methods=['GET', 'POST'])
def user_info_language():
    token = session['auth_token']
    user = get_user_info(token)
    lang = user.get('lang','ko')
    if request.method == 'POST':
        new_lang = request.form['language']
        update_user_field(token, 'lang', new_lang)
        session['lang'] = new_lang  # 세션에 반영
        return redirect(url_for('user_info'))
    return render_template('user_info_language.html',lang=lang)

#알림 수신 이메일 변경
@app.route('/user_info_alert', methods=['GET', 'POST'])
def user_info_alert():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        update_user_field(token, 'alert_email', request.form['alert_email'])
        return redirect(url_for('user_info'))
    return render_template('user_info_alert.html',lang=lang)

#비밀번호 변경
@app.route('/user_info_password', methods=['GET', 'POST'])
def user_info_password():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        current = request.form['current_password']
        new1 = request.form['new_password']
        new2 = request.form['confirm_password']
        if new1 != new2:
            flash("새 비밀번호가 일치하지 않습니다.")
        elif not validate_user_password(token, current):
            flash("현재 비밀번호가 틀렸습니다.")
        else:
            update_user_field(token, 'passwd', new1)
            flash("비밀번호가 변경되었습니다.")
        return redirect(url_for('user_info_password'))
    return render_template('user_info_password.html',lang=lang)

#계정 탈퇴
@app.route('/user_info_delete', methods=['GET', 'POST'])
def user_info_delete():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        delete_user_account(token)
        flash("계정이 삭제되었습니다.")
        return redirect(url_for('logout'))
    return render_template('user_info_delete.html',lang=lang)

# app.py의 기존 @app.route('/report', methods=['GET', 'POST']) 함수를 대체

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'auth_token' not in session:
        return redirect(url_for('index'))
    
    token = session['auth_token']
    username = session['username']
    kst = pytz.timezone('Asia/Seoul')
    DATE_FORMAT_API = '%Y-%m-%d %H:%M:%S'
    DATE_FORMAT_HTML = '%Y-%m-%dT%H:%M'
    
    context = {
        'lang': session.get('lang', 'ko'),
        'entered_email': '',
        'selected_start': '-24h',
        'start_custom': '',
        'end_custom': ''
    }
    
    # ----------------------------------------------------
    # POST 요청 처리 (보고서 전송)
    # ----------------------------------------------------
    if request.method == 'POST':
        action = request.form.get('action') # 'send'만 처리
        selected_period = request.form.get('start', '-24h')
        entered_email = request.form.get('email')
        
        # report.html에서 체크박스를 통해 선택된 리소스 목록
        selected_resources = request.form.getlist('resources')
        # 세션에 선택된 리소스 저장 (GET API에서 사용)
        session['selected_resources'] = selected_resources 

        context.update({'entered_email': entered_email, 'selected_start': selected_period})
        
        start_time_str = None
        end_time_str = None

        # 1. 기간 설정 및 시간 문자열 변환 (PDF 생성 함수에 전달할 형식)
        if selected_period == 'custom':
            # report.html에서 datetime-local 포맷 (YYYY-MM-DDTHH:MM)으로 넘어옴
            start_time_raw = request.form.get('start_custom')
            end_time_raw = request.form.get('end_custom')
            
            # API 호출 형식 (YYYY-MM-DD HH:MM:SS)으로 변환
            if start_time_raw and end_time_raw:
                start_time_str = start_time_raw.replace('T', ' ') + ':00'
                end_time_str = end_time_raw.replace('T', ' ') + ':00'
                context.update({'start_custom': start_time_raw, 'end_custom': end_time_raw})
            else:
                flash("커스텀 기간을 모두 입력해야 합니다.", 'error')
                return render_template('report.html', **context)
                
        else: # -1h 또는 -24h
            now_kst = datetime.now(kst)
            end_dt = now_kst
            
            if selected_period == '-1h':
                start_dt = now_kst - timedelta(hours=1)
            else: # -24h
                start_dt = now_kst - timedelta(hours=24)
            
            # PDF 함수에 전달할 형식 (KST 기준)
            start_time_str = start_dt.strftime(DATE_FORMAT_API)
            end_time_str = end_dt.strftime(DATE_FORMAT_API)

        # 2. 전송 (Send) 액션 처리
        if action == 'send':
            pdf_path = None
            try:
                # PDF 생성 및 그래프 포함 (report_generator.py에서 처리)
                pdf_path = generate_pdf_report(token, username, start_time_str, end_time_str, selected_resources)
                
                additional_files = ["static/help_guide.pdf", "static/notice.txt"]
                attachments = [pdf_path] + [f for f in additional_files if os.path.exists(f)]

                send_email_with_attachment(
                    to_email=entered_email,
                    file_paths=attachments,
                    subject=" Zabbix 모니터링 보고서",
                    body=f"""{username}님,
요청하신 리소스 사용률 보고서를 첨부해드립니다.
기간: {start_time_str} ~ {end_time_str}
첨부: PDF 보고서 및 안내자료

감사합니다.
""")
                flash(f"PDF 보고서를 {entered_email}로 성공적으로 전송했습니다.", 'success')
                
            except Exception as e:
                traceback.print_exc()
                flash(f"보고서 생성/전송 중 오류 발생: {e}", 'error')
            finally:
                # 서버에 생성된 임시 PDF 파일 삭제
                if pdf_path and os.path.exists(pdf_path):
                    os.remove(pdf_path)
            
            return redirect(url_for('report'))
    
    # ----------------------------------------------------
    # GET 요청 처리 (페이지 로드)
    # ----------------------------------------------------
    
    # 기본값으로 24시간 전 시간을 datetime-local 형식으로 context에 넣어줍니다.
    now_kst = datetime.now(kst)
    start_dt_default = now_kst - timedelta(hours=24)
    context.update({
        'start_custom': start_dt_default.strftime(DATE_FORMAT_HTML),
        'end_custom': now_kst.strftime(DATE_FORMAT_HTML)
    })

    # 사용자 등록 이메일 기본값으로 설정
    user_info = get_user_info(token)
    email = None
    medias = user_info.get('medias') or user_info.get('user_medias')
    if medias and isinstance(medias, list) and len(medias) > 0:
        raw = medias[0].get('sendto')
        # Zabbix 미디어 정보에서 이메일 추출
        email = raw[0] if isinstance(raw, list) and raw else raw 
    
    context['entered_email'] = context['entered_email'] or email or ''
    
    return render_template('report.html', **context)

#회원가입 페이지 + 설치파일 생성
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        os_type = request.form['os_type']

        try:
            admin_token = get_auth_token(ZABBIX_ADMIN_ID, ZABBIX_ADMIN_PW)
            create_zabbix_user(admin_token, username, password, email)
        except Exception as e:
            flash(f"Zabbix 사용자 생성 실패: {str(e)}")
            return redirect(url_for('register'))

        timestamp = int(time.time())
        if os_type == 'linux':
            path = f"/tmp/install_{username}_{timestamp}.sh"
            with open(path, 'w') as f:
                f.write(f"""#!/bin/bash
                    sudo apt update
                    sudo apt install zabbix-agent -y
                    sudo sed -i 's/^Server=.*/Server={ZABBIX_SERVER_IP}/' /etc/zabbix/zabbix_agentd.conf
                    sudo sed -i 's/^Hostname=.*/Hostname={username}/' /etc/zabbix/zabbix_agentd.conf
                    sudo sed -i 's/^# HostMetadata=.*/HostMetadata=zabbix_agent/' /etc/zabbix/zabbix_agentd.conf
                    sudo systemctl enable zabbix-agent
                    sudo systemctl restart zabbix-agent
                    """)
            os.chmod(path, 0o755)
        else:
            path = f"/tmp/install_{username}_{timestamp}.bat"
            with open(path, 'w') as f:
                f.write(f"""@echo off
                    msiexec /i https://cdn.zabbix.com/zabbix/binaries/stable/6.0/6.0.20/zabbix_agent-6.0.20-windows-amd64-openssl.msi /quiet
                    timeout 10
                    powershell -Command "(Get-Content 'C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf') -replace '^Server=.*', 'Server={ZABBIX_SERVER_IP}' | Set-Content 'C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf'"
                    powershell -Command "(Add-Content 'C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf' 'Hostname={username}')"
                    powershell -Command "(Add-Content 'C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf' 'HostMetadata=zabbix_agent')"
                    net start "Zabbix Agent"
                    """)

        flash("계정이 생성되었습니다. 설치 파일을 다운로드하세요.")
        return render_template('register_done.html', username=username, os_type=os_type, timestamp=timestamp)

    return render_template('register.html')

#설치 파일 다운로드
@app.route('/download/agent/<os_type>/<username>/<timestamp>')
def download_agent_script(os_type, username, timestamp):
    ext = 'sh' if os_type == 'linux' else 'bat'
    path = f"/tmp/install_{username}_{timestamp}.{ext}"
    return send_file(path, as_attachment=True)

#서버 실행 (포트 5000, 외부 접속 허용)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
