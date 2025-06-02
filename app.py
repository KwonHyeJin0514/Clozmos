from flask import jsonify, Flask, render_template, request, redirect, url_for, session, flash, send_file
from zabbix_api import (
    get_auth_token, get_all_hosts, get_user_host, get_item_id, get_latest_data,
    get_user_info, update_user_field, validate_user_password, delete_user_account,
    get_alert_logs, create_zabbix_user
)

#자빅스와 연동하기 위해 만든 api 함수들
from report_generator import generate_pdf_report
from email_sender import send_email_with_attachment

#다국어 처리리
from translations import translations  # 추가
import time
import os
from flask import g


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
    def _(key):         #번역 함수 정의의
        return translations.get(lang, {}).get(key, key)
    return dict(_=_)        #_이라는 함수를 등록 => {'_': _}

#언어 설정값을 g.lang에 저장
@app.before_request
def set_lang():
    token = session.get('auth_token')
    if token:
        info = get_user_info(token)
        g.lang = info.get('lang', 'ko')
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
        if username not in host_names: #예외처리
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

#api가져와서 리소스 데이터 표시
@app.route('/api/data')
def api_data():
    try:
        token = session['auth_token']
        host = request.args.get('host') or session['username']
        host_id = get_user_host(token, host, return_id=True)

        session_resources = session.get('selected_resources') or []

        # 표시 이름 → 내부 키 매핑
        metric_key_map = {
            "CPU 평균 부하": "cpu_load",
            "CPU 사용률": "cpu_util",
            "사용 가능한 메모리": "mem_avail",
            "전체대비 메모리 사용률": "mem_util",
            "디스크 사용률": "disk",
            "네트워크 송수신 바이트수": "network",
            "패킷 손실율": "loss",
            "부팅 후 경과시간": "uptime",
            "중요 포트 오픈 여부": "port"
        }

        item_candidates = {
            "CPU 평균 부하": ["system.cpu.load[percpu,avg1]"],
            "CPU 사용률": ["system.cpu.util[,user]", "system.cpu.util"],
            "사용 가능한 메모리": ["vm.memory.size[available]"],
            "전체대비 메모리 사용률": ["vm.memory.util"],
            "디스크 사용률": ["vfs.fs.size[/,pused]", "vfs.fs.size[C:,pused]"],
            "네트워크 송수신 바이트수": ["net.if.in[eth0]", "net.if.out[eth0]", "net.if.in[Ethernet]", "net.if.out[Ethernet]"],
            "패킷 손실율": ["net.if.loss[eth0]", "net.if.loss[Ethernet]"],
            "부팅 후 경과시간": ["system.uptime"],
            "중요 포트 오픈 여부": ["net.tcp.listen[22]", "net.tcp.listen[3389]"]
        }

        result = {}

        for metric, keys in item_candidates.items():
            if session_resources and metric not in session_resources:
                continue

            for key in keys:
                try:
                    item_id = get_item_id(token, host_id, key)
                    data = get_latest_data(token, item_id)
                    key_name = metric_key_map[metric]
                    result[key_name] = {
                        "timestamps": [time.strftime('%H:%M:%S', time.localtime(int(d['clock']))) for d in data],
                        "values": [float(d['value']) for d in data]
                    }
                    break
                except:
                    continue

        return jsonify(result)

    except Exception as e:
        print("[API ERROR]", str(e))
        return jsonify({"error": str(e)}), 500
    

#리소스 선택 저장
@app.route('/manage', methods=['GET', 'POST'])
def manage():
    lang = session.get('lang','ko')
    if request.method == 'POST':
        session['selected_resources'] = request.form.getlist('resources')
        
        #threshold 값 저장. (임계치)
        thresholds = {}
        for i, resource in enumerate([
            "CPU 평균 부하", "CPU 사용률", "사용 가능한 메모리", "전체대비 메모리 사용률",
            "디스크 사용률", "네트워크 송수신 바이트수", "패킷 손실율", "부팅 후 경과시간", "중요 포트 오픈 여부"
        ]):
            warn_key = f'warning_{i}'
            crit_key = f'critical_{i}'
            thresholds[resource] = {
                'warn': request.form.get(warn_key, ''),
                'crit': request.form.get(crit_key, '')
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
    return render_template('user_info.html'
                           , email = info.get('email')
                           , username=info.get('name') or info.get('alias')
                           ,lang=lang)

#사용자 닉네임 수정
@app.route('/user_info_name', methods=['GET', 'POST'])
def user_info_name():
    token = session['auth_token']
    if request.method == 'POST': #폼 제출 시 post 요청이 들어오면 실행행
        update_user_field(token, 'name', request.form['alias'])  #from = 새 닉네임,  field 함수는 실제 zabbix 서버에 반영하는 역할할
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

#tranlations를 전역으로
@app.context_processor
def inject_translations():
    from translations import translations
    return dict(translations=translations)

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

#보고서 생성 및 이메일 전송
@app.route('/report', methods=['GET', 'POST'])
def report():
    lang = session.get('lang', 'ko')
    if request.method == 'POST':
        token = session.get('auth_token')
        username = session.get('username')
        start = request.form.get('start')
        email = request.form.get('email')
        end = time.strftime('%Y-%m-%d %H:%M:%S')
        action = request.form.get('action')

        if start == 'custom':
            start = request.form.get('start_custom')
            end = request.form.get('end_custom')

        if action == "preview":
            preview = f"{username}님의 보고서 (기간: {start} ~ {end})\n리소스 그래프, 최대치, 로그 요약 포함"
            return render_template("report.html", preview=preview ,lang=lang)

        try:
            selected_resources = session.get('selected_resources')
            pdf_path = generate_pdf_report(token, username, start, end, selected_resources)
            
            additional_files = ["static/help_guide.pdf", "static/notice.txt"]
            attachments = [pdf_path] + [f for f in additional_files if os.path.exists(f)]
            
            send_email_with_attachment(
        to_email=email,
        file_paths=attachments,
        subject="📊 Zabbix 모니터링 보고서",
        body=f"""{username}님,

요청하신 리소스 사용률 보고서를 첨부해드립니다.

📆 기간: {start} ~ {end}
📎 첨부: PDF 보고서 및 안내자료

감사합니다.
"""
    )
            
            flash("PDF 보고서를 이메일로 전송했습니다.")
        except Exception as e:
            flash(f"오류 발생: {str(e)}")

        return redirect(url_for('report'))

    return render_template('report.html', lang=lang)


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
echo Server={ZABBIX_SERVER_IP}>> "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf"
echo Hostname={username}>> "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf"
echo HostMetadata=zabbix_agent>> "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf"
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
