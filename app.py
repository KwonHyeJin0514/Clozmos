from flask import jsonify, Flask, render_template, request, redirect, url_for, session, flash
from zabbix_api import (
    get_auth_token, get_all_hosts, get_user_host, get_item_id, get_latest_data,
    get_user_info, update_user_field, validate_user_password, delete_user_account,
    get_alert_logs
)
from report_generator import generate_pdf_report
from email_sender import send_email_with_attachment
from translations import translations  # 추가

@app.context_processor
def inject_translator():
    def _(text):
        lang = session.get('lang', 'ko')
        return translations.get(lang, {}).get(text, text)
    return dict(_=_)

import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'

#다국어 지원 코드
@app.context_processor
def inject_translator():
    def _(text):
        lang = session.get('lang', 'ko')
        return translations.get(lang, {}).get(text, text)
    return dict(_=_)

#로그인 화면
@app.route('/')
def index():
    lang = session.get('lang','ko')
    return render_template('login.html', lang=session.get('lang', 'ko'))

#로그인 시도가 발생하면 데이터베이스와 비교
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    try:
        token = get_auth_token(username, password)
        user = get_user_info(token)
        session['lang'] = user.get('lang', 'ko')  # Zabbix 인증 토큰 획득
        host_names = [h['host'] for h in get_all_hosts(token)]
        if username not in host_names:
            raise Exception("입력된 이름에 해당하는 호스트가 존재하지 않습니다.")

        session['username'] = username
        session['auth_token'] = token
        session['is_admin'] = (username.lower() == 'admin')
        session['lang'] = get_user_info(token).get('lang','ko')
        return redirect(url_for('dashboard'))
    except:
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
    if 'auth_token' not in session:
        return redirect(url_for('index'))

    token = session['auth_token']
    is_admin = session.get('is_admin', False)
    username = session['username']

#관리자일 경우 호스트 선택 가능
    if is_admin:
        hosts = get_all_hosts(token)
        selected_host = request.args.get('host') or hosts[0]['host']
    else:
        selected_host = username

    return render_template('dashboard.html',
                           username=username,
                           is_admin=is_admin,
                           selected_host=selected_host,
                           hosts=get_all_hosts(token) if is_admin else [],
                           alerts=get_alert_logs(token, selected_host),
                           lang=session.get('lang', 'ko'))


#api가져와서 리소스 데이터 표시
@app.route('/api/data')
def api_data():
    try:
        token = session['auth_token']
        host = request.args.get('host') or session['username']
        host_id = get_user_host(token, host, return_id=True)

        session_resources = session.get('selected_resources') or []

        #리눅스 or 윈도우 모두 모니터링 가능한 리소스
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
                    result[metric] = {
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

#사용자 정보 페이지
@app.route('/user_info')
def user_info():
    token = session['auth_token']
    info = get_user_info(token)
    lang = session.get('lang','ko')
    return render_template('user_info.html', user=info, lang=session.get('lang', 'ko'))

#사용자 닉네임 수정
@app.route('/user_info_name', methods=['GET', 'POST'])
def user_info_name():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'alias', request.form['alias'])
        return redirect(url_for('user_info'))
    lang = session.get('lang','ko')
    return render_template('user_info_name.html', lang=session.get('lang', 'ko'))

#사용자 이메일 수정
@app.route('/user_info_email', methods=['GET', 'POST'])
def user_info_email():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'email', request.form['email'])
        return redirect(url_for('user_info'))
    lang = session.get('lang','ko')
    return render_template('user_info_email.html',lang=session.get('lang', 'ko')))

#사용자 언어 수정
@app.route('/user_info_language', methods=['GET', 'POST'])
def user_info_language():
    token = session['auth_token']
    if request.method == 'POST':
        new_lang = request.form['lang']
        update_user_field(token, 'lang', new_lang)
        session['lang'] = new_lang  # 세션에 반영
        return redirect(url_for('user_info'))
    return render_template('user_info_language.html', lang=session.get('lang', 'ko'))

#알림 수신 이메일 변경
@app.route('/user_info_alert', methods=['GET', 'POST'])
def user_info_alert():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        update_user_field(token, 'alert_email', request.form['alert_email'])
        return redirect(url_for('user_info'))
    return render_template('user_info_alert.html',lang=session.get('lang', 'ko'))

#비밀번호 변경
@app.route('/user_info_password', methods=['GET', 'POST'])
def user_info_password():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        current = request.form['current_pw']
        new1 = request.form['new_pw']
        new2 = request.form['new_pw2']
        if new1 != new2:
            flash("새 비밀번호가 일치하지 않습니다.")
        elif not validate_user_password(token, current):
            flash("현재 비밀번호가 틀렸습니다.")
        else:
            update_user_field(token, 'passwd', new1)
            flash("비밀번호가 변경되었습니다.")
        return redirect(url_for('user_info_password'))
    return render_template('user_info_password.html',lang=session.get('lang', 'ko'))

#계정 탈퇴
@app.route('/user_info_delete', methods=['GET', 'POST'])
def user_info_delete():
    token = session['auth_token']
    lang = session.get('lang','ko')
    if request.method == 'POST':
        delete_user_account(token)
        flash("계정이 삭제되었습니다.")
        return redirect(url_for('logout'))
    return render_template('user_info_delete.html',lang=session.get('lang', 'ko'))

#보고서 생성 및 이메일 전송
@app.route('/report', methods=['GET', 'POST'])
def report():
    lang = session.get('lang','ko')
    if request.method == 'POST':
        token = session.get('auth_token')
        username = session.get('username')
        start = request.form.get('start')
        email = request.form.get('email')
        end = time.strftime('%Y-%m-%d %H:%M:%S')

        if start == 'custom':
            start = request.form.get('start_custom')
            end = request.form.get('end_custom')

        try:
            selected_resources = session.get('selected_resources')
            pdf_path = generate_pdf_report(token, username, start, end, selected_resources)
            send_email_with_attachment(email, pdf_path)
            flash("PDF 보고서를 이메일로 전송했습니다.")
        except Exception as e:
            flash(f"오류 발생: {str(e)}")

        return redirect(url_for('report'))

    return render_template('report.html',lang=session.get('lang', 'ko'))

#리소스 선택 저장
@app.route('/manage', methods=['GET', 'POST'])
def manage():
    lang = session.get('lang','ko')
    if request.method == 'POST':
        session['selected_resources'] = request.form.getlist('resources')
        flash("설정이 저장되었습니다.")
        return redirect(url_for('dashboard'))
    return render_template('manage.html',lang=session.get('lang', 'ko'))

#서버 실행 (포트 5000, 외부 접속 허용)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
