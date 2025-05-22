from flask import jsonify, Flask, render_template, request, redirect, url_for, session, flash
from zabbix_api import (
    get_auth_token, get_all_hosts, get_user_host, get_item_id, get_latest_data,
    get_user_info, update_user_field, validate_user_password, delete_user_account,
    get_alert_logs
)
from report_generator import generate_pdf_report
from email_sender import send_email_with_attachment
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    try:
        token = get_auth_token(username, password)
        session['username'] = username
        session['auth_token'] = token
        session['is_admin'] = (username.lower() == 'admin')
        return redirect(url_for('dashboard'))
    except:
        flash("로그인 실패. 사용자명 또는 비밀번호를 확인하세요.")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'auth_token' not in session:
        return redirect(url_for('index'))

    token = session['auth_token']
    is_admin = session.get('is_admin', False)

    if is_admin:
        hosts = get_all_hosts(token)
        selected_host = request.args.get('host') or hosts[0]['host']
    else:
        selected_host = get_user_host(token, session['username'])

    return render_template('dashboard.html',
                           username=session['username'],
                           is_admin=is_admin,
                           selected_host=selected_host,
                           hosts=get_all_hosts(token) if is_admin else [],
                           alerts=get_alert_logs(token, selected_host))

@app.route('/api/data')
def api_data():
    try:
        token = session['auth_token']
        host = request.args.get('host') or get_user_host(token, session['username'])
        host_id = get_user_host(token, host, return_id=True)

        # 키 후보 리스트 (순차적으로 시도)
        item_candidates = {
            "cpu": [
                "system.cpu.util[,user]",     # Linux
                "system.cpu.util"            # Windows
            ],
            "memory": [
                "vm.memory.size[available]",
                "vm.memory.util"
            ]
        }

        result = {}

        for metric, candidates in item_candidates.items():
            found = False
            for key in candidates:
                try:
                    item_id = get_item_id(token, host_id, key)
                    data = get_latest_data(token, item_id)
                    result[metric] = {
                        "timestamps": [time.strftime('%H:%M:%S', time.localtime(int(d['clock']))) for d in data],
                        "values": [float(d['value']) for d in data]
                    }
                    found = True
                    break  # 첫 번째 성공한 키로 고정
                except Exception as e:
                    continue
            if not found:
                raise Exception(f"{metric.upper()} 관련 키를 찾을 수 없습니다.")

        return jsonify(result)

    except Exception as e:
        print("[API ERROR]", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/user_info')
def user_info():
    token = session['auth_token']
    info = get_user_info(token)
    return render_template('user_info.html', user=info)

@app.route('/user_info_name', methods=['GET', 'POST'])
def user_info_name():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'alias', request.form['alias'])
        return redirect(url_for('user_info'))
    return render_template('user_info_name.html')

@app.route('/user_info_email', methods=['GET', 'POST'])
def user_info_email():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'email', request.form['email'])
        return redirect(url_for('user_info'))
    return render_template('user_info_email.html')

@app.route('/user_info_language', methods=['GET', 'POST'])
def user_info_language():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'lang', request.form['lang'])
        return redirect(url_for('user_info'))
    return render_template('user_info_language.html')

@app.route('/user_info_alert', methods=['GET', 'POST'])
def user_info_alert():
    token = session['auth_token']
    if request.method == 'POST':
        update_user_field(token, 'alert_email', request.form['alert_email'])
        return redirect(url_for('user_info'))
    return render_template('user_info_alert.html')

@app.route('/user_info_password', methods=['GET', 'POST'])
def user_info_password():
    token = session['auth_token']
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
    return render_template('user_info_password.html')


@app.route('/report', methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        token = session.get('auth_token')
        username = session.get('username')
        start = request.form.get('start')
        email = request.form.get('email')

        # 사용자 지정일 경우, 별도 입력값 사용
        if start == "custom":
            start = request.form.get('start_custom')
            end = request.form.get('end_custom')
        else:
            # 기본 기간이면 end는 현재 시간
            end = time.strftime('%Y-%m-%d %H:%M:%S')

        if not (start and end and email):
            flash("기간과 이메일을 정확히 입력해주세요.")
            return redirect(url_for('report'))

        try:
            pdf_path = generate_pdf_report(token, username, start, end)
            send_email_with_attachment(email, pdf_path)
            flash("PDF 보고서를 이메일로 전송했습니다.")
        except Exception as e:
            flash(f"오류 발생: {str(e)}")

        return redirect(url_for('report'))

    return render_template('report.html')




@app.route('/manage', methods=['GET', 'POST'])
def manage():
    if request.method == 'POST':
        session['dashboard_count'] = int(request.form['count'])
        session['thresholds'] = request.form.to_dict()
        return redirect(url_for('dashboard'))
    return render_template('manage.html')

# ✅ 포트 5000 열림 및 외부 접속 허용
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
