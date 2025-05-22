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

@app.route('/')
def home():
    return 'HTML 테스트를 위한 라우트입니다.'

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/user_settings')
def setting():
    return render_template('user_settings.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/admin_feedback')
def admin_feedback():
    return render_template('admin_feedback.html')

@app.route('/user_info_password')
def info_password():
    return render_template('user_info_password.html')

@app.route('/user_info_email')
def info_email():
    return render_template('user_info_email.html')

@app.route('/user_info_language')
def user_info_language():
    return render_template('user_info_language.html')

@app.route('/user_info_delete')
def user_info_delete():
    return render_template('user_info_delete.html')

@app.route('/user_info')
def user_info():
    return render_template('user_info.html')

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/report_generator')
def report_generator():
    return render_template('report_generator.html')

@app.route('/email_sender')
def email_sender():
    return render_template('email_sender.html')

@app.route('/user_info_name')
def user_info_name():
    return render_template('user_info_name.html')

@app.route('/user_info_alert')
def user_info_alert():
    return render_template('user_info_alert.html')

@app.route('/manage', methods=['GET', 'POST'])
def manage():
    if request.method == 'POST':
        selected = request.form.getlist('resources')
        thresholds = []

        for i, res in enumerate(selected):
            warn = request.form.get(f'warning_{i}')
            crit = request.form.get(f'critical_{i}')
            thresholds.append({
                "resource": res,
                "warning": float(warn) if warn else "default",
                "critical": float(crit) if crit else "default"
            })

        # 여기서 thresholds 리스트를 저장하거나 처리하는 코드를 작성
        print(thresholds)  # 디버깅용
        flash("설정이 저장되었습니다.")
        return redirect(url_for('manage'))

    # GET 요청 시에 템플릿 렌더링
    return render_template('manage.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
