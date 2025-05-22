from flask import Flask, render_template

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

@app.route('/info_password')
def info_password():
    return render_template('user_info_password.html')

@app.route('/info_email')
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
