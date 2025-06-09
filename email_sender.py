import smtplib
from email.message import EmailMessage
import os

def send_email_with_attachment(to_email, file_paths, subject="리소스 보고서", body="첨부 파일을 확인해주세요."):
    
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "@gmail.com"
    msg["To"] = to_email
    msg.set_content(body)

    if isinstance(file_paths, str):
        file_paths = [file_paths]

    for path in file_paths:
        if not os.path.exists(path):
            continue
        with open(path, 'rb') as f:
            filename = os.path.basename(path)
            msg.add_attachment(f.read(), maintype='application', subtype='octet-stream', filename=filename)

    # 외부 SMTP 서버 접속 (Gmail 기준)
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "clozmos@gmail.com"
    smtp_password = "gmuz nzhz jeag dggd"

    with smtplib.SMTP(smtp_server, smtp_port) as smtp:
        smtp.starttls()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(msg)

