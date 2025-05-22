import smtplib
from email.message import EmailMessage
import os

def send_email_with_attachment(to_email, file_path):
    msg = EmailMessage()
    msg["Subject"] = "Zabbix 리소스 보고서"
    msg["From"] = "your-email@example.com"
    msg["To"] = to_email
    msg.set_content("첨부된 PDF 보고서를 확인해 주세요.")

    with open(file_path, 'rb') as f:
        msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=os.path.basename(file_path))

    # SMTP 설정: Gmail 예시
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login("your-email@example.com", "your-app-password")
        smtp.send_message(msg)
