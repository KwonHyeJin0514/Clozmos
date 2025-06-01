import smtplib
from email.message import EmailMessage
import os

def send_email_with_attachment(to_email, file_paths, subject="리소스 보고서", body="첨부 파일을 확인해주세요."):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "zabbix@localhost"  # Zabbix 서버에서 정의된 발신 이메일
    msg["To"] = to_email
    msg.set_content(body)

    # 단일 파일일 경우 리스트로 변환
    if isinstance(file_paths, str):
        file_paths = [file_paths]

    for path in file_paths:
        if not os.path.exists(path):
            continue
        with open(path, 'rb') as f:
            filename = os.path.basename(path)
            msg.add_attachment(
                f.read(),
                maintype='application',
                subtype='octet-stream',
                filename=filename
            )

    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)
