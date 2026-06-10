import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Tuple


def send_email_notification(to_address: str, subject: str, body: str) -> Tuple[bool, str]:
    """Send a simple SMTP email notification.

    Uses environment variables:
    - SMTP_HOST
    - SMTP_PORT
    - SMTP_USER
    - SMTP_PASSWORD
    - FROM_EMAIL
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("FROM_EMAIL") or smtp_user

    if not smtp_user or not smtp_password or not from_email:
        return False, "SMTP is not configured. Set SMTP_USER, SMTP_PASSWORD, and optionally FROM_EMAIL."

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = to_address
    message.set_content(body)

    try:
        if smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10, context=context) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(message)
        else:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(smtp_user, smtp_password)
                server.send_message(message)
    except Exception as exc:
        return False, f"SMTP send failed: {exc}"

    return True, "Email notification sent successfully."
