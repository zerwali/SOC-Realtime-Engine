import smtplib
from email.message import EmailMessage

def send_email_notification(receiver_email, subject, body):
    sender_email = "pycomp47@gmail.com"
    sender_password = "kvhq wbkr asji ignz"  # Not your Gmail password

    # Build the email
    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    # Connect to Gmail SMTP and send
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.send_message(msg)

    print(f"Email sent successfully!")
    
