
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.utils import SENDER_EMAIL,SMTP_SERVER,SMTP_PORT,SENDER_PASSWORD



def send_otp_to_user(email: str, otp: str):
    try:
        subject = "Your OTP Code"
        body = f"Your OTP code is: {otp}"

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls() 
            server.login(SENDER_EMAIL, SENDER_PASSWORD)  
            text = msg.as_string() 
            server.sendmail(SENDER_EMAIL, email, text) 

        print(f"OTP sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")