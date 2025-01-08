from src.models import UserRegistration
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException,APIRouter
from pydantic import BaseModel
from src.controllers.verification import send_otp_to_user
from src.utils import cache,collection,auth_s

router=APIRouter()

@router.post("/verify/",response_model=dict)
async def verify_otp(user: UserRegistration):
   
    
    print(user)
    cached_otp = await cache.get(f"otp_{user.email}")

    if not cached_otp:
        raise HTTPException(status_code=400, detail="OTP expired or not sent.")

    if cached_otp != user.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP.")
    user_data=collection.find_one({"email":user.email})
    if user_data["role"]=="subscriber":
        token = auth_s.dumps({"email":user.email})
        user_data["secret_key"]=token
        user_data["verified"]=True
        result = collection.update_one(
            {"email": user.email},
            {"$set": user_data}
        )
        return {"secret_key":user_data["secret_key"]}
    result = collection.update_one(
            {"email": user.email},
            {"$set": {"verified": True}}
        )
    return {"message": "OTP verified successfully!"}
