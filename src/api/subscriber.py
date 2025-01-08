from src.controllers.auth import get_password_hash,create_access_token
from src.models import Subscriber,User
from fastapi import APIRouter,HTTPException
from datetime import datetime, timedelta, timezone
from src.utils import auth_s,collection
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY
from src.models import Token,UserInDB,User
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY,collection,db,generate_otp,cache,OTP_EXPIRY
from icecream import ic
from src.controllers.verification import send_otp_to_user

router=APIRouter()

@router.post("/subscribe/", response_model=dict)
async def subscriber(user: UserInDB):
    if collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if user.role != 'subscriber':
        raise HTTPException(status_code=400, detail="Only subscriber are allowed")
    otp = generate_otp()
    await cache.set(f"otp_{user.email}", otp, ttl=OTP_EXPIRY)
    send_otp_to_user(user.email, otp)
    user_dict=user.dict()
    user_dict['password']=get_password_hash(user_dict['password'])
    result = collection.insert_one(user_dict)
    new_user = collection.find_one({"_id": result.inserted_id})
    return {"message": "OTP sent to your email,please verify!"}


@router.get("/subscriber_login/")
async def subscriber_login(token):
    data=auth_s.loads(token)
    user=collection.find_one({"email": data["email"]})
    if user and user["role"]=="subscriber":
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
        data={"sub": data["email"]}, expires_delta=access_token_expires
    )
        return Token(access_token=access_token, token_type="bearer")