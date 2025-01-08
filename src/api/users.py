from src.controllers.auth import get_password_hash,create_access_token,authenticate_user,get_current_active_user
from fastapi import APIRouter
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from src.models import Token,UserInDB,User,UserLogin
from datetime import datetime, timedelta, timezone
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY,collection,db,generate_otp,cache,OTP_EXPIRY
from icecream import ic
from src.controllers.verification import send_otp_to_user
router=APIRouter()

@router.get("/users/")
def listed_users()->list:
    payload=[]
    data=list(collection.find())
    for item in data:
        res=item.copy()
        del res["_id"]
        payload.append(res)
    return payload


@router.post("/token/",response_model=dict)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends(UserLogin)] 
) :
    user = authenticate_user(collection, form_data.email, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    load={"access_token":access_token,"token_type":"bearer"}
    return load
   


@router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user




@router.post("/signup/", response_model=dict)
async def create_user(user: UserInDB):
    if collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    otp = generate_otp()

    await cache.set(f"otp_{user.email}", otp, ttl=OTP_EXPIRY)

    send_otp_to_user(user.email, otp)
    user_dict=user.dict()
    user_dict['password']=get_password_hash(user_dict['password'])
    result = collection.insert_one(user_dict)
    new_user = collection.find_one({"_id": result.inserted_id})
    return {"message": "OTP sent to your email,please verify!"}
