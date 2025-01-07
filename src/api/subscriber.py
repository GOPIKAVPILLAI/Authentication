from src.controllers.auth import get_password_hash,create_access_token
from src.models import Subscriber,User
from src.models import fake_users_db
from fastapi import APIRouter
from datetime import datetime, timedelta, timezone
from src.utils import auth_s
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY
from src.models import Token,UserInDB,User

router=APIRouter()
@router.post("/subcribe/", response_model=Subscriber| str)
async def subscriber(user_in: User,password):
    if user_in.username in fake_users_db:
        return "The given username already exist"
    if user_in.role != 'subscriber':
        return "Only subscriber are allowed"
    hashed_password = get_password_hash(password)
    user=dict(user_in.copy())
    user["hashed_password"]=hashed_password
    fake_users_db[user_in.username]=user
    token = auth_s.dumps({"username":user["username"]})
    user["secret_key"]=token
    return user["secret_key"]


@router.get("/subscriber_login/")
async def subscriber_login(token):
    data=auth_s.loads(token)
    if data["username"] in fake_users_db and fake_users_db[data["username"]]["role"]=="subscriber":
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
        data={"sub": data["username"]}, expires_delta=access_token_expires
    )
        return Token(access_token=access_token, token_type="bearer")