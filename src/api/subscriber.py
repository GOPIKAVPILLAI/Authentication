from src.controllers.auth import get_password_hash,create_access_token
from src.models import Subscriber,User
from src.models import fake_users_db
from fastapi import APIRouter,HTTPException
from datetime import datetime, timedelta, timezone
from src.utils import auth_s,collection
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY
from src.models import Token,UserInDB,User

router=APIRouter()
@router.post("/subscribe/", response_model=dict)
async def subscriber(user: UserInDB):
    if collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if user.role != 'subscriber':
        raise HTTPException(status_code=400, detail="Only subscriber are allowed")
  
    user_dict=user.dict()
    user_dict['password']=get_password_hash(user_dict['password'])
    token = auth_s.dumps({"email":user.email})
    user_dict["secret_key"]=token
    result = collection.insert_one(user_dict)
    new_user = collection.find_one({"_id": result.inserted_id})
    return {"secret_key":new_user["secret_key"]}
    


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