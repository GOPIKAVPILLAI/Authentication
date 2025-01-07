from src.controllers.auth import get_password_hash,create_access_token,authenticate_user,get_current_active_user
from src.models import fake_users_db
from fastapi import APIRouter
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from src.models import Token,UserInDB,User
from datetime import datetime, timedelta, timezone
from src.utils import ACCESS_TOKEN_EXPIRE_MINUTES,ALGORITHM,SECRET_KEY,collection,db
from icecream import ic
router=APIRouter()

@router.get("/users/")
def listed_users():
    return fake_users_db


@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()] 
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")



@router.post("/create/", response_model=UserInDB|str)
async def create_user(user_in: User,password):
    if user_in.username in fake_users_db:
        return "The given username already exist"
    hashed_password = get_password_hash(password)
    user=dict(user_in.copy())
    user["hashed_password"]=hashed_password
    fake_users_db[user_in.username]=user
    return user

@router.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


def user_helper(user) -> User:
    return User(
        username=user["username"],
        email=user["email"],
        role=user["role"],
        full_name=user.get("full_name", None),
        disabled=user["disabled"]
    )

@router.post("/signup/", response_model=User)
async def create_user(user: User):
    ic(collection)
    if collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_dict = user.dict(exclude={"password"})
    result = collection.insert_one(user_dict)
    new_user = collection.find_one({"_id": result.inserted_id})
    ic(new_user)
    return user_helper(new_user)
