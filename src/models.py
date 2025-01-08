from pydantic import BaseModel,Field
from enum import Enum
from datetime import datetime


class Role(str, Enum):
    business = "business"
    subscriber = "subscriber"
    admin = "admin"

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


class User(BaseModel):
    username: str | None = None
    email: str
    full_name: str | None = None
    role : Role
    verified:bool=Field(default=False) 
    disabled: bool=Field(default=False) 

class UserLogin(BaseModel):
    email : str
    password : str

class UserInDB(User):
    password: str

class Subscriber(UserInDB):
    secret_token : str

class UserRegistration(BaseModel):
    email:str
    otp:str