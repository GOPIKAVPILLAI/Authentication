from pydantic import BaseModel,Field
from enum import Enum


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "role":"admin",
        "hashed_password": "$2b$12$.IcwGgKzW/rMGe7Yw8rE0uJMNsivx5yaPQx.pdAEIimCcu7Jjj1sO",
        "disabled": False,
    }
}
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
    disabled: bool=Field(default=False) 

class UserLogin(BaseModel):
    email : str
    password : str

class UserInDB(User):
    password: str

class Subscriber(UserInDB):
    secret_token : str

