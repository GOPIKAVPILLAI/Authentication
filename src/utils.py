from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeSerializer
# from pymongo import MongoClient
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import certifi
from aiocache import Cache
from aiocache.serializers import JsonSerializer
import random


cache = Cache.from_url("redis://localhost")

# Cache configuration
OTP_EXPIRY = 300  # OTP validity in seconds (5 minutes)

# Email configuration (Gmail SMTP example)
SENDER_EMAIL = "gopika.v.pillai3@gmail.com"  # Your Gmail address
SENDER_PASSWORD = "kylq tbtt swrp rrdl"  # Your Gmail password or App password
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
auth_s = URLSafeSerializer("secret key", "auth")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# MONGO_URI = "mongodb+srv://test:myHdkZBc2Tri9VdF@mernapp.omrpa.mongodb.net/FastApi"
MONGO_URI = "mongodb+srv://test:myHdkZBc2Tri9VdF@mernapp.omrpa.mongodb.net/?retryWrites=true&w=majority&appName=MERNapp"

client = MongoClient(MONGO_URI, server_api=ServerApi('1'),  tlsCAFile=certifi.where())


def generate_otp() -> str:
    otp = random.randint(100000, 999999) 
    return str(otp) 


# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    db=client["test"]
    collection=db["user"]
    subcriber_collection=db["subscriber"]
except Exception as e:
    print(e)
# db = client['FastApi']
# collection = db['Userdata']

