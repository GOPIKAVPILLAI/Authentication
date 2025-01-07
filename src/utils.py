from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeSerializer
# from pymongo import MongoClient
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import certifi

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
auth_s = URLSafeSerializer("secret key", "auth")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# MONGO_URI = "mongodb+srv://test:myHdkZBc2Tri9VdF@mernapp.omrpa.mongodb.net/FastApi"
MONGO_URI = "mongodb+srv://test:myHdkZBc2Tri9VdF@mernapp.omrpa.mongodb.net/?retryWrites=true&w=majority&appName=MERNapp"

client = MongoClient(MONGO_URI, server_api=ServerApi('1'),  tlsCAFile=certifi.where())

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    db=client["test"]
    collection=db["user"]
    print(client['test'])
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
# db = client['FastApi']
# collection = db['Userdata']

