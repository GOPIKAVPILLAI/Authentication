from fastapi import FastAPI

from src.api import users,subscriber



app = FastAPI()
app.include_router(users.router)
app.include_router(subscriber.router)




