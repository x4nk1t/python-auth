from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from models import User, Token, EmailPasswordLogin
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from models import TokenData
from database import user_collection

import os
import database

SECRET_KEY = os.getenv("JWT_SECRET", "mysecretkey")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=['bcrypt'])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

async def username_exists(username: str):
    response = await database.user_collection.find_one({"username": username})
    if response is None:
        return False
    else:
        return True
    
async def email_exists(email: str):
    response = await database.user_collection.find_one({"email": email})
    if response is None:
        return False
    else:
        return True


def create_access_token(username: str, timedelta = timedelta(minutes=30)):
    expire = datetime.now(timezone.utc) + timedelta
    data = {"sub": username, "exp": expire}

    encoded_jwt = jwt.encode(data, SECRET_KEY, ALGORITHM)
    return encoded_jwt

def is_token_valid(token: str):
    return

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms={ALGORITHM})
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    
    user = await user_collection.find_one({"username": token_data.username})
    if user is None:
        raise credential_exception
    
    return user
'''
Login
'''
async def login_email_password(user: EmailPasswordLogin) -> Token:
    incorrect_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    response = await database.user_collection.find_one({"email": user.email})

    if not response:
        raise incorrect_exception
        
    if not verify_password(user.password, response["password"]):
        raise incorrect_exception
    else:
        token = create_access_token(response["username"])
        return {"access_token": token, "token_type": "bearer"}

'''
Signup
'''
async def create_user(user: User):
    user_data = user.model_dump(mode="json")
    user_data["password"] = hash_password(user.password)

    result = await database.user_collection.insert_one(user_data)

    if result:
        return {"inserted_id": str(result.inserted_id), "detail": "User created!"}
    else:
        return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)