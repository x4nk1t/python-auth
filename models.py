from pydantic import BaseModel

class User(BaseModel):
    email: str
    password: str
    username: str

class EmailPasswordLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

class ResponseUser(BaseModel):
    username: str
    email: str