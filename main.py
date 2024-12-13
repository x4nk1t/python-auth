from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from models import Token, User, EmailPasswordLogin, ResponseUser
import auth

app = FastAPI()
templates = Jinja2Templates(directory="templates")

class EmailPasswordForm(OAuth2PasswordRequestForm):
    email: str

'''
Home Page
'''
@app.get('/')
async def home_page(request: Request):
    return templates.TemplateResponse(request, "home.html")

'''
Login Page
'''
@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")
'''
Signup Page
'''
@app.get("/signup")
async def signup_page(request: Request):
    return templates.TemplateResponse(request, "signup.html")

@app.post("/auth/validate")
async def validate():
    return auth.is_token_valid()

@app.post("/auth/signup")
async def signup(user: User):
    userExists = await auth.username_exists(user.username)
    if userExists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken!")
    return await auth.create_user(user)

@app.post("/auth/login", response_model=Token)
async def login(user: EmailPasswordLogin):
    userExists = await auth.email_exists(user.email)
    if not userExists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User doesn't exist. Signup first")
    return await auth.login_email_password(EmailPasswordLogin(email=user.email, password=user.password))

@app.get("/auth/me", response_model=ResponseUser)
async def me(current_user: User = Depends(auth.get_current_user)):
    return current_user