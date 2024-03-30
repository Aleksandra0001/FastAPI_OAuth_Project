from fastapi import FastAPI, Depends, HTTPException, status, Security, Request
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
from source.service.google_auth import oauth
from source.service.github_auth import oauth_github
from source.routes.auth import create_access_token, create_refresh_token, get_email_form_refresh_token, \
    get_current_user, Hash
from source.database.db import User, get_db
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config

config = Config(".env")
app = FastAPI()
templates = Jinja2Templates(directory="source/templates")
hash_handler = Hash()
security = HTTPBearer()

#Секретний ключ можна згенерувати за допомогою команди:
# openssl rand -hex 32 або самостійно вказати вручну
app.add_middleware(SessionMiddleware, secret_key=config("SECRET_KEY"))


class UserModel(BaseModel):
    username: str
    password: str


@app.get("/auth", response_class=HTMLResponse)
async def home_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/auth/signup")
async def signup(body: UserModel, db: Session = Depends(get_db)):
    print('BODY:', body.dict())
    exist_user = db.query(User).filter(User.email == body.username).first()
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
    new_user = User(email=body.username, password=hash_handler.get_password_hash(body.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"new_user": new_user.email}


@app.post("/auth/login")
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not hash_handler.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    # Generate JWT
    access_token = await create_access_token(data={"sub": user.email})
    refresh_token = await create_refresh_token(data={"sub": user.email})
    user.refresh_token = refresh_token
    db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get('/auth/refresh_token')
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    email = await get_email_form_refresh_token(token)
    user = db.query(User).filter(User.email == email).first()
    if user.refresh_token != token:
        user.refresh_token = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await create_access_token(data={"sub": email})
    refresh_token = await create_refresh_token(data={"sub": email})
    user.refresh_token = refresh_token
    db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get("/auth/secret")
async def read_item(current_user: User = Depends(get_current_user)):
    return {"message": 'secret router', "owner": current_user.email}

@app.get("/auth/google")
async def auth_via_google(request: Request):
    redirect_uri = request.url_for('auth_via_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_via_google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = await oauth.google.parse_id_token(request, token)
    return {"user": user}

@app.get("/auth/github")
async def auth_via_github(request: Request):
    redirect_uri = request.url_for('auth_via_github_callback')
    return await oauth_github.github.authorize_redirect(request, redirect_uri)


@app.get("/auth/github/callback")
async def auth_via_github_callback(request: Request):
    token = await oauth_github.github.authorize_access_token(request)
    resp = await oauth_github.github.get('https://api.github.com/user', token=token)
    user = resp.json()
    # print('USER:', user)
    return {"user": user}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host='localhost', port=8000)
