from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI

# Load environment variables
config = Config('.env')

# Initialize FastAPI app
app = FastAPI()

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=config('SECRET_KEY'))

# OAuth2 configuration
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

oauth.register(
    name='facebook',
    client_id=config('FACEBOOK_CLIENT_ID'),
    client_secret=config('FACEBOOK_CLIENT_SECRET'),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

oauth.register(
    name='github',
    client_id=config('GITHUB_CLIENT_ID'),
    client_secret=config('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)


# Redirect to the provider's login page
@app.get('/login/{provider_name}')
async def login(request: Request, provider_name: str):
    provider = oauth.create_client(provider_name)
    redirect_uri = request.url_for('auth', provider_name=provider_name)
    return await provider.authorize_redirect(request, redirect_uri)


# Handle the callback from the provider
@app.route('/auth/{provider_name}')
async def auth(request: Request, provider_name: str):
    provider = oauth.create_client(provider_name)
    token = await provider.authorize_access_token(request)
    user_info = await provider.userinfo(token=token)
    # Here you can store the user information in the database and create a session
    return user_info


# Main page
@app.get('/')
def index():
    return {'message': 'Welcome to the OAuth2 example'}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)
