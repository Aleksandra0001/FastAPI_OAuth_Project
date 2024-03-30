from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

config = Config(".env")
oauth_github = OAuth()
oauth_github.register(
    name='github',
    client_id=config('GITHUB_CLIENT_ID'),
    client_secret=config('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},  # Пример scope, можно изменить в зависимости от необходимых данных
)
