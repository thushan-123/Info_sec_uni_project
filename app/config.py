from pydantic_settings import BaseSettings
from pydantic import AnyUrl, Field

class Settings(BaseSettings):
    AUTH0_DOMAIN: str
    AUTH0_CLIENT_ID: str
    AUTH0_CLIENT_SECRET: str
    AUTH0_AUDIENCE: str | None = None
    AUTH0_CALLBACK_URL: AnyUrl

    SESSION_SECRET: str = Field(min_length=32)
    DATABASE_URL: str = "sqlite:///./app.db"
    APP_DEBUG: bool = False
    PORT: int = 8000

   
    model_config = {
        "env_file": ".env",
        "extra": "allow"  
    }


settings = Settings()
