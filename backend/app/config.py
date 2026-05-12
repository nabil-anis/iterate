"""Global configuration with environment variable support."""
from pydantic_settings import BaseSettings
from typing import List, Optional, Dict, Any
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # App
    APP_NAME: str = "Unified Cybersecurity Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    
    # API Gateway
    API_V1_PREFIX: str = "/api/v1"
    API_KEY_HEADER: str = "X-API-Key"
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    
    # Database (SQLite)
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/maester.db"
    
    # LLM
    LLM_PROVIDER: str = "openai"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4"
    LLM_SELF_HOSTED_URL: Optional[str] = None
    
    # Tool API Keys
    PENTESTGPT_API_KEY: Optional[str] = None
    PENTESTGPT_API_URL: str = "http://localhost:9090"
    
    BURP_API_KEY: Optional[str] = None
    BURP_API_URL: str = "http://localhost:1337"
    
    METASPLOIT_HOST: str = "localhost"
    METASPLOIT_PORT: int = 55552
    METASPLOIT_PASS: Optional[str] = None
    
    NESSUS_API_KEY: Optional[str] = None
    NESSUS_SECRET_KEY: Optional[str] = None
    NESSUS_URL: str = "https://localhost:8834"
    
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    
    STACKHAWK_API_KEY: Optional[str] = None
    
    # Observability
    PROMETHEUS_ENABLED: bool = True
    SENTRY_DSN: Optional[str] = None
    LOG_LEVEL: str = "INFO"
    
    # Kubernetes
    K8S_NAMESPACE: str = "cybersec-platform"
    POD_NAME: str = os.environ.get("HOSTNAME", "local")
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
