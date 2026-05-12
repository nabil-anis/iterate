"""SSO/OAuth integration for enterprise authentication."""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import jwt
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class SSOProvider:
    """SSO provider configuration."""
    name: str
    provider_type: str  # oauth2, oidc, saml, ldap
    client_id: str = ""
    client_secret: str = ""
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    issuer: str = ""
    scopes: List[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    redirect_uri: str = ""
    jwks_uri: str = ""
    metadata_url: str = ""


@dataclass
class SSOUser:
    """Authenticated SSO user."""
    id: str
    email: str
    name: str
    provider: str
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    access_token: str = ""
    refresh_token: str = ""
    expires_at: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)


class SSOIntegration:
    """Enterprise SSO integration."""
    
    def __init__(self):
        self._providers: Dict[str, SSOProvider] = {}
        self._sessions: Dict[str, SSOUser] = {}
        self._jwt_secret = None
    
    def set_jwt_secret(self, secret: str):
        """Set the JWT secret for token signing."""
        self._jwt_secret = secret
    
    async def register_provider(self, provider: SSOProvider):
        """Register an SSO provider."""
        self._providers[provider.name] = provider
        logger.info(f"Registered SSO provider: {provider.name} ({provider.provider_type})")
    
    async def get_authorization_url(self, provider_name: str, state: Optional[str] = None) -> Dict:
        """Get the authorization URL for an OAuth2/OIDC provider."""
        provider = self._providers.get(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")
        
        if provider.provider_type in ("oauth2", "oidc"):
            state = state or str(uuid4())
            params = {
                "response_type": "code",
                "client_id": provider.client_id,
                "redirect_uri": provider.redirect_uri,
                "scope": " ".join(provider.scopes),
                "state": state,
            }
            
            if provider.provider_type == "oidc":
                params["response_mode"] = "query"
            
            import urllib.parse
            auth_url = f"{provider.authorization_url}?{urllib.parse.urlencode(params)}"
            
            return {"authorization_url": auth_url, "state": state, "provider": provider_name}
        
        raise ValueError(f"Unsupported provider type: {provider.provider_type}")
    
    async def handle_callback(self, provider_name: str, code: str, state: str) -> SSOUser:
        """Handle OAuth2/OIDC callback and exchange code for tokens."""
        provider = self._providers.get(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")
        
        # Exchange code for tokens
        tokens = await self._exchange_code(provider, code)
        
        # Get user info
        user_info = await self._get_user_info(provider, tokens.get("access_token", ""))
        
        # Create user session
        user = SSOUser(
            id=user_info.get("sub") or user_info.get("id") or user_info.get("email", ""),
            email=user_info.get("email", ""),
            name=user_info.get("name", user_info.get("preferred_username", "")),
            provider=provider_name,
            access_token=tokens.get("access_token", ""),
            refresh_token=tokens.get("refresh_token", ""),
            expires_at=datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600)),
            roles=user_info.get("roles", user_info.get("groups", [])),
            metadata=user_info,
        )
        
        # Store session
        session_id = str(uuid4())
        self._sessions[session_id] = user
        
        # Generate JWT for platform
        jwt_token = self._generate_jwt(user)
        
        user.metadata["session_id"] = session_id
        user.metadata["jwt_token"] = jwt_token
        
        return user
    
    async def validate_session(self, session_id: str) -> Optional[SSOUser]:
        """Validate a session and return user info."""
        user = self._sessions.get(session_id)
        if not user:
            return None
        
        # Check expiration
        if user.expires_at and user.expires_at < datetime.utcnow():
            # Try to refresh token
            if user.refresh_token:
                user = await self._refresh_session(session_id)
            else:
                del self._sessions[session_id]
                return None
        
        return user
    
    async def _refresh_session(self, session_id: str) -> Optional[SSOUser]:
        """Refresh an expired session."""
        user = self._sessions.get(session_id)
        if not user or not user.refresh_token:
            return None
        
        provider = self._providers.get(user.provider)
        if not provider:
            return None
        
        try:
            tokens = await self._refresh_tokens(provider, user.refresh_token)
            user.access_token = tokens.get("access_token", "")
            user.refresh_token = tokens.get("refresh_token", user.refresh_token)
            user.expires_at = datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))
            return user
        except Exception as e:
            logger.error(f"Failed to refresh session {session_id}: {e}")
            del self._sessions[session_id]
            return None
    
    async def _exchange_code(self, provider: SSOProvider, code: str) -> Dict:
        """Exchange authorization code for tokens."""
        import httpx
        
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": provider.redirect_uri,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(provider.token_url, data=payload)
            if response.status_code != 200:
                raise Exception(f"Token exchange failed: {response.text}")
            return response.json()
    
    async def _refresh_tokens(self, provider: SSOProvider, refresh_token: str) -> Dict:
        """Refresh access tokens."""
        import httpx
        
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(provider.token_url, data=payload)
            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.text}")
            return response.json()
    
    async def _get_user_info(self, provider: SSOProvider, access_token: str) -> Dict:
        """Get user info from provider."""
        import httpx
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                provider.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code != 200:
                raise Exception(f"Userinfo request failed: {response.text}")
            return response.json()
    
    def _generate_jwt(self, user: SSOUser) -> str:
        """Generate a platform JWT for the user."""
        if not self._jwt_secret:
            return ""
        
        payload = {
            "sub": user.id,
            "email": user.email,
            "name": user.name,
            "provider": user.provider,
            "roles": user.roles,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=24),
        }
        
        return jwt.encode(payload, self._jwt_secret, algorithm="HS256")
