"""Enterprise API integration for external systems."""
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import asyncio
from uuid import uuid4

logger = logging.getLogger(__name__)


class EnterpriseAPIIntegration:
    """Generic enterprise API integration for connecting to external platforms."""
    
    def __init__(self):
        self._integrations: Dict[str, Dict] = {}
        self._webhook_routes: Dict[str, Dict] = {}
        self._rate_limits: Dict[str, List[datetime]] = {}
        self._max_rate_limit_window = 100  # requests
        self._rate_limit_period = 60  # seconds
    
    async def register_integration(self, name: str, integration_type: str, config: Dict):
        """Register an enterprise integration."""
        self._integrations[name] = {
            "type": integration_type,  # rest, graphql, grpc, custom
            "config": config,
            "healthy": True,
            "last_used": None,
            "error_count": 0,
        }
        logger.info(f"Registered enterprise integration: {name} ({integration_type})")
    
    async def call_api(self, integration_name: str, endpoint: str, method: str = "GET",
                       data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
        """Call an external API through an integration."""
        integration = self._integrations.get(integration_name)
        if not integration:
            raise ValueError(f"Integration '{integration_name}' not found")
        
        # Check rate limit
        await self._check_rate_limit(integration_name)
        
        base_url = integration["config"].get("base_url", "").rstrip("/")
        api_key = integration["config"].get("api_key", "")
        headers = integration["config"].get("headers", {})
        
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        url = f"{base_url}/{endpoint.lstrip('/')}"
        
        import httpx
        async with httpx.AsyncClient(timeout=integration["config"].get("timeout", 30)) as client:
            response = await client.request(method, url, json=data, params=params, headers=headers)
            
            integration["last_used"] = datetime.utcnow().isoformat()
            
            if response.status_code >= 400:
                integration["error_count"] += 1
                if integration["error_count"] > 10:
                    integration["healthy"] = False
                raise Exception(f"API call failed: {response.status_code} - {response.text}")
            
            integration["error_count"] = 0
            integration["healthy"] = True
            
            return {
                "status_code": response.status_code,
                "data": response.json() if response.text else {},
                "headers": dict(response.headers),
            }
    
    async def register_webhook(self, route: str, handler_name: str, config: Dict):
        """Register a webhook handler for incoming events."""
        self._webhook_routes[route] = {
            "handler": handler_name,
            "config": config,
            "registered_at": datetime.utcnow().isoformat(),
        }
        logger.info(f"Registered webhook route: {route} -> {handler_name}")
    
    async def handle_webhook(self, route: str, payload: Dict, headers: Dict) -> Dict:
        """Handle an incoming webhook event."""
        webhook = self._webhook_routes.get(route)
        if not webhook:
            raise ValueError(f"No webhook registered for route: {route}")
        
        logger.info(f"Received webhook on route: {route}")
        
        return {
            "route": route,
            "handler": webhook["handler"],
            "received_at": datetime.utcnow().isoformat(),
            "payload_size": len(str(payload)),
            "processed": True,
        }
    
    async def _check_rate_limit(self, integration_name: str):
        """Check and enforce rate limits for an integration."""
        now = datetime.utcnow()
        
        if integration_name not in self._rate_limits:
            self._rate_limits[integration_name] = []
        
        # Clean old entries
        self._rate_limits[integration_name] = [
            t for t in self._rate_limits[integration_name]
            if (now - t).total_seconds() < self._rate_limit_period
        ]
        
        if len(self._rate_limits[integration_name]) >= self._max_rate_limit_window:
            wait_time = self._rate_limit_period - (now - self._rate_limits[integration_name][0]).total_seconds()
            if wait_time > 0:
                logger.warning(f"Rate limit hit for {integration_name}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
        
        self._rate_limits[integration_name].append(now)
    
    def get_integration_status(self, name: str) -> Optional[Dict]:
        """Get the status of an integration."""
        integration = self._integrations.get(name)
        if integration:
            return {
                "name": name,
                "type": integration["type"],
                "healthy": integration["healthy"],
                "last_used": integration["last_used"],
                "error_count": integration["error_count"],
            }
        return None
    
    def get_all_integrations(self) -> List[Dict]:
        """Get all registered integrations."""
        return [
            {
                "name": name,
                "type": integration["type"],
                "healthy": integration["healthy"],
                "last_used": integration["last_used"],
            }
            for name, integration in self._integrations.items()
        ]
