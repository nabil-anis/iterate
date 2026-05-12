"""API Gateway middleware for cross-cutting concerns."""
import time
import hashlib
import json
import logging
from typing import Callable, Dict, Optional
from datetime import datetime
from uuid import uuid4

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from platform.config import settings

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting using Redis-backed sliding window."""
    
    def __init__(self, app: ASGIApp, redis_client=None):
        super().__init__(app)
        self.redis = redis_client
        self._local_counts: Dict[str
