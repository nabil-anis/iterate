"""Conversation context management."""
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from uuid import uuid4

logger = logging.getLogger(__name__)


class ConversationContext:
    """Manages conversation state, history, and context for chat agents."""
    
    def __init__(self, conversation_id: str, max_history: int = 100):
        self.conversation_id = conversation_id
        self.max_history = max_history
        self.messages: List[Dict] = []
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "messages_count": 0,
            "context_window": [],
        }
        self._active_tools: Dict[str, Any] = {}
        self._findings_context: Dict[str, Any] = {}
        self._scan_context: Dict[str, Any] = {}
    
    def add_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Add a message to the conversation history."""
        msg = {
            "id": str(uuid4()),
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }
        self.messages.append(msg)
        self.metadata["messages_count"] = len(self.messages)
        self.metadata["updated_at"] = datetime.utcnow().isoformat()
        
        # Trim history
        if len(self.messages) > self.max_history:
            self.messages = self.messages[-self.max_history:]
    
    def get_history(self, recent_n: Optional[int] = None) -> List[Dict]:
        """Get conversation history, optionally limited to recent N messages."""
        if recent_n:
            return self.messages[-recent_n:]
        return self.messages
    
    def set_active_tool(self, tool_name: str, config: Dict):
        """Set an active tool context for the conversation."""
        self._active_tools[tool_name] = config
    
    def get_active_tools(self) -> Dict:
        return self._active_tools
    
    def set_findings_context(self, findings: List[Dict]):
        """Store findings context for the conversation."""
        self._findings_context = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "recent": findings[:5],
            "all_ids": [f.get("id") for f in findings],
        }
    
    def get_findings_context(self) -> Dict:
        return self._findings_context
    
    def set_scan_context(self, scan_data: Dict):
        """Store scan context."""
        self._scan_context = scan_data
    
    def get_scan_context(self) -> Dict:
        return self._scan_context
    
    def build_prompt_context(self) -> str:
        """Build a context string for LLM prompt injection."""
        parts = []
        parts.append(f"## Conversation Context (ID: {self.conversation_id})")
        
        if self._scan_context:
            parts.append(f"### Active Scan")
            parts.append(f"Target: {self._scan_context.get('target', 'N/A')}")
            parts.append(f"Status: {self._scan_context.get('status', 'N/A')}")
        
        if self._findings_context:
            parts.append(f"### Findings Context")
            fc = self._findings_context
            parts.append(f"Total: {fc.get('total', 0)} | Critical: {fc.get('critical', 0)} | High: {fc.get('high', 0)}")
        
        if self._active_tools:
            parts.append("### Active Tools")
            for tool, config in self._active_tools.items():
                parts.append(f"- {tool}: {config.get('status', 'active')}")
        
        return "\n".join(parts)
    
    def clear(self):
        """Reset the conversation context."""
        self.messages.clear()
        self._active_tools.clear()
        self._findings_context.clear()
        self._scan_context.clear()
        self.metadata["messages_count"] = 0
        self.metadata["updated_at"] = datetime.utcnow().isoformat()
