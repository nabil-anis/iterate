"""Multi-agent communication models."""
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AgentType(str, Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    COMPLIANCE = "compliance"
    COORDINATOR = "coordinator"
    ANALYST = "analyst"


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"


class AgentMessage(BaseModel):
    """Message exchanged between agents."""
    id: str
    source_agent: AgentType
    target_agent: AgentType
    message_type: str  # task, result, query, response, consensus, alert
    content: str
    context: Optional[Dict[str, Any]] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    parent_message_id: Optional[str] = None
    conversation_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentTask(BaseModel):
    """A task assigned to an agent."""
    id: str
    agent_type: AgentType
    task_type: str  # scan, analyze, correlate, report, exploit, hunt
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)
    status: TaskStatus = TaskStatus.PENDING
    assigned_to: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
