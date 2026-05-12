"""Layer 3: Multi-Agent Orchestration Engine."""
from .engine import OrchestrationEngine
from .agents import BaseAgent, RedTeamAgent, BlueTeamAgent, PurpleTeamAgent, ComplianceAgent, CoordinatorAgent
from .task_classifier import TaskClassifier
from .tool_selector import ToolSelector
from .scheduler import TaskScheduler

__all__ = [
    "OrchestrationEngine", "BaseAgent", "RedTeamAgent", "BlueTeamAgent",
    "PurpleTeamAgent", "ComplianceAgent", "CoordinatorAgent",
    "TaskClassifier", "ToolSelector", "TaskScheduler",
]
