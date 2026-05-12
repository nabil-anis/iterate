"""Core orchestration engine that coordinates all agents."""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from uuid import uuid4
from collections import defaultdict

from app.models.agent import AgentMessage, AgentTask, AgentType, TaskStatus
from app.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from app.config import settings
from app.adapters import ToolAdapterRegistry
from .agents import BaseAgent, CoordinatorAgent
from .task_classifier import TaskClassifier
from .tool_selector import ToolSelector
from .scheduler import TaskScheduler

logger = logging.getLogger(__name__)


class OrchestrationEngine:
    """Central orchestration engine for multi-agent coordination."""
    
    def __init__(self):
        self.coordinator = CoordinatorAgent("coordinator-1")
        self.classifier = TaskClassifier()
        self.tool_selector = ToolSelector()
        self.scheduler = TaskScheduler()
        
        self._agents: Dict[AgentType, BaseAgent] = {}
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._message_bus: Dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        self._active_tasks: Dict[str, AgentTask] = {}
        self._task_results: Dict[str, Dict] = {}
        self._running = False
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the engine."""
        self._agents[agent.agent_type] = agent
        agent.engine = self
        logger.info(f"Registered agent: {agent.name} ({agent.agent_type.value})")
    
    async def start(self):
        """Start the orchestration engine."""
        self._running = True
        
        # Start agent workers
        workers = []
        for agent in self._agents.values():
            workers.append(asyncio.create_task(self._agent_worker(agent)))
        
        # Start task dispatcher
        workers.append(asyncio.create_task(self._task_dispatcher()))
        
        logger.info(f"Orchestration engine started with {len(self._agents)} agents")
        await asyncio.gather(*workers)
    
    async def stop(self):
        """Stop the orchestration engine."""
        self._running = False
        logger.info("Orchestration engine stopped")
    
    async def submit_scan(self, scan_task: ScanTask) -> str:
        """Submit a scan task for orchestration."""
        conversation_id = str(uuid4())
        
        agent_task = AgentTask(
            id=str(uuid4()),
            agent_type=AgentType.COORDINATOR,
            task_type="orchestrate_scan",
            description=f"Orchestrate scan of {scan_task.target}",
            parameters={
                "scan_task": scan_task.dict(),
                "target": scan_task.target,
                "tools": [t.value for t in scan_task.tools],
            },
            priority=scan_task.priority,
        )
        
        self._active_tasks[agent_task.id] = agent_task
        await self._task_queue.put((conversation_id, agent_task))
        
        return conversation_id
    
    async def submit_agent_task(self, task: AgentTask) -> str:
        """Submit a task for any agent."""
        conversation_id = str(uuid4())
        self._active_tasks[task.id] = task
        await self._task_queue.put((conversation_id, task))
        return conversation_id
    
    async def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        task = self._active_tasks.get(task_id)
        if task:
            return task.status
        return None
    
    async def get_task_result(self, task_id: str) -> Optional[Dict]:
        return self._task_results.get(task_id)
    
    async def send_message(self, message: AgentMessage):
        """Send a message between agents."""
        queue = self._message_bus[message.target_agent.value]
        await queue.put(message)
    
    async def _task_dispatcher(self):
        """Dispatch tasks to appropriate agents."""
        while self._running:
            try:
                conversation_id, task = await asyncio.wait_for(
                    self._task_queue.get(), timeout=1.0
                )
                
                if task.agent_type == AgentType.COORDINATOR:
                    asyncio.create_task(self._handle_coordinator_task(conversation_id, task))
                elif task.agent_type in self._agents:
                    agent = self._agents[task.agent_type]
                    asyncio.create_task(self._route_to_agent(agent, task))
                else:
                    logger.warning(f"No agent registered for {task.agent_type}")
                    task.status = TaskStatus.FAILED
                    task.error = f"No agent for {task.agent_type.value}"
            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Task dispatcher error: {e}")
    
    async def _handle_coordinator_task(self, conversation_id: str, task: AgentTask):
        """Handle coordinator-level orchestration."""
        try:
            scan_task = ScanTask(**task.parameters.get("scan_task", {}))
            logger.info(f"Coordinator orchestrating scan: {scan_task.target}")
            
            # 1. Classify the task
            classification = await self.classifier.classify(scan_task)
            logger.info(f"Task classified as: {classification}")
            
            # 2. Select optimal tools
            selected_tools = await self.tool_selector.select_tools(classification, scan_task)
            logger.info(f"Selected tools: {[t.value for t in selected_tools]}")
            
            # 3. Create subtasks for each tool
            subtask_ids = []
            for tool in selected_tools:
                subtask = AgentTask(
                    id=str(uuid4()),
                    agent_type=self._tool_to_agent_type(tool),
                    task_type="execute_tool_scan",
                    description=f"Execute {tool.value} scan on {scan_task.target}",
                    parameters={
                        "tool": tool.value,
                        "target": scan_task.target,
                        "target_type": scan_task.target_type,
                        "parent_scan_id": scan_task.id,
                    },
                    priority=task.priority,
                    dependencies=[],
                )
                self._active_tasks[subtask.id] = subtask
                await self._task_queue.put((conversation_id, subtask))
                subtask_ids.append(subtask.id)
            
            # 4. Wait for results
            results = {}
            for st_id in subtask_ids:
                result = await self._wait_for_result(st_id, timeout=3600)
                if result:
                    results[st_id] = result
            
            # 5. Synthesize final result
            final_result = {
                "target": scan_task.target,
                "classification": classification,
                "tools_used": [t.value for t in selected_tools],
                "tool_results": results,
                "total_findings": sum(
                    r.get("findings_count", 0) for r in results.values() if r
                ),
            }
            
            self._task_results[task.id] = final_result
            task.status = TaskStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Coordinator task failed: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    async def _route_to_agent(self, agent: BaseAgent, task: AgentTask):
        """Route a task to a specific agent."""
        try:
            task.status = TaskStatus.IN_PROGRESS
            task.started_at = datetime.utcnow()
            
            result = await agent.execute_task(task)
            self._task_results[task.id] = result
            
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.result = result
            
        except Exception as e:
            logger.error(f"Agent {agent.name} task failed: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    async def _agent_worker(self, agent: BaseAgent):
        """Background worker that processes messages for an agent."""
        queue = self._message_bus[agent.agent_type.value]
        while self._running:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=1.0)
                asyncio.create_task(agent.handle_message(message))
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Agent worker error for {agent.name}: {e}")
    
    async def _wait_for_result(self, task_id: str, timeout: int = 3600) -> Optional[Dict]:
        """Wait for a task to complete and return its result."""
        for _ in range(timeout):
            result = self._task_results.get(task_id)
            if result is not None:
                return result
            await asyncio.sleep(1)
        return None
    
    def _tool_to_agent_type(self, tool: ToolType) -> AgentType:
        """Map a tool type to the appropriate agent type."""
        offensive_tools = {ToolType.METASPLOIT, ToolType.BURPSUITE, ToolType.PENTESTGPT,
                          ToolType.NUCLEI, ToolType.BBOT, ToolType.SHODAN, ToolType.CENSYS}
        defensive_tools = {ToolType.NESSUS, ToolType.OPENVAS, ToolType.STACKHAWK}
        
        if tool in offensive_tools:
            return AgentType.RED_TEAM
        elif tool in defensive_tools:
            return AgentType.BLUE_TEAM
        else:
            return AgentType.PURPLE_TEAM
