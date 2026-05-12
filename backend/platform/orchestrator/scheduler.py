"""Task scheduler for prioritization, concurrency, and orchestration."""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Priority(int, Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ScheduledTask:
    """A task scheduled for execution."""
    id: str
    priority: Priority
    target: str
    task_type: str
    payload: Dict[str, Any]
    scheduled_at: Optional[datetime] = None
    max_retries: int = 3
    retry_count: int = 0
    dependencies: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


class TaskScheduler:
    """Manages task prioritization, scheduling, and concurrent execution."""
    
    def __init__(self, max_concurrent: int = 10):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._scheduled: Dict[str, ScheduledTask] = {}
        self._running: Dict[str, ScheduledTask] = {}
        self._completed: Dict[str, ScheduledTask] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._active_count = 0
    
    async def schedule(self, task: ScheduledTask) -> str:
        """Schedule a task for execution."""
        priority_key = (task.priority.value, task.created_at.timestamp())
        await self._queue.put((priority_key, task.id))
        self._scheduled[task.id] = task
        logger.info(
            f"Scheduled task {task.id} ({task.task_type}) "
            f"with priority {task.priority.name} on {task.target}"
        )
        return task.id
    
    async def schedule_batch(self, tasks: List[ScheduledTask]) -> List[str]:
        """Schedule multiple tasks at once."""
        ids = []
        for task in tasks:
            tid = await self.schedule(task)
            ids.append(tid)
        return ids
    
    async def next_task(self) -> Optional[ScheduledTask]:
        """Get the next highest-priority task from the queue."""
        try:
            _, task_id = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            task = self._scheduled.pop(task_id, None)
            if task:
                # Check dependencies
                if task.dependencies:
                    missing = [d for d in task.dependencies if d not in self._completed]
                    if missing:
                        logger.warning(f"Task {task_id} has unmet dependencies: {missing}")
                        # Re-queue after dependencies
                        for dep_id in missing:
                            dep_task = self._completed.get(dep_id) or self._scheduled.get(dep_id)
                            if not dep_task:
                                task.dependencies = [d for d in task.dependencies if d != dep_id]
                        if task.dependencies:
                            await self.schedule(task)
                            return None
                
                self._running[task_id] = task
                self._active_count += 1
                return task
        except asyncio.TimeoutError:
            return None
        return None
    
    async def complete_task(self, task_id: str, result: Any = None):
        """Mark a task as completed."""
        task = self._running.pop(task_id, None)
        if task:
            task.payload["result"] = result
            task.payload["completed_at"] = datetime.utcnow().isoformat()
            self._completed[task_id] = task
            self._active_count -= 1
            logger.info(f"Task {task_id} completed")
    
    async def fail_task(self, task_id: str, error: str):
        """Handle task failure with retry logic."""
        task = self._running.pop(task_id, None)
        if task:
            self._active_count -= 1
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                logger.info(f"Retrying task {task_id} (attempt {task.retry_count}/{task.max_retries})")
                await self.schedule(task)
            else:
                task.payload["error"] = error
                task.payload["failed_at"] = datetime.utcnow().isoformat()
                self._completed[task_id] = task
                logger.error(f"Task {task_id} failed after {task.max_retries} retries: {error}")
    
    def get_status(self, task_id: str) -> str:
        """Get the status of a task."""
        if task_id in self._scheduled:
            return "scheduled"
        elif task_id in self._running:
            return "running"
        elif task_id in self._completed:
            if "error" in self._completed[task_id].payload:
                return "failed"
            return "completed"
        return "unknown"
    
    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()
    
    @property
    def active_count(self) -> int:
        return self._active_count
    
    @property
    def completed_count(self) -> int:
        return len(self._completed)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        return {
            "queue_depth": self.queue_depth,
            "active_count": self.active_count,
            "completed_count": self.completed_count,
            "max_concurrent": self._max_concurrent,
            "scheduled_keys": list(self._scheduled.keys()),
            "running_keys": list(self._running.keys()),
        }
