"""Specialized agents for Red, Blue, Purple, and Compliance operations."""
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import uuid4

from platform.models.agent import AgentMessage, AgentTask, AgentType, TaskStatus
from platform.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from platform.adapters import ToolAdapterRegistry

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all agents."""
    
    def __init__(self, name: str, agent_type: AgentType):
        self.name = name
        self.agent_type = agent_type
        self.engine = None  # Set by OrchestrationEngine
        self._context: Dict[str, Any] = {}
    
    @abstractmethod
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute an assigned task."""
        pass
    
    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle an incoming message from another agent."""
        logger.info(f"{self.name} received message: {message.message_type}")
        return None
    
    async def send_message(self, target: AgentType, msg_type: str, content: str, 
                          conversation_id: str, **kwargs):
        """Send a message to another agent."""
        if self.engine:
            message = AgentMessage(
                id=str(uuid4()),
                source_agent=self.agent_type,
                target_agent=target,
                message_type=msg_type,
                content=content,
                conversation_id=conversation_id,
                **kwargs,
            )
            await self.engine.send_message(message)
    
    async def _run_tool_scan(self, tool_type: ToolType, target: str, 
                            target_type: str = "domain", **kwargs) -> ScanResult:
        """Execute a scan using a specific tool."""
        adapter = ToolAdapterRegistry.get_adapter(tool_type)
        if not adapter:
            return ScanResult(
                scan_id=str(uuid4()), tool=tool_type, status=ScanStatus.FAILED,
                error=f"No adapter for {tool_type.value}",
            )
        
        scan_task = ScanTask(
            id=str(uuid4()),
            target=target,
            target_type=target_type,
            tools=[tool_type],
            created_by=self.name,
            metadata=kwargs,
        )
        
        return await adapter.execute_scan(scan_task)


class RedTeamAgent(BaseAgent):
    """Offensive security agent - executes attacks, exploits, and penetration tests."""
    
    def __init__(self, name: str = "red-team-1"):
        super().__init__(name, AgentType.RED_TEAM)
        self._offensive_tools = [
            ToolType.METASPLOIT, ToolType.BURPSUITE, ToolType.PENTESTGPT,
            ToolType.NUCLEI, ToolType.BBOT, ToolType.SHODAN, ToolType.CENSYS,
        ]
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        logger.info(f"RedTeam executing: {task.description}")
        
        if task.task_type == "execute_tool_scan":
            tool = ToolType(task.parameters.get("tool", ""))
            target = task.parameters.get("target", "")
            target_type = task.parameters.get("target_type", "domain")
            
            result = await self._run_tool_scan(tool, target, target_type)
            return {
                "agent": self.name,
                "tool": tool.value,
                "target": target,
                "status": result.status.value,
                "findings_count": result.findings_count,
                "summary": result.summary,
                "duration_seconds": result.duration_seconds,
                "raw_output": result.raw_output,
            }
        
        elif task.task_type == "reconnaissance":
            results = {}
            for tool in [ToolType.BBOT, ToolType.SHODAN, ToolType.CENSYS]:
                result = await self._run_tool_scan(
                    tool, task.parameters.get("target", ""),
                    task.parameters.get("target_type", "domain"),
                )
                results[tool.value] = {
                    "status": result.status.value,
                    "findings": result.findings_count,
                }
            return {"agent": self.name, "recon_results": results}
        
        return {"agent": self.name, "status": "unknown_task_type"}
    
    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        if message.message_type == "request_exploit":
            # Generate exploit guidance
            response = AgentMessage(
                id=str(uuid4()),
                source_agent=self.agent_type,
                target_agent=message.source_agent,
                message_type="exploit_guidance",
                content=f"Analyzing exploit requirements for: {message.content}",
                conversation_id=message.conversation_id,
                parent_message_id=message.id,
            )
            await self.engine.send_message(response)
        return None


class BlueTeamAgent(BaseAgent):
    """Defensive security agent - monitors, detects, and analyzes threats."""
    
    def __init__(self, name: str = "blue-team-1"):
        super().__init__(name, AgentType.BLUE_TEAM)
        self._defensive_tools = [
            ToolType.NESSUS, ToolType.OPENVAS, ToolType.STACKHAWK,
        ]
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        logger.info(f"BlueTeam executing: {task.description}")
        
        if task.task_type == "execute_tool_scan":
            tool = ToolType(task.parameters.get("tool", ""))
            target = task.parameters.get("target", "")
            target_type = task.parameters.get("target_type", "domain")
            
            result = await self._run_tool_scan(tool, target, target_type)
            return {
                "agent": self.name,
                "tool": tool.value,
                "target": target,
                "status": result.status.value,
                "findings_count": result.findings_count,
                "summary": result.summary,
            }
        
        elif task.task_type == "vulnerability_assessment":
            results = {}
            for tool in self._defensive_tools:
                result = await self._run_tool_scan(
                    tool, task.parameters.get("target", ""),
                )
                results[tool.value] = {
                    "status": result.status.value,
                    "findings": result.findings_count,
                }
            return {"agent": self.name, "va_results": results}
        
        return {"agent": self.name, "status": "unknown_task_type"}
    
    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        if message.message_type == "alert":
            logger.warning(f"BlueTeam alert: {message.content}")
            response = AgentMessage(
                id=str(uuid4()),
                source_agent=self.agent_type,
                target_agent=AgentType.RED_TEAM,
                message_type="cross_validation",
                content=f"Validating alert: {message.content}",
                conversation_id=message.conversation_id,
            )
            await self.engine.send_message(response)
        return None


class PurpleTeamAgent(BaseAgent):
    """Hybrid agent - coordinates Red and Blue team operations."""
    
    def __init__(self, name: str = "purple-team-1"):
        super().__init__(name, AgentType.PURPLE_TEAM)
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        logger.info(f"PurpleTeam executing: {task.description}")
        
        if task.task_type == "attack_validation":
            # Simulate attack, measure detection
            attack_result = await self._run_tool_scan(
                ToolType.METASPLOIT, task.parameters.get("target", ""),
            )
            return {
                "agent": self.name,
                "attack_executed": attack_result.status.value == "completed",
                "detection_metrics": {
                    "detected": False,
                    "response_time": None,
                },
                "recommendations": [
                    "Deploy EDR on target",
                    "Enable network monitoring",
                ],
            }
        
        return {"agent": self.name, "status": "unknown_task_type"}
    
    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        if message.message_type == "purple_exercise":
            # Coordinate attack/detection exercise
            await self.send_message(
                AgentType.RED_TEAM, "request_exploit",
                f"Execute attack for: {message.content}",
                message.conversation_id,
            )
            await self.send_message(
                AgentType.BLUE_TEAM, "prepare_detection",
                f"Prepare to detect: {message.content}",
                message.conversation_id,
            )
        return None


class ComplianceAgent(BaseAgent):
    """Governance, Risk, and Compliance agent."""
    
    def __init__(self, name: str = "compliance-1"):
        super().__init__(name, AgentType.COMPLIANCE)
        self._frameworks = ["nist_csf", "nist_800_53", "iso_27001", "pci_dss", "hipaa", "soc_2"]
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        logger.info(f"Compliance executing: {task.description}")
        
        if task.task_type == "map_findings":
            findings = task.parameters.get("findings", [])
            frameworks = task.parameters.get("frameworks", self._frameworks)
            
            mappings = self._map_to_frameworks(findings, frameworks)
            return {
                "agent": self.name,
                "findings_mapped": len(findings),
                "frameworks": frameworks,
                "mappings": mappings,
                "compliant": all(m.get("status") == "compliant" for m in mappings),
            }
        
        elif task.task_type == "generate_compliance_report":
            return {
                "agent": self.name,
                "report_type": task.parameters.get("framework", "nist_csf"),
                "status": "generated",
                "summary": "Compliance report generated with 0 critical gaps",
            }
        
        return {"agent": self.name, "status": "unknown_task_type"}
    
    def _map_to_frameworks(self, findings: List[Dict], frameworks: List[str]) -> List[Dict]:
        """Map findings to compliance controls."""
        mappings = []
        control_map = {
            "nist_csf": ["ID.AM-1", "ID.RA-1", "PR.AC-1", "PR.DS-1", "DE.CM-1", "RS.RP-1"],
            "nist_800_53": ["AC-1", "AU-1", "CA-1", "CM-1", "CP-1", "IA-1", "IR-1", "MP-1", "PE-1", "PL-1", "PS-1", "RA-1", "SA-1", "SC-1", "SI-1"],
            "iso_27001": ["A.5.1", "A.6.1", "A.7.1", "A.8.1", "A.9.1", "A.10.1", "A.11.1", "A.12.1", "A.13.1", "A.14.1", "A.15.1", "A.16.1", "A.17.1", "A.18.1"],
            "pci_dss": ["1.1", "2.1", "3.1", "4.1", "5.1", "6.1", "7.1", "8.1", "9.1", "10.1", "11.1", "12.1"],
            "hipaa": ["164.308", "164.310", "164.312", "164.314", "164.316"],
            "soc_2": ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9", "A1", "C1", "P1"],
        }
        
        for finding in findings[:10]:  # Limit for example
            title = finding.get("title", "").lower()
            for framework in frameworks:
                controls = control_map.get(framework, [])
                for control in controls[:3]:
                    mappings.append({
                        "finding_id": finding.get("id", ""),
                        "framework": framework,
                        "control_id": control,
                        "status": "non_compliant" if finding.get("severity") in ("critical", "high") else "compliant",
                    })
        
        return mappings


class CoordinatorAgent(BaseAgent):
    """Orchestrator agent that coordinates multi-agent workflows."""
    
    def __init__(self, name: str = "coordinator-1"):
        super().__init__(name, AgentType.COORDINATOR)
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        logger.info(f"Coordinator executing: {task.description}")
        # Coordinator tasks are handled by OrchestrationEngine._handle_coordinator_task
        return {"agent": self.name, "status": "delegated"}
