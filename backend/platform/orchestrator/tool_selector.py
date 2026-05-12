"""Intelligent tool selection based on task classification."""
import logging
from typing import Dict, List, Set, Optional
from platform.models.scan import ScanTask, ToolType
from .task_classifier import TaskCategory

logger = logging.getLogger(__name__)


class ToolSelector:
    """Selects optimal tools for a given task classification."""
    
    # Mapping of task categories to recommended tool stacks
    CATEGORY_TOOLS: Dict[TaskCategory, List[ToolType]] = {
        TaskCategory.RECONNAISSANCE: [
            ToolType.BBOT, ToolType.SHODAN, ToolType.CENSYS,
        ],
        TaskCategory.VULNERABILITY_SCAN: [
            ToolType.NESSUS, ToolType.OPENVAS, ToolType.NUCLEI,
        ],
        TaskCategory.WEB_APPLICATION: [
            ToolType.BURPSUITE, ToolType.NUCLEI, ToolType.BBOT,
        ],
        TaskCategory.API_SECURITY: [
            ToolType.STACKHAWK, ToolType.BURPSUITE, ToolType.NUCLEI,
        ],
        TaskCategory.NETWORK: [
            ToolType.NESSUS, ToolType.OPENVAS, ToolType.METASPLOIT,
        ],
        TaskCategory.EXPLOITATION: [
            ToolType.METASPLOIT, ToolType.PENTESTGPT, ToolType.NUCLEI,
        ],
        TaskCategory.CLOUD: [
            ToolType.SHODAN, ToolType.CENSYS, ToolType.NUCLEI,
        ],
        TaskCategory.COMPLIANCE: [
            ToolType.NESSUS, ToolType.OPENVAS,
        ],
        TaskCategory.THREAT_HUNTING: [
            ToolType.SHODAN, ToolType.CENSYS, ToolType.NESSUS,
        ],
        TaskCategory.INCIDENT_RESPONSE: [
            ToolType.NESSUS, ToolType.METASPLOIT,
        ],
        TaskCategory.UNKNOWN: [
            ToolType.BBOT, ToolType.NUCLEI, ToolType.SHODAN,
        ],
    }
    
    # Tool capabilities matrix for finer-grained selection
    TOOL_CAPABILITIES: Dict[str, Set[str]] = {
        "shodan": {"recon", "osint", "internet_scanning", "iot", "cloud"},
        "censys": {"recon", "osint", "internet_scanning", "certificate", "cloud"},
        "bbot": {"recon", "subdomain", "dns", "web", "network"},
        "nuclei": {"web", "network", "cloud", "template_based", "cve", "api"},
        "nessus": {"vulnerability_scan", "compliance", "network", "config_audit"},
        "openvas": {"vulnerability_scan", "network", "compliance"},
        "burpsuite": {"web", "api", "intercepting_proxy", "active_scan", "fuzzing"},
        "metasploit": {"exploitation", "payload_delivery", "post_exploit", "network"},
        "pentestgpt": {"llm", "exploit_generation", "analysis", "reporting"},
        "stackhawk": {"api", "web", "automated_scanning", "ci_integration"},
    }
    
    def __init__(self):
        self._tool_health: Dict[str, bool] = {}
    
    async def select_tools(self, category: TaskCategory, task: ScanTask) -> List[ToolType]:
        """Select the optimal set of tools for a task."""
        
        # Start with the default tool stack for this category
        recommended = list(self.CATEGORY_TOOLS.get(category, self.CATEGORY_TOOLS[TaskCategory.UNKNOWN]))
        
        # If specific tools were requested, use those (with fallback)
        if task.tools:
            requested = [t for t in task.tools if t in recommended] or task.tools
            return list(dict.fromkeys(requested))  # Deduplicate while preserving order
        
        # Apply context-based optimizations
        optimized = await self._apply_context_filters(recommended, task)
        
        # Ensure tool diversity
        optimized = self._ensure_diversity(optimized, category)
        
        logger.info(f"Selected tools for {category.value}: {[t.value for t in optimized]}")
        return optimized
    
    async def _apply_context_filters(self, tools: List[ToolType], task: ScanTask) -> List[ToolType]:
        """Apply contextual filters based on target metadata."""
        filtered = list(tools)
        target_lower = task.target.lower()
        
        # If it's an API target, keep API-capable tools
        if "api" in target_lower or task.target_type == "api":
            api_tools = {ToolType.BURPSUITE, ToolType.STACKHAWK, ToolType.NUCLEI}
            filtered = [t for t in filtered if t in api_tools] or filtered[:2]
        
        # If cloud domain, prefer cloud-capable tools
        cloud_domains = {"aws", "amazonaws", "azure", "windows.net", "gcp", "googleapis", "cloud"}
        if any(d in target_lower for d in cloud_domains):
            cloud_tools = {ToolType.SHODAN, ToolType.CENSYS, ToolType.NUCLEI}
            filtered = [t for t in filtered if t in cloud_tools] or filtered
        
        # Remove unavailable tools
        filtered = [t for t in filtered if self._tool_health.get(t.value, True)]
        
        return filtered[:5]  # Max 5 tools per task
    
    def _ensure_diversity(self, tools: List[ToolType], category: TaskCategory) -> List[ToolType]:
        """Ensure tool diversity - complementary rather than overlapping tools."""
        if not tools:
            return tools
        
        selected_types = set()
        diverse = []
        
        for tool in tools:
            t_name = tool.value.lower()
            capabilities = self.TOOL_CAPABILITIES.get(t_name, set())
            
            # Check overlap with already selected
            overlap = False
            for existing in selected_types:
                existing_caps = self.TOOL_CAPABILITIES.get(existing, set())
                if capabilities and existing_caps:
                    if len(capabilities & existing_caps) / max(len(capabilities | existing_caps), 1) > 0.7:
                        overlap = True
                        break
            
            if not overlap:
                diverse.append(tool)
                selected_types.add(t_name)
        
        return diverse or [tools[0]]
    
    async def check_tool_health(self, tool: ToolType) -> bool:
        """Check if a tool adapter is healthy and available."""
        from platform.adapters import ToolAdapterRegistry
        adapter = ToolAdapterRegistry.get_adapter(tool)
        if not adapter:
            self._tool_health[tool.value] = False
            return False
        try:
            healthy = await adapter.health_check()
            self._tool_health[tool.value] = healthy
            return healthy
        except Exception:
            self._tool_health[tool.value] = False
            return False
