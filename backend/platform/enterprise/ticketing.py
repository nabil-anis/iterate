"""Ticketing system integration (Jira, ServiceNow, Linear, etc.)."""
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import uuid4

from platform.models.finding import Finding

logger = logging.getLogger(__name__)


class TicketingIntegration:
    """Integration with ticketing/issue tracking systems."""
    
    def __init__(self):
        self._providers: Dict[str, Dict] = {}
        self._ticket_mappings: Dict[str, str] = {}  # finding_id -> ticket_id
    
    async def register_provider(self, name: str, provider_type: str, config: Dict):
        """Register a ticketing provider."""
        self._providers[name] = {
            "type": provider_type,  # jira, servicenow, linear, github, gitlab
            "config": config,
            "healthy": True,
        }
        logger.info(f"Registered ticketing provider: {name} ({provider_type})")
    
    async def create_ticket(self, finding: Finding, provider: str = "default",
                            project: Optional[str] = None) -> Dict:
        """Create a ticket for a finding."""
        if provider not in self._providers:
            raise ValueError(f"Provider '{provider}' not registered")
        
        prov = self._providers[provider]
        ticket_data = await self._create_in_provider(prov, finding, project)
        
        self._ticket_mappings[finding.id] = ticket_data.get("ticket_id", "")
        
        return {
            "finding_id": finding.id,
            "provider": provider,
            "ticket_id": ticket_data.get("ticket_id"),
            "ticket_url": ticket_data.get("url", ""),
            "status": ticket_data.get("status", "created"),
            "created_at": datetime.utcnow().isoformat(),
        }
    
    async def create_tickets_batch(self, findings: List[Finding], provider: str = "default",
                                   project: Optional[str] = None) -> Dict:
        """Create tickets for multiple findings."""
        results = []
        for finding in findings:
            try:
                result = await self.create_ticket(finding, provider, project)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to create ticket for finding {finding.id}: {e}")
                results.append({"finding_id": finding.id, "error": str(e)})
        
        return {
            "total": len(results),
            "created": sum(1 for r in results if "ticket_id" in r),
            "failed": sum(1 for r in results if "error" in r),
            "tickets": results,
        }
    
    async def _create_in_provider(self, provider: Dict, finding: Finding, project: Optional[str] = None) -> Dict:
        """Create a ticket in a specific provider."""
        ptype = provider["type"]
        config = provider["config"]
        
        if ptype == "jira":
            return await self._create_jira(config, finding, project)
        elif ptype == "servicenow":
            return await self._create_servicenow(config, finding)
        elif ptype == "linear":
            return await self._create_linear(config, finding, project)
        elif ptype == "github":
            return await self._create_github(config, finding)
        elif ptype == "gitlab":
            return await self._create_gitlab(config, finding)
        else:
            raise ValueError(f"Unsupported provider type: {ptype}")
    
    async def _create_jira(self, config: Dict, finding: Finding, project: Optional[str] = None) -> Dict:
        """Create a Jira issue."""
        import httpx
        
        url = config.get("url", "").rstrip("/") + "/rest/api/3/issue"
        email = config.get("email", "")
        api_token = config.get("api_token", "")
        project_key = project or config.get("project", "SEC")
        
        # Map severity to Jira priority
        priority_map = {
            "critical": "Highest", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Lowest",
        }
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        priority = priority_map.get(severity_str.lower(), "Medium")
        
        description = f"""
h2. Finding Details
* *Target:* {finding.target}
* *Severity:* {severity_str}
* *CVSS:* {finding.cvss_score or 'N/A'}
* *Type:* {finding.type}

h3. Description
{finding.description}

h3. Remediation
{finding.remediation or 'N/A'}

h3. References
{finding.sources[0].url if finding.sources else 'N/A'}
"""
        
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[SEC] {finding.title}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "labels": ["security", severity_str.lower(), finding.type.lower()] if hasattr(finding, 'type') else ["security"],
            }
        }
        
        auth = (email, api_token) if api_token else None
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload, auth=auth)
            
            if response.status_code not in (201, 200):
                raise Exception(f"Jira returned {response.status_code}: {response.text}")
            
            data = response.json()
            issue_key = data.get("key", "")
            
            return {
                "ticket_id": issue_key,
                "url": f"{config.get('url', '').rstrip('/')}/browse/{issue_key}",
                "status": "created",
            }
    
    async def _create_servicenow(self, config: Dict, finding: Finding) -> Dict:
        """Create a ServiceNow incident."""
        import httpx
        
        url = config.get("url", "").rstrip("/") + "/api/now/table/incident"
        username = config.get("username", "")
        password = config.get("password", "")
        
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        
        # Map severity to ServiceNow impact/urgency
        impact_map = {"critical": 1, "high": 2, "medium": 2, "low": 3, "info": 3}
        impact = impact_map.get(severity_str.lower(), 3)
        
        payload = {
            "short_description": f"Security Finding: {finding.title}",
            "description": f"Target: {finding.target}\n\n{finding.description}\n\nRemediation: {finding.remediation or 'N/A'}",
            "category": "Security",
            "impact": impact,
            "urgency": impact,
            "caller_id": config.get("caller", "admin"),
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload, auth=(username, password))
            
            if response.status_code not in (201, 200):
                raise Exception(f"ServiceNow returned {response.status_code}")
            
            data = response.json()
            ticket_id = data.get("result", {}).get("number", "")
            
            return {
                "ticket_id": ticket_id,
                "url": f"{config.get('url', '').rstrip('/')}/nav_to.do?uri=incident.do?sys_id={data.get('result', {}).get('sys_id', '')}",
                "status": "created",
            }
    
    async def _create_linear(self, config: Dict, finding: Finding, project: Optional[str] = None) -> Dict:
        """Create a Linear issue."""
        import httpx
        
        api_key = config.get("api_key", "")
        team_id = config.get("team_id", "")
        
        query = """
        mutation CreateIssue($teamId: String!, $title: String!, $description: String!) {
            issueCreate(input: { teamId: $teamId, title: $title, description: $description }) {
                issue { id, identifier, url }
            }
        }
        """
        
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        
        variables = {
            "teamId": team_id,
            "title": f"[SEC] {finding.title}",
            "description": f"**Target:** {finding.target}\n**Severity:** {severity_str}\n**CVSS:** {finding.cvss_score or 'N/A'}\n\n{finding.description}\n\n**Remediation:**\n{finding.remediation or 'N/A'}",
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.linear.app/graphql",
                json={"query": query, "variables": variables},
                headers={"Authorization": api_key},
            )
            
            data = response.json()
            issue = data.get("data", {}).get("issueCreate", {}).get("issue", {})
            
            return {
                "ticket_id": issue.get("identifier", ""),
                "url": issue.get("url", ""),
                "status": "created",
            }
    
    async def _create_github(self, config: Dict, finding: Finding) -> Dict:
        """Create a GitHub issue."""
        import httpx
        
        token = config.get("token", "")
        repo = config.get("repo", "")
        
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        labels = ["security", severity_str.lower()]
        if hasattr(finding, 'type'):
            labels.append(finding.type.lower())
        
        payload = {
            "title": f"[SEC] {finding.title}",
            "body": f"## Security Finding\n\n**Target:** {finding.target}\n**Severity:** {severity_str}\n**CVSS:** {finding.cvss_score or 'N/A'}\n\n### Description\n{finding.description}\n\n### Remediation\n{finding.remediation or 'N/A'}",
            "labels": labels,
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"https://api.github.com/repos/{repo}/issues"
            response = await client.post(url, json=payload, headers={"Authorization": f"token {token}"})
            
            if response.status_code not in (201, 200):
                raise Exception(f"GitHub returned {response.status_code}")
            
            data = response.json()
            return {
                "ticket_id": str(data.get("number", "")),
                "url": data.get("html_url", ""),
                "status": "created",
            }
    
    async def _create_gitlab(self, config: Dict, finding: Finding) -> Dict:
        """Create a GitLab issue."""
        import httpx
        
        token = config.get("token", "")
        project_id = config.get("project_id", "")
        
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        labels = ["security", severity_str.lower()]
        
        payload = {
            "title": f"[SEC] {finding.title}",
            "description": f"## Security Finding\n\n**Target:** {finding.target}\n**Severity:** {severity_str}\n**CVSS:** {finding.cvss_score or 'N/A'}\n\n### Description\n{finding.description}\n\n### Remediation\n{finding.remediation or 'N/A'}",
            "labels": ",".join(labels),
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"https://gitlab.com/api/v4/projects/{project_id}/issues"
            response = await client.post(url, json=payload, headers={"PRIVATE-TOKEN": token})
            
            if response.status_code not in (201, 200):
                raise Exception(f"GitLab returned {response.status_code}")
            
            data = response.json()
            return {
                "ticket_id": str(data.get("iid", "")),
                "url": data.get("web_url", ""),
                "status": "created",
            }
    
    def get_ticket_mapping(self, finding_id: str) -> Optional[str]:
        """Get the ticket ID associated with a finding."""
        return self._ticket_mappings.get(finding_id)
