"""Specialized chat agents for different security roles."""
import logging
from typing import Dict, List, Optional, Any
from uuid import uuid4

from .context import ConversationContext
from app.models.scan import Severity

logger = logging.getLogger(__name__)


class ChatAgent:
    """Base chat agent with role-specific behavior."""
    
    def __init__(self, name: str, role_description: str, system_prompt: str):
        self.name = name
        self.role_description = role_description
        self.system_prompt = system_prompt
        self.contexts: Dict[str, ConversationContext] = {}
    
    async def handle_message(self, message: str, conversation_id: str) -> Dict[str, Any]:
        """Handle an incoming chat message."""
        context = self._get_or_create_context(conversation_id)
        context.add_message("user", message)
        
        response = await self._generate_response(message, context)
        context.add_message("assistant", response["content"])
        
        return response
    
    async def _generate_response(self, message: str, context: ConversationContext) -> Dict[str, Any]:
        """Generate a response. Override in subclasses."""
        return {
            "content": f"[{self.name}] Processing your request...",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": [],
            "metadata": {},
        }
    
    def _get_or_create_context(self, conversation_id: str) -> ConversationContext:
        if conversation_id not in self.contexts:
            self.contexts[conversation_id] = ConversationContext(conversation_id)
        return self.contexts[conversation_id]
    
    def get_context(self, conversation_id: str) -> Optional[ConversationContext]:
        return self.contexts.get(conversation_id)


class AnalystChatAgent(ChatAgent):
    """Chat agent specializing in vulnerability analysis and explanation."""
    
    def __init__(self):
        super().__init__(
            name="analyst",
            role_description="Security analyst specializing in vulnerability analysis and explanation",
            system_prompt="""You are a senior security analyst. You explain vulnerabilities clearly,
help prioritize findings, and provide remediation guidance. You understand CVSS, OWASP Top 10,
CWE, and common vulnerability patterns. You communicate technical findings in business-friendly terms.""",
        )
        self._analysis_templates = {
            "explain_finding": self._explain_finding,
            "prioritize": self._prioritize_findings,
            "remediate": self._suggest_remediation,
        }
    
    async def _generate_response(self, message: str, context: ConversationContext) -> Dict[str, Any]:
        message_lower = message.lower()
        
        # Route to specialized handlers
        for keyword, handler in self._analysis_templates.items():
            if keyword in message_lower:
                result = await handler(message, context)
                if result:
                    return result
        
        # Default: generic analysis response
        return {
            "content": f"I understand you're asking about security analysis. Let me help you understand the findings and their implications. Could you share specific findings or scan results you'd like me to analyze?",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["analyze_findings", "explain_vulnerability", "prioritize"],
            "metadata": {"confidence": 0.9},
        }
    
    async def _explain_finding(self, message: str, context: ConversationContext) -> Optional[Dict]:
        findings_ctx = context.get_findings_context()
        if not findings_ctx:
            return None
        
        return {
            "content": f"Analysis of {findings_ctx.get('total', 0)} findings shows {findings_ctx.get('critical', 0)} critical and {findings_ctx.get('high', 0)} high severity issues. The most critical finding is {findings_ctx.get('recent', [{}])[0].get('title', 'N/A')} which requires immediate attention due to its potential for remote code execution.",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["show_details", "generate_report"],
            "metadata": {"findings_analyzed": findings_ctx.get('total', 0)},
        }
    
    async def _prioritize_findings(self, message: str, context: ConversationContext) -> Optional[Dict]:
        findings_ctx = context.get_findings_context()
        if not findings_ctx:
            return None
        
        return {
            "content": f"Based on severity, CVSS scores, and exploitability, I recommend prioritizing: 1) All {findings_ctx.get('critical', 0)} critical findings (patch within 24h), 2) {findings_ctx.get('high', 0)} high severity findings (patch within 7 days). Would you like me to generate a remediation plan?",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["generate_remediation_plan", "create_tickets"],
            "metadata": {"priority_matrix": "critical > high > medium"},
        }
    
    async def _suggest_remediation(self, message: str, context: ConversationContext) -> Optional[Dict]:
        return {
            "content": "For effective remediation: 1) Apply patches for known CVEs, 2) Implement WAF rules for web vulnerabilities, 3) Review access controls, 4) Enable security monitoring. I can create a detailed remediation plan if you share the specific findings.",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["create_remediation_tickets", "schedule_rescan"],
            "metadata": {},
        }


class PentestChatAgent(ChatAgent):
    """Chat agent specializing in penetration testing guidance."""
    
    def __init__(self):
        super().__init__(
            name="pentest",
            role_description="Penetration testing specialist",
            system_prompt="""You are an expert penetration tester. You help plan and execute
security assessments, select appropriate tools, interpret results, and suggest exploitation
strategies. You're knowledgeable about Metasploit, BurpSuite, and other pentest tools.""",
        )
    
    async def _generate_response(self, message: str, context: ConversationContext) -> Dict[str, Any]:
        message_lower = message.lower()
        
        if "scan" in message_lower or "recon" in message_lower:
            return {
                "content": "Let me set up reconnaissance. I'll use BBOT for subdomain enumeration and Shodan for internet-facing asset discovery. What's your target scope?",
                "role": self.name,
                "conversation_id": context.conversation_id,
                "actions": ["run_recon", "select_tools", "start_scan"],
                "metadata": {"recommended_tools": ["bbot", "nuclei", "shodan"]},
            }
        elif "exploit" in message_lower:
            return {
                "content": "For exploitation, I recommend starting with Metasploit for known CVEs, then custom exploitation for findings without public exploits. What vulnerabilities did your scan identify?",
                "role": self.name,
                "conversation_id": context.conversation_id,
                "actions": ["launch_metasploit", "search_exploits", "generate_payload"],
                "metadata": {},
            }
        
        return {
            "content": f"I'm ready to assist with penetration testing. I can help with reconnaissance, exploitation, post-exploitation, or reporting. What phase are you in?",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["recon", "scanning", "exploitation", "reporting"],
            "metadata": {},
        }


class ComplianceChatAgent(ChatAgent):
    """Chat agent specializing in compliance and governance."""
    
    def __init__(self):
        super().__init__(
            name="compliance",
            role_description="Compliance and governance specialist",
            system_prompt="""You are a compliance specialist familiar with NIST CSF, NIST 800-53,
ISO 27001, PCI DSS, HIPAA, and SOC 2. You help map findings to compliance controls,
assess compliance posture, and generate compliance reports.""",
        )
    
    async def _generate_response(self, message: str, context: ConversationContext) -> Dict[str, Any]:
        message_lower = message.lower()
        
        frameworks = {"nist": "NIST CSF", "pci": "PCI DSS", "hipaa": "HIPAA", "iso": "ISO 27001", "soc": "SOC 2"}
        
        for keyword, framework in frameworks.items():
            if keyword in message_lower:
                return {
                    "content": f"I can assess your findings against {framework} controls. The current findings would map to several controls. Would you like me to generate a {framework} compliance report?",
                    "role": self.name,
                    "conversation_id": context.conversation_id,
                    "actions": ["generate_compliance_report", "map_findings", "gap_analysis"],
                    "metadata": {"framework": framework},
                }
        
        return {
            "content": "I can help with compliance assessments across NIST CSF, NIST 800-53, ISO 27001, PCI DSS, HIPAA, and SOC 2. Which framework are you interested in?",
            "role": self.name,
            "conversation_id": context.conversation_id,
            "actions": ["select_framework", "assess_compliance", "generate_report"],
            "metadata": {"supported_frameworks": list(frameworks.values())},
        }
