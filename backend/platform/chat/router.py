"""AI Chat Router - processes natural language queries."""
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ChatRouter:
    """Routes and processes chat messages through the AI assistant."""
    
    def __init__(self):
        self._context: Dict = {}
        self._conversation_history: List[Dict] = []
        self._max_history = 50
    
    async def process_message(self, message: str, context: Optional[Dict] = None) -> str:
        """Process a chat message and return the AI response."""
        if context:
            self._context.update(context)
        
        self._conversation_history.append({"role": "user", "content": message})
        
        if len(self._conversation_history) > self._max_history:
            self._conversation_history = self._conversation_history[-self._max_history:]
        
        # Here the actual LLM call would happen (OpenAI, LLaMA, etc.)
        response = await self._query_llm(message)
        
        self._conversation_history.append({"role": "assistant", "content": response})
        
        return response
    
    async def generate_report(self, scan_data: Any, findings: List, format: str = "markdown") -> str:
        """Generate a natural language report from scan results."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        report = f"""# Security Assessment Report

## Executive Summary

- **Targets Analyzed:** {len(scan_data.targets) if hasattr(scan_data, 'targets') else 'N/A'}
- **Total Findings:** {len(findings)}
- **Critical:** {severity_counts['critical']}
- **High:** {severity_counts['high']}
- **Medium:** {severity_counts['medium']}
- **Low:** {severity_counts['low']}

## Key Findings

"""
        for finding in findings[:20]:
            report += f"- **{finding.get('severity', 'INFO').upper()}** | {finding.get('title', 'Untitled')} - {finding.get('target', 'Unknown')}\n"
            if finding.get('remediation'):
                report += f"  - *Remediation:* {finding.get('remediation', 'N/A')}\n"
        
        report += "\n## Recommendations\n\n"
        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            report += "1. **Immediate action required** for all Critical and High severity findings.\n"
        report += "2. Establish a remediation timeline based on severity.\n"
        report += "3. Schedule regular security assessments.\n"
        
        return report
    
    async def _query_llm(self, message: str) -> str:
        """Query the LLM (OpenAI or local model)."""
        import os
        
        api_key = os.getenv("OPENAI_API_KEY", "")
        
        if api_key:
            try:
                import openai
                client = openai.AsyncClient(api_key=api_key)
                response = await client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-4"),
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity assistant helping with security assessments, vulnerability analysis, and remediation guidance."},
                        *self._conversation_history[-10:],
                    ],
                    max_tokens=2048,
                    temperature=0.3,
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.error(f"LLM query failed: {e}")
                return f"_LLM unavailable. Analysis based on internal data._\n\nAnalyzing your request: {message}"
        
        return f"_AI analysis based on platform data._ Your query has been logged for processing."
