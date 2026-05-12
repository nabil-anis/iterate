"""Cross-tool finding correlation and deduplication."""
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from difflib import SequenceMatcher

from app.models.finding import Finding, FindingSource
from app.models.scan import Severity, ToolType

logger = logging.getLogger(__name__)


class FindingCorrelator:
    """Correlates findings across different tools to identify duplicates and relationships."""
    
    SIMILARITY_THRESHOLD = 0.75
    
    def __init__(self):
        self._correlation_cache: Dict[str, List[str]] = defaultdict(list)
    
    async def correlate(self, findings: List[Finding]) -> List[Finding]:
        """Correlate findings across tools, merging duplicates and linking related issues."""
        if not findings:
            return []
        
        # Step 1: Group by target
        by_target = defaultdict(list)
        for f in findings:
            by_target[f.target].append(f)
        
        correlated = []
        for target, target_findings in by_target.items():
            target_correlated = await self._correlate_target(target_findings)
            correlated.extend(target_correlated)
        
        # Step 2: Cross-target correlation for related findings
        final = await self._correlate_across_targets(correlated)
        
        logger.info(f"Correlated {len(findings)} findings into {len(final)} unique findings")
        return final
    
    async def _correlate_target(self, findings: List[Finding]) -> List[Finding]:
        """Correlate findings for a single target."""
        if not findings:
            return []
        
        # Create fingerprint for each finding
        fingerprinted = []
        for f in findings:
            fp = self._fingerprint(f)
            fingerprinted.append((fp, f))
        
        # Group by exact fingerprint match
        fp_groups = defaultdict(list)
        for fp, f in fingerprinted:
            fp_groups[fp].append(f)
        
        # Merge exact matches
        merged = []
        for fp, group in fp_groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                merged.append(self._merge_findings(group, "exact_match"))
        
        # Fuzzy match remaining for cross-reference
        final = []
        used = set()
        for i, f1 in enumerate(merged):
            if i in used:
                continue
            group = [f1]
            used.add(i)
            for j, f2 in enumerate(merged):
                if j in used:
                    continue
                similarity = self._title_similarity(f1.title, f2.title)
                if similarity >= self.SIMILARITY_THRESHOLD:
                    group.append(f2)
                    used.add(j)
            
            if len(group) > 1:
                final.append(self._merge_findings(group, "similar_title"))
            else:
                final.append(f1)
        
        return final
    
    async def _correlate_across_targets(self, findings: List[Finding]) -> List[Finding]:
        """Correlate findings across different targets (e.g., same CVE on different hosts)."""
        # Group by normalized title (CVE ID, plugin name, etc.)
        cve_groups = defaultdict(list)
        for f in findings:
            # Extract CVE IDs from title/description
            cve_id = self._extract_cve(f)
            if cve_id:
                cve_groups[cve_id].append(f)
        
        # Add cross-reference metadata
        for cve_id, group in cve_groups.items():
            if len(group) > 1:
                for f in group:
                    f.metadata["related_targets"] = [g.target for g in group if g.id != f.id]
                    f.metadata["affected_count"] = len(group)
                    f.is_deduplicated = True
        
        return findings
    
    def _fingerprint(self, finding: Finding) -> str:
        """Create a deterministic fingerprint for a finding."""
        raw = ""
        for source in finding.sources:
            if isinstance(source.raw_data, dict):
                raw = source.raw_data.get("plugin_id", "") or \
                      source.raw_data.get("template_id", "") or \
                      source.raw_data.get("id", "") or ""
                if raw:
                    break
        
        fp_input = f"{finding.title}:{finding.target}:{raw}:{finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}"
        return hashlib.sha256(fp_input.encode()).hexdigest()
    
    def _title_similarity(self, a: str, b: str) -> float:
        """Compute similarity between two finding titles."""
        a_norm = self._normalize_title(a)
        b_norm = self._normalize_title(b)
        return SequenceMatcher(None, a_norm, b_norm).ratio()
    
    def _normalize_title(self, title: str) -> str:
        """Normalize title for comparison."""
        import re
        title = title.lower().strip()
        title = re.sub(r'[\(\)\[\]\{\},.:;!?]', '', title)
        title = re.sub(r'\b(cve|port|host)\b', '', title, flags=re.IGNORECASE)
        return title
    
    def _extract_cve(self, finding: Finding) -> Optional[str]:
        """Extract CVE identifier from a finding."""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # Check title
        match = re.search(cve_pattern, finding.title, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        
        # Check description
        match = re.search(cve_pattern, finding.description, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        
        # Check sources
        for source in finding.sources:
            if isinstance(source.raw_data, dict):
                for val in source.raw_data.values():
                    if isinstance(val, str):
                        match = re.search(cve_pattern, val, re.IGNORECASE)
                        if match:
                            return match.group(0).upper()
        
        return None
    
    def _merge_findings(self, findings: List[Finding], merge_reason: str) -> Finding:
        """Merge multiple findings into one consolidated finding."""
        primary = findings[0]
        
        # Collect all sources
        all_sources = []
        for f in findings:
            all_sources.extend(f.sources)
        
        # Take highest severity
        max_severity = max(
            (f.severity for f in findings),
            key=lambda s: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}.get(
                s.value if hasattr(s, 'value') else str(s), 0
            )
        )
        
        # Take best description and remediation
        best_desc = max(
            (f.description for f in findings if f.description),
            key=len,
            default=primary.description
        )
        best_remediation = max(
            (f.remediation for f in findings if f.remediation),
            key=len,
            default=primary.remediation
        )
        
        merged = Finding(
            id=primary.id,
            title=primary.title,
            description=best_desc or primary.description,
            severity=max_severity,
            cvss_score=primary.cvss_score,
            cvss_vector=primary.cvss_vector,
            target=primary.target,
            affected_endpoint=primary.affected_endpoint,
            affected_component=primary.affected_component,
            remediation=best_remediation or primary.remediation,
            references=primary.references,
            sources=all_sources,
            metadata={
                "merge_reason": merge_reason,
                "merged_count": len(findings),
                "original_ids": [f.id for f in findings],
                "merge_timestamp": __import__('datetime').datetime.utcnow().isoformat(),
            },
            is_deduplicated=len(findings) > 1,
            duplicate_count=len(findings) - 1,
        )
        
        return merged
